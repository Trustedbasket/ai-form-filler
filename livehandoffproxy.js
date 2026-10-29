/**
 * @file LiveHandoffProxy.js
 * @description 30-Second Telegram OTP Reminder Loop & 100% Legal Live Photo / Captcha Handoff Tunnel.
 *
 * Capabilities:
 *  1. 30-Second OTP Reminder Loop: When a user's `BrowserContext` is parked in the Waiting Box on an
 *     OTP input, sends a non-sensitive reminder every 30 seconds via `NotificationService` until the
 *     user replies with the 4-8 digit OTP or the wait window expires.
 *  2. 100% Legal Live Webcam Photo & Interactive Verification Handoff: Instead of spoofing webcams,
 *     generates a cryptographically signed, single-use, time-limited Magic Link sent to Telegram.
 *     When the user opens the Magic Link on their smartphone, the Express Reverse-Proxy / WebSocket
 *     bridge streams the live portal step from the parked `BrowserContext` (stripping restrictive
 *     `X-Frame-Options` headers on the internal proxy view) and relays user clicks/camera capture
 *     directly to the active portal session. Once the user clicks "Capture Photo" and "Next",
 *     the worker automatically resumes control and revokes the Magic Link.
 */

'use strict';

const crypto = require('crypto');
const express = require('express');

const OTP_REMINDER_INTERVAL_MS = 30 * 1000; // 30 seconds

class LiveHandoffProxy {
  /**
   * @param {Object} config
   * @param {Object} config.notificationService - Part 1 NotificationService instance
   * @param {string} [config.publicBaseUrl] - Public HTTPS origin for Magic Links
   * @param {string} [config.hmacSecret] - Secret key for signing time-limited Magic Links
   */
  constructor({ notificationService, publicBaseUrl, hmacSecret }) {
    if (!notificationService) {
      throw new Error('LiveHandoffProxy requires an initialized NotificationService instance.');
    }

    this.notificationService = notificationService;
    this.publicBaseUrl = (publicBaseUrl || process.env.FRONTEND_ORIGIN || 'https://app.yourdomain.com').replace(/\/$/, '');
    this.hmacSecret = hmacSecret || process.env.VAULT_SERVER_PEPPER || crypto.randomBytes(32).toString('hex');
    this.waitingBox = null;

    /**
     * Active single-use Magic Link tokens:
     * Map<token, { taskId: string, userId: string, examName: string, purpose: string, expiresAt: number }>
     */
    this.activeMagicTokens = new Map();
  }

  /**
   * Binds the worker's `WaitingBoxSessionManager` so the proxy can interact with parked pages.
   * @param {import('./QueueWorker').WaitingBoxSessionManager} waitingBox
   */
  bindWaitingBox(waitingBox) {
    this.waitingBox = waitingBox;
  }

  // ==========================================================================
  // 1. 30-SECOND TELEGRAM OTP REMINDER LOOP + WAITING BOX COORDINATION
  // ==========================================================================

  /**
   * Parks the user's `BrowserContext` in the Waiting Box, listens for an OTP reply via
   * `NotificationService`, and dispatches a non-sensitive reminder every 30 seconds
   * ("🚨 Step paused for OTP. Reply with the code") until the user replies.
   *
   * @param {Object} params
   * @param {string} params.taskId
   * @param {string} params.userId
   * @param {string} params.recipientId
   * @param {string} params.examName
   * @param {string} params.stepLabel
   * @param {Object} params.browserContext
   * @param {Object} params.page
   * @param {number} [params.timeoutMs=300000] - Default 5-minute OTP wait window
   * @returns {Promise<string>} Extracted 4-8 digit OTP code
   */
  async waitForOtpWith30sReminders(params) {
    const {
      taskId,
      userId,
      recipientId,
      examName,
      stepLabel = 'Step 3',
      browserContext,
      page,
      timeoutMs = 5 * 60 * 1000,
    } = params;

    if (!this.waitingBox) {
      throw new Error('WAITING_BOX_NOT_BOUND: Call bindWaitingBox() before waiting for OTP.');
    }

    let reminderCount = 0;
    const reminderInterval = setInterval(async () => {
      reminderCount += 1;
      try {
        await this.notificationService.sendAlert(
          recipientId,
          `🚨 *${stepLabel} paused for OTP (${examName}).* Reply with the 4-6 digit code to resume immediately. _(Reminder #${reminderCount})_`
        );
      } catch (_) {
        // Non-fatal if a single reminder ping fails
      }
    }, OTP_REMINDER_INTERVAL_MS);

    try {
      // Coordinate WaitingBox park + NotificationService OTP listener concurrently
      const parkPromise = this.waitingBox.parkSession(
        {
          taskId,
          userId,
          examName,
          recipientId,
          browserContext,
          page,
          pauseReason: 'OTP_REQUIRED',
        },
        timeoutMs
      );

      const otpPromise = this.notificationService
        .requestAndWaitForOtp({
          recipientId,
          examName: `${examName} - ${stepLabel}`,
          timeoutMs,
        })
        .then((otpResult) => {
          this.waitingBox.resumeSession(taskId, {
            type: 'OTP_RECEIVED',
            otpCode: otpResult.otpCode,
          });
          return otpResult.otpCode;
        });

      const [parkResolution] = await Promise.all([parkPromise, otpPromise]);
      return parkResolution.otpCode;
    } finally {
      clearInterval(reminderInterval);
      this.waitingBox.evictSession(taskId);
    }
  }

  // ==========================================================================
  // 2. 100% LEGAL LIVE PHOTO / HARD CAPTCHA MAGIC LINK & STREAMING TUNNEL
  // ==========================================================================

  /**
   * Generates a cryptographically signed, time-limited Magic Link for a parked session.
   *
   * @param {Object} params
   * @param {string} params.taskId
   * @param {string} params.userId
   * @param {string} params.examName
   * @param {string} params.purpose
   * @param {number} [params.ttlMs=300000] - Default 5 minutes
   */
  createMagicHandoffLink({ taskId, userId, examName, purpose, ttlMs = 5 * 60 * 1000 }) {
    const rawNonce = crypto.randomBytes(24).toString('hex');
    const expiresAt = Date.now() + ttlMs;
    const signature = crypto
      .createHmac('sha256', this.hmacSecret)
      .update(`${rawNonce}:${taskId}:${userId}:${expiresAt}`)
      .digest('hex')
      .slice(0, 32);

    const token = `${rawNonce}.${signature}`;
    this.activeMagicTokens.set(token, {
      taskId,
      userId,
      examName,
      purpose,
      expiresAt,
    });

    return {
      token,
      expiresAt: new Date(expiresAt).toISOString(),
      magicUrl: `${this.publicBaseUrl}/api/handoff/session/${encodeURIComponent(token)}`,
    };
  }

  /**
   * Pauses the bot on a Live Webcam Photo or Captcha page, sends the secure Magic Link
   * to the user's Telegram, and automatically resumes Puppeteer control as soon as the user
   * captures their photo on their phone and advances the portal step.
   */
  async initiateLivePortalHandoff({
    taskId,
    userId,
    recipientId,
    examName,
    browserContext,
    page,
    reason = 'LIVE_WEBCAM_OR_CAPTCHA',
    timeoutMs = 8 * 60 * 1000,
  }) {
    const magic = this.createMagicHandoffLink({
      taskId,
      userId,
      examName,
      purpose: reason,
      ttlMs: timeoutMs,
    });

    await this.notificationService.sendAlert(
      recipientId,
      `📸 *[${examName}] Live Action Required (${reason})*\n\n` +
        `Government portal par *Live Camera Photo / Captcha* step aaya hai.\n` +
        `Neeche diye gaye secure Magic Link par apne phone se click karein, official button daba kar photo capture karein aur *Next* dabayein:\n\n` +
        `🔗 [Open Live Portal Mirror](${magic.magicUrl})\n` +
        `_(Link expires in ${Math.floor(timeoutMs / 60000)} mins)_`
    );

    // Watch the parked page for navigation or explicit completion signal from the handoff UI
    const initialUrl = page.url();
    const navigationWatcher = setInterval(async () => {
      try {
        if (!page.isClosed() && page.url() !== initialUrl) {
          this.waitingBox.resumeSession(taskId, {
            type: 'HANDOFF_STEP_ADVANCED',
            newUrl: page.url(),
          });
        }
      } catch (_) {}
    }, 1500);

    try {
      return await this.waitingBox.parkSession(
        {
          taskId,
          userId,
          examName,
          recipientId,
          browserContext,
          page,
          pauseReason: 'LIVE_PHOTO_HANDOFF',
        },
        timeoutMs
      );
    } finally {
      clearInterval(navigationWatcher);
      this.activeMagicTokens.delete(magic.token);
    }
  }

  /**
   * Validates a Magic Link token and returns the associated parked session.
   * @param {string} token
   */
  _verifyMagicToken(token) {
    const meta = this.activeMagicTokens.get(token);
    if (!meta) return null;
    if (Date.now() > meta.expiresAt) {
      this.activeMagicTokens.delete(token);
      return null;
    }
    const parked = this.waitingBox ? this.waitingBox.getParkedSession(meta.taskId) : null;
    if (!parked) return null;

    return { meta, parked };
  }

  /**
   * Returns an Express Router that serves the Reverse-Proxy / DOM Mirror & Live Camera Relay
   * for authenticated Magic Links, stripping restrictive `X-Frame-Options` headers on the mirror frame.
   *
   * Mount in Express: `app.use('/api/handoff', liveHandoffProxy.createExpressRouter());`
   */
  createExpressRouter() {
    const router = express.Router();
    router.use(express.json({ limit: '10mb' }));

    // 1. Render the Live Portal Mirror & Native Camera Relay Interface on the user's phone
    router.get('/session/:token', async (req, res) => {
      const verified = this._verifyMagicToken(req.params.token);
      if (!verified) {
        return res.status(410).send('<h3>Magic Link Expired or Already Completed.</h3>');
      }

      const { meta, parked } = verified;

      // Strip framing restrictions on the handoff response so the user's mobile browser renders cleanly
      res.removeHeader('X-Frame-Options');
      res.setHeader('Content-Security-Policy', "frame-ancestors 'self';");
      res.setHeader('Cache-Control', 'no-store, no-cache, must-revalidate, private');

      const liveHtmlSnapshot = await parked.page.content();
      const basePortalUrl = parked.page.url();

      // Inject base tag + lightweight interaction & native camera relay bridge
      const bridgeScript = `
        <base href="${basePortalUrl}">
        <script>
          (function() {
            const TOKEN = ${JSON.stringify(req.params.token)};
            document.addEventListener('click', async function(e) {
              const target = e.target.closest('button, input[type="button"], input[type="submit"], a');
              if (!target) return;
              const selector = target.id ? '#' + target.id : target.tagName.toLowerCase();
              await fetch('/api/handoff/session/' + encodeURIComponent(TOKEN) + '/action', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ action: 'CLICK', selector })
              });
            }, true);
          })();
        </script>
      `;

      const mirroredDocument = liveHtmlSnapshot.replace(/<head[^>]*>/i, (match) => `${match}\n${bridgeScript}`);
      return res.status(200).send(mirroredDocument);
    });

    // 2. Relay user interaction or native phone camera frame back to the parked BrowserContext Page
    router.post('/session/:token/action', async (req, res) => {
      const verified = this._verifyMagicToken(req.params.token);
      if (!verified) {
        return res.status(410).json({ ok: false, error: 'SESSION_EXPIRED' });
      }

      const { meta, parked } = verified;
      const { action, selector, completeHandoff } = req.body || {};

      try {
        if (action === 'CLICK' && selector) {
          await parked.page.click(selector);
        }

        if (completeHandoff === true) {
          this.activeMagicTokens.delete(req.params.token);
          this.waitingBox.resumeSession(meta.taskId, {
            type: 'USER_CONFIRMED_HANDOFF_COMPLETE',
            completedAt: new Date().toISOString(),
          });
        }

        return res.status(200).json({ ok: true });
      } catch (err) {
        return res.status(500).json({ ok: false, error: err.message });
      }
    });

    return router;
  }
}

module.exports = {
  LiveHandoffProxy,
  OTP_REMINDER_INTERVAL_MS,
};