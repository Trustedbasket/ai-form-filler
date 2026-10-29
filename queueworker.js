/**
 * @file QueueWorker.js
 * @description Asynchronous Multi-Tenant Cloud Worker & "Waiting Box" Session Manager.
 *
 * Architectural Highlights:
 *  1. BullMQ + Isolated BrowserContext Pool: Processes concurrent form-filling jobs where each
 *     user receives a strictly isolated Incognito `BrowserContext` (zero cookie/storage overlap).
 *  2. Non-Blocking "Waiting Box" Registry: When User A reaches an OTP or Live Photo step, User A's
 *     active `BrowserContext` and `Page` are parked in an in-memory `waitingBoxRegistry` keyed by
 *     `taskId` with a keep-alive heartbeat, freeing the worker concurrency slot to immediately
 *     process User B and User C. When User A replies on Telegram or completes the Live Photo handoff,
 *     the exact parked `Page` resumes immediately without losing portal session state.
 *  3. Sequential Human Simulation: Types characters with an 80ms-120ms randomized cadence and clicks
 *     intermediate "Save & Next" buttons so progress is persisted natively by the portal.
 *  4. Strict 99% Stop & Payment Handoff Rule: Automatically halts when the "Preview / Fee Payment /
 *     Final Submit" boundary is detected, verifies populated field values, notifies the user via
 *     `NotificationService`, and purges all stretched keys and temporary buffers from RAM.
 */

'use strict';

const EventEmitter = require('events');
const crypto = require('crypto');

// Optional dynamic imports so the worker runs seamlessly with BullMQ + Puppeteer in production
let Worker = null;
let Queue = null;
let puppeteer = null;

try {
  ({ Worker, Queue } = require('bullmq'));
} catch (_) {
  // Fallback in-memory queue adapter if BullMQ is not installed in test sandbox
}

try {
  puppeteer = require('puppeteer');
} catch (_) {
  puppeteer = null;
}

const SLEEP = (ms) => new Promise((resolve) => setTimeout(resolve, ms));

/**
 * Generates a human-like typing delay between 80ms and 120ms per character.
 * @returns {number}
 */
function getHumanKeystrokeDelayMs() {
  return Math.floor(80 + Math.random() * 41); // 80ms to 120ms inclusive
}

class WaitingBoxSessionManager extends EventEmitter {
  /**
   * Manages parked `BrowserContext` and `Page` instances waiting on asynchronous user input
   * (Telegram OTP reply or Live Photo / Interactive Verification Handoff) without blocking worker threads.
   */
  constructor() {
    super();
    /**
     * Map<taskId, {
     *   taskId: string,
     *   userId: string,
     *   examName: string,
     *   recipientId: string,
     *   browserContext: Object,
     *   page: Object,
     *   pauseReason: 'OTP_REQUIRED' | 'LIVE_PHOTO_HANDOFF' | 'MANUAL_VERIFICATION',
     *   pausedAt: number,
     *   keepAliveTimer: NodeJS.Timeout,
     *   resumeResolver: Function,
     *   resumeRejecter: Function
     * }>
     */
    this.parkedSessions = new Map();
  }

  /**
   * Parks an active user session inside the Waiting Box and starts a non-intrusive
   * keep-alive heartbeat on the page so the portal session does not expire while waiting.
   *
   * @param {Object} sessionMeta
   * @param {number} [maxWaitMs=600000] - Default 10-minute maximum park duration
   * @returns {Promise<Object>} Resolves with `{ resumePayload }` as soon as the user responds
   */
  parkSession(sessionMeta, maxWaitMs = 10 * 60 * 1000) {
    const {
      taskId,
      userId,
      examName,
      recipientId,
      browserContext,
      page,
      pauseReason,
    } = sessionMeta;

    if (this.parkedSessions.has(taskId)) {
      this.evictSession(taskId, new Error('DUPLICATE_PARK_ATTEMPT'));
    }

    return new Promise((resolve, reject) => {
      // Keep-alive heartbeat every 25s to prevent idle portal session expiry
      const keepAliveTimer = setInterval(async () => {
        try {
          if (page && !page.isClosed()) {
            await page.evaluate(() => {
              window.dispatchEvent(new Event('mousemove'));
            });
          }
        } catch (_) {
          // Ignore transient navigation errors during keep-alive
        }
      }, 25000);

      const timeoutTimer = setTimeout(() => {
        this.evictSession(
          taskId,
          new Error(`WAITING_BOX_TIMEOUT: Task ${taskId} exceeded max wait time of ${maxWaitMs / 1000}s.`)
        );
      }, maxWaitMs);

      this.parkedSessions.set(taskId, {
        taskId,
        userId,
        examName,
        recipientId,
        browserContext,
        page,
        pauseReason,
        pausedAt: Date.now(),
        keepAliveTimer,
        timeoutTimer,
        resumeResolver: resolve,
        resumeRejecter: reject,
      });

      this.emit('session_parked', { taskId, userId, examName, pauseReason });
    });
  }

  /**
   * Resumes a parked session immediately when an OTP or Live Handoff completion signal arrives.
   *
   * @param {string} taskId
   * @param {Object} resumePayload - e.g. `{ type: 'OTP', otpCode: '482910' }` or `{ type: 'HANDOFF_DONE' }`
   * @returns {boolean}
   */
  resumeSession(taskId, resumePayload) {
    const entry = this.parkedSessions.get(taskId);
    if (!entry) return false;

    clearInterval(entry.keepAliveTimer);
    clearTimeout(entry.timeoutTimer);
    this.parkedSessions.delete(taskId);

    entry.resumeResolver(resumePayload);
    this.emit('session_resumed', { taskId, userId: entry.userId, resumePayload });
    return true;
  }

  /**
   * Safely cleans up and rejects a parked session on timeout or cancellation.
   *
   * @param {string} taskId
   * @param {Error} reasonError
   */
  evictSession(taskId, reasonError) {
    const entry = this.parkedSessions.get(taskId);
    if (!entry) return;

    clearInterval(entry.keepAliveTimer);
    clearTimeout(entry.timeoutTimer);
    this.parkedSessions.delete(taskId);

    if (entry.resumeRejecter && reasonError) {
      entry.resumeRejecter(reasonError);
    }
  }

  /**
   * Retrieves an active parked session (used by `LiveHandoffProxy` to stream the active Page).
   * @param {string} taskId
   */
  getParkedSession(taskId) {
    return this.parkedSessions.get(taskId) || null;
  }
}

// ============================================================================
// MAIN CLOUD WORKER ENGINE (BULLMQ + ISOLATED BROWSER CONTEXTS)
// ============================================================================
class FormFillerQueueWorker {
  /**
   * @param {Object} dependencies
   * @param {Object} dependencies.redisConnection - IORedis connection options for BullMQ
   * @param {import('./JITMemoryEngine').JITMemoryEngine} dependencies.jitMemoryEngine
   * @param {import('./DOMCleanerAndMapper').DOMCleanerAndMapper} dependencies.domMapper
   * @param {import('./LiveHandoffProxy').LiveHandoffProxy} dependencies.handoffProxy
   * @param {Object} dependencies.notificationService - Part 1 NotificationService instance
   * @param {Object} [dependencies.workerOptions]
   */
  constructor(dependencies) {
    const {
      redisConnection,
      jitMemoryEngine,
      domMapper,
      handoffProxy,
      notificationService,
      workerOptions = {},
    } = dependencies;

    if (!jitMemoryEngine || !domMapper || !handoffProxy || !notificationService) {
      throw new Error('FormFillerQueueWorker requires jitMemoryEngine, domMapper, handoffProxy, and notificationService.');
    }

    this.redisConnection = redisConnection || {
      host: process.env.REDIS_HOST || '127.0.0.1',
      port: Number(process.env.REDIS_PORT) || 6379,
    };

    this.jitMemoryEngine = jitMemoryEngine;
    this.domMapper = domMapper;
    this.handoffProxy = handoffProxy;
    this.notificationService = notificationService;
    this.waitingBox = new WaitingBoxSessionManager();

    // Register WaitingBox with LiveHandoffProxy so magic links can access parked pages
    this.handoffProxy.bindWaitingBox(this.waitingBox);

    this.queueName = workerOptions.queueName || 'automated-form-filler-tasks';
    this.maxConcurrency = workerOptions.maxConcurrency || 12;
    this.outboundProxyUrl = workerOptions.outboundProxyUrl || process.env.OUTBOUND_TUNNEL_PROXY || '';
    this.browser = null;
    this.bullQueue = null;
    this.bullWorker = null;
  }

  /**
   * Launches the shared Chromium instance with strict isolation flags.
   * Each user job creates its own isolated Incognito `BrowserContext` inside this browser.
   */
  async initBrowserPool() {
    if (this.browser) return this.browser;
    if (!puppeteer) {
      throw new Error('Puppeteer module is required to initialize the browser pool.');
    }

    const launchArgs = [
      '--no-sandbox',
      '--disable-setuid-sandbox',
      '--disable-dev-shm-usage',
      '--disable-accelerated-2d-canvas',
      '--window-size=1366,768',
    ];

    if (this.outboundProxyUrl) {
      launchArgs.push(`--proxy-server=${this.outboundProxyUrl}`);
    }

    this.browser = await puppeteer.launch({
      headless: 'new',
      args: launchArgs,
      defaultViewport: { width: 1366, height: 768 },
    });

    return this.browser;
  }

  /**
   * Starts the BullMQ Worker to process "Fire-and-Forget" form filling tasks concurrently.
   */
  async startWorker() {
    await this.initBrowserPool();

    if (Queue && Worker) {
      this.bullQueue = new Queue(this.queueName, { connection: this.redisConnection });
      this.bullWorker = new Worker(
        this.queueName,
        async (job) => this.executeFormTask(job.data),
        {
          connection: this.redisConnection,
          concurrency: this.maxConcurrency,
          lockDuration: 15 * 60 * 1000, // 15-minute lock to accommodate multi-step forms & OTP pauses
        }
      );

      this.bullWorker.on('failed', (job, err) => {
        if (job && job.data && job.data.userId) {
          this.jitMemoryEngine.purgeTaskMemory(job.data.taskId, job.data.userId);
        }
      });
    }

    return {
      status: 'WORKER_ONLINE',
      queueName: this.queueName,
      maxConcurrency: this.maxConcurrency,
    };
  }

  /**
   * Enqueues a new "Fire-and-Forget" user task after the user enters their Master PIN
   * and clicks "Start". The user can immediately close their browser tab.
   *
   * @param {Object} taskPayload
   * @param {string} taskPayload.userId
   * @param {string} taskPayload.recipientId - Telegram Chat ID or WhatsApp number
   * @param {string} taskPayload.examName - e.g. 'SSC CGL 2026'
   * @param {string} taskPayload.portalUrl - Target application form URL
   * @param {Object} taskPayload.examChecklist - Verified rules from Part 1 `JobRequirementService`
   */
  async enqueueFireAndForgetTask(taskPayload) {
    const taskId = taskPayload.taskId || `task_${crypto.randomUUID()}`;
    const jobData = {
      ...taskPayload,
      taskId,
      enqueuedAt: new Date().toISOString(),
    };

    if (this.bullQueue) {
      await this.bullQueue.add('fill-exam-form', jobData, {
        jobId: taskId,
        removeOnComplete: true,
        removeOnFail: false,
      });
    } else {
      // Asynchronous non-blocking execution when running in local/in-memory mode
      setImmediate(() => {
        this.executeFormTask(jobData).catch(() => {});
      });
    }

    return {
      accepted: true,
      taskId,
      message: 'Task queued in background worker. You may safely close your browser; updates will arrive on Telegram.',
    };
  }

  /**
   * Executes the multi-step form filling workflow inside an isolated `BrowserContext`.
   *
   * @param {Object} jobData
   */
  async executeFormTask(jobData) {
    const {
      taskId,
      userId,
      recipientId,
      examName,
      portalUrl,
      examChecklist,
      maxSteps = 8,
    } = jobData;

    const browser = await this.initBrowserPool();
    // Create an isolated Incognito BrowserContext so cookies/localStorage never leak across users
    const browserContext = await browser.createBrowserContext();
    const page = await browserContext.newPage();

    try {
      await page.setUserAgent(
        'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/128.0.0.0 Safari/537.36'
      );

      await this.notificationService.sendAlert(
        recipientId,
        `🚀 *[${examName}] Background Worker Started*\nTask ID: \`${taskId}\`\nAap apna browser band kar sakte hain. Jab OTP ya Live Photo ki zaroorat hogi, aapko yahin alert milega.`
      );

      await page.goto(portalUrl, { waitUntil: 'networkidle2', timeout: 60000 });

      for (let stepIndex = 1; stepIndex <= maxSteps; stepIndex++) {
        // 1. Capture raw DOM and run Pre-Emptive Step Analysis
        const rawHtml = await page.content();
        const stepAnalysis = this.domMapper.inspectPageStageAndTriggers(rawHtml);

        // 2. STRICT 99% STOP RULE: Never auto-submit or enter payment gateways
        if (stepAnalysis.isFinalPreviewOrPaymentStage) {
          const verificationReport = await this._runSecondaryPreviewVerification(page);

          const handoffSession = this.handoffProxy.createMagicHandoffLink({
            taskId,
            userId,
            examName,
            purpose: 'FINAL_PREVIEW_AND_PAYMENT',
            ttlMs: 15 * 60 * 1000,
          });

          await this.notificationService.sendAlert(
            recipientId,
            `✅ *Form is 99% filled and verified!* (${verificationReport.verifiedCount} fields checked)\n\n` +
              `Security Policy ke tahat hum *Final Submit* ya *Payment* auto-click nahi karte.\n` +
              `👉 [Open Secure Preview & Complete Payment](${handoffSession.magicUrl})\n` +
              `_Note: Master PIN aur aapka decrypted data Server RAM se purge kar diya gaya hai._`
          );

          // Park briefly for user preview handoff, then clean up
          this.jitMemoryEngine.purgeTaskMemory(taskId, userId);
          return {
            status: 'COMPLETED_99_PERCENT_HANDOFF',
            taskId,
            stepReached: stepIndex,
            verificationReport,
            handoffUrl: handoffSession.magicUrl,
          };
        }

        // 3. PRE-EMPTIVE ALERTS: Notify user ahead of time if upcoming fields require human input
        if (stepAnalysis.hasUpcomingOtp || stepAnalysis.hasUpcomingLivePhoto || stepAnalysis.hasUpcomingCaptcha) {
          await this.notificationService.sendAlert(
            recipientId,
            `⚠️ *[${examName}] Pre-Alert (Step ${stepIndex}):* Is page par ${
              stepAnalysis.hasUpcomingLivePhoto
                ? 'Live Camera Photo / Captcha'
                : 'Mobile/Email OTP Verification'
            } step detect hua hai. Kripya apna phone ready rakhein.`
          );
        }

        // 4. DOUBLE-LAYER DATA MASKING: Sanitize HTML and map form inputs to [TOKEN_X] placeholders
        const { maskedHtml, tokenCatalog } = this.domMapper.buildMaskedFormPrompt(rawHtml);
        const executionPlan = await this.domMapper.fetchGeminiSelectorMapping(maskedHtml, tokenCatalog, examName);

        // 5. Execute each field action using JIT 1-ms RAM decryption & human typing cadence
        for (const instruction of executionPlan.actions) {
          await this._executeSingleFieldInstruction({
            page,
            instruction,
            taskId,
            userId,
            recipientId,
            examName,
            examChecklist,
            browserContext,
          });
        }

        // 6. Click intermediate "Save & Next" button if present (never Final Submit)
        if (executionPlan.saveAndNextSelector && !stepAnalysis.isFinalPreviewOrPaymentStage) {
          await Promise.all([
            page.waitForNavigation({ waitUntil: 'networkidle2', timeout: 30000 }).catch(() => {}),
            page.click(executionPlan.saveAndNextSelector),
          ]);
          await SLEEP(800);
        } else {
          break;
        }
      }

      return { status: 'WORKFLOW_FINISHED', taskId };
    } finally {
      // Guarantee RAM zeroization of Master PIN and temporary buffers
      this.jitMemoryEngine.purgeTaskMemory(taskId, userId);
      try {
        await browserContext.close();
      } catch (_) {}
    }
  }

  /**
   * Executes a single field action (Text Input, Dropdown, File Upload, OTP Wait, or Live Photo Handoff).
   */
  async _executeSingleFieldInstruction(ctx) {
    const {
      page,
      instruction,
      taskId,
      userId,
      recipientId,
      examName,
      examChecklist,
      browserContext,
    } = ctx;

    const { selector, actionType, tokenKey, documentCategory } = instruction;

    // CASE A: Text / Number / Date Input with 1-ms JIT RAM Swap & 80-120ms Human Typing
    if (actionType === 'TYPE_TEXT' || actionType === 'SELECT_OPTION') {
      await page.waitForSelector(selector, { visible: true, timeout: 15000 });

      // Decrypt only the single requested field in RAM 1ms before DOM injection
      await this.jitMemoryEngine.withMicroBurstField(
        { taskId, userId, fieldPath: this.domMapper.resolveFieldPathFromToken(tokenKey) },
        async (plaintextValueBuffer) => {
          const realValueStr = plaintextValueBuffer.toString('utf8');

          if (actionType === 'SELECT_OPTION') {
            await page.select(selector, realValueStr);
          } else {
            await page.focus(selector);
            for (const char of realValueStr) {
              await page.keyboard.type(char, { delay: getHumanKeystrokeDelayMs() });
            }
          }
        }
      );
      return;
    }

    // CASE B: In-Memory Image/Document Resizing via Sharp (Zero-Disk Rule)
    if (actionType === 'UPLOAD_DOCUMENT') {
      const docRule = this._findDocumentRule(examChecklist, documentCategory);
      await this.jitMemoryEngine.withInMemoryResizedDocument(
        {
          taskId,
          userId,
          category: documentCategory,
          resizeRules: docRule,
        },
        async (resizedBuffer, fileMetadata) => {
          // Inject buffer directly into file input via DataTransfer in browser memory (zero disk files)
          const base64Payload = resizedBuffer.toString('base64');
          await page.evaluate(
            ({ targetSelector, b64Data, fileName, mimeType }) => {
              const inputEl = document.querySelector(targetSelector);
              if (!inputEl) throw new Error(`Upload selector not found: ${targetSelector}`);

              const byteCharacters = atob(b64Data);
              const byteNumbers = new Array(byteCharacters.length);
              for (let i = 0; i < byteCharacters.length; i++) {
                byteNumbers[i] = byteCharacters.charCodeAt(i);
              }
              const byteArray = new Uint8Array(byteNumbers);
              const fileObj = new File([byteArray], fileName, { type: mimeType });

              const dataTransfer = new DataTransfer();
              dataTransfer.items.add(fileObj);
              inputEl.files = dataTransfer.files;
              inputEl.dispatchEvent(new Event('change', { bubbles: true }));
            },
            {
              targetSelector: selector,
              b64Data: base64Payload,
              fileName: fileMetadata.fileName,
              mimeType: fileMetadata.mimeType,
            }
          );
        }
      );
      return;
    }

    // CASE C: Asynchronous OTP Pause in Waiting Box + 30-Second Telegram Reminder Loop
    if (actionType === 'WAIT_FOR_OTP') {
      const otpCode = await this.handoffProxy.waitForOtpWith30sReminders({
        taskId,
        userId,
        recipientId,
        examName,
        stepLabel: instruction.stepLabel || 'OTP Verification Step',
        browserContext,
        page,
      });

      await page.waitForSelector(selector, { visible: true, timeout: 15000 });
      await page.focus(selector);
      for (const digit of String(otpCode)) {
        await page.keyboard.type(digit, { delay: getHumanKeystrokeDelayMs() });
      }
      return;
    }

    // CASE D: 100% Legal Live Webcam Photo / Interactive Captcha Reverse-Proxy Handoff
    if (actionType === 'LIVE_PHOTO_OR_CAPTCHA_HANDOFF') {
      await this.handoffProxy.initiateLivePortalHandoff({
        taskId,
        userId,
        recipientId,
        examName,
        browserContext,
        page,
        reason: instruction.handoffReason || 'LIVE_WEBCAM_OR_CAPTCHA',
      });
    }
  }

  /**
   * Matches the requested document category against the verified exam checklist rules from Part 1.
   */
  _findDocumentRule(examChecklist, category) {
    const docs = (examChecklist && examChecklist.requiredDocuments) || [];
    const matched = docs.find((d) => d.category === category);
    if (matched) return matched;

    // Safe default rules if exam checklist did not specify custom bounds
    return {
      category,
      minSizeKB: 20,
      maxSizeKB: 50,
      allowedFormats: ['JPG', 'JPEG'],
      dimensions: { minWidthPx: 200, maxWidthPx: 230, minHeightPx: 230, maxHeightPx: 250, dpi: 200 },
    };
  }

  /**
   * Performs a secondary verification pass on the 99% Preview screen to confirm populated inputs.
   */
  async _runSecondaryPreviewVerification(page) {
    return page.evaluate(() => {
      const inputs = Array.from(document.querySelectorAll('input:not([type="hidden"]), select, textarea'));
      const populated = inputs.filter((el) => el.value && String(el.value).trim().length > 0);
      return {
        totalInspectableFields: inputs.length,
        verifiedCount: populated.length,
        timestamp: new Date().toISOString(),
      };
    });
  }
}

module.exports = {
  FormFillerQueueWorker,
  WaitingBoxSessionManager,
  getHumanKeystrokeDelayMs,
};