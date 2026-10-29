/**
 * @file NotificationService.js
 * @description Plug-and-Play Notification & Real-Time OTP Reply Engine (Adapter Pattern).
 *
 * Architecture:
 *  - Defines a strict provider interface (`sendAlert`, `waitForOtpReply`, `handleIncomingPayload`).
 *  - Ships with a complete, 100% free `TelegramBotAdapter` supporting both Long-Polling and Webhooks
 *    to send instant exam form alerts and read incoming 4-to-8 digit OTP replies from the user.
 *  - Includes a pre-wired `WhatsAppCloudAdapter` so switching the entire application from Telegram
 *    to the Official Meta WhatsApp Cloud API requires changing just the provider instantiation lines
 *    at the bottom of this file (or setting `NOTIFICATION_PROVIDER=whatsapp` in `.env`) without
 *    touching a single controller or service elsewhere in the codebase.
 */

'use strict';

const EventEmitter = require('events');

// ============================================================================
// BASE ADAPTER CONTRACT (INTERFACE)
// ============================================================================
class BaseNotificationAdapter extends EventEmitter {
  constructor() {
    super();
    /**
     * Pending OTP resolvers keyed by recipientId (chatId or phone number):
     * Map<string, { resolve: Function, reject: Function, timer: NodeJS.Timeout, examName: string }>
     */
    this.pendingOtpWaiters = new Map();
  }

  /**
   * Sends a message/alert to the user.
   * @param {string} recipientId - Telegram Chat ID or E.164 WhatsApp Phone Number
   * @param {string} messageText - Notification text
   * @returns {Promise<{ delivered: boolean, messageId: string|number }>}
   */
  async sendAlert(recipientId, messageText) {
    throw new Error('METHOD_NOT_IMPLEMENTED: sendAlert() must be implemented by concrete adapter.');
  }

  /**
   * Prompts the user for an OTP and resolves as soon as the user replies with a valid OTP code.
   *
   * @param {Object} params
   * @param {string} params.recipientId - Telegram Chat ID or WhatsApp Phone Number
   * @param {string} params.examName - e.g. 'SSC CGL 2026'
   * @param {number} [params.timeoutMs=180000] - Default 3-minute OTP wait window
   * @returns {Promise<{ otpCode: string, receivedAt: string }>}
   */
  async requestAndWaitForOtp({ recipientId, examName, timeoutMs = 180000 }) {
    const normalizedRecipient = String(recipientId).trim();

    // Cancel any stale waiter for the same user
    if (this.pendingOtpWaiters.has(normalizedRecipient)) {
      const stale = this.pendingOtpWaiters.get(normalizedRecipient);
      clearTimeout(stale.timer);
      stale.reject(new Error('OTP_WAIT_SUPERSEDED: A newer OTP request was initiated.'));
      this.pendingOtpWaiters.delete(normalizedRecipient);
    }

    await this.sendAlert(
      normalizedRecipient,
      `🔐 *[${examName}] OTP Verification Required*\n\n` +
        `Portal ne aapke registered mobile/email par OTP bheja hai.\n` +
        `Please is message ke reply mein apna *4-8 digit OTP* bhejein (Valid for ${Math.floor(timeoutMs / 60000)} mins).`
    );

    return new Promise((resolve, reject) => {
      const timer = setTimeout(() => {
        this.pendingOtpWaiters.delete(normalizedRecipient);
        reject(new Error(`OTP_TIMEOUT: User did not reply with an OTP within ${timeoutMs / 1000} seconds.`));
      }, timeoutMs);

      this.pendingOtpWaiters.set(normalizedRecipient, {
        resolve,
        reject,
        timer,
        examName,
      });
    });
  }

  /**
   * Internal helper called when a message arrives via Webhook or Polling.
   * Extracts a 4-to-8 digit OTP and resolves any pending `requestAndWaitForOtp` promise.
   *
   * @param {string} senderId
   * @param {string} rawText
   * @returns {boolean} True if matched and resolved a pending OTP request
   */
  _dispatchIncomingMessage(senderId, rawText) {
    const normalizedSender = String(senderId).trim();
    const cleanText = String(rawText || '').trim();

    this.emit('message', { senderId: normalizedSender, text: cleanText, timestamp: new Date().toISOString() });

    // Match standalone 4 to 8 digit numeric OTP inside the user's reply
    const otpMatch = cleanText.match(/\b(\d{4,8})\b/);
    if (!otpMatch) {
      return false;
    }

    const extractedOtp = otpMatch[1];
    const waiter = this.pendingOtpWaiters.get(normalizedSender);

    if (waiter) {
      clearTimeout(waiter.timer);
      this.pendingOtpWaiters.delete(normalizedSender);
      waiter.resolve({
        otpCode: extractedOtp,
        examName: waiter.examName,
        receivedAt: new Date().toISOString(),
      });
      return true;
    }

    return false;
  }
}

// ============================================================================
// CONCRETE ADAPTER 1: TELEGRAM BOT API (100% FREE - ACTIVE DEFAULT)
// Supports both Webhook ingestion & Long-Polling (`getUpdates`)
// ============================================================================
class TelegramBotAdapter extends BaseNotificationAdapter {
  /**
   * @param {Object} config
   * @param {string} config.botToken - Telegram Bot Token from @BotFather
   * @param {boolean} [config.enablePolling=false] - Enable automatic background long-polling
   * @param {number} [config.pollingIntervalMs=2500]
   */
  constructor({ botToken, enablePolling = false, pollingIntervalMs = 2500 }) {
    super();
    if (!botToken) {
      throw new Error('TelegramBotAdapter requires a valid TELEGRAM_BOT_TOKEN.');
    }

    this.botToken = botToken;
    this.baseUrl = `https://api.telegram.org/bot${this.botToken}`;
    this.lastUpdateId = 0;
    this.isPolling = false;
    this.pollingTimer = null;
    this.pollingIntervalMs = pollingIntervalMs;

    if (enablePolling) {
      this.startPolling();
    }
  }

  /**
   * Sends a Markdown-formatted alert message via Telegram `sendMessage`.
   * @param {string} chatId
   * @param {string} messageText
   */
  async sendAlert(chatId, messageText) {
    const response = await fetch(`${this.baseUrl}/sendMessage`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        chat_id: String(chatId).trim(),
        text: messageText,
        parse_mode: 'Markdown',
        disable_web_page_preview: true,
      }),
    });

    const payload = await response.json();
    if (!response.ok || !payload.ok) {
      throw new Error(`TELEGRAM_SEND_ERROR: ${payload.description || response.statusText}`);
    }

    return {
      delivered: true,
      provider: 'telegram',
      messageId: payload.result.message_id,
    };
  }

  /**
   * Processes an incoming Telegram Update object (called by Webhook route or Polling loop).
   * @param {Object} update - Telegram Update JSON payload
   */
  async handleIncomingWebhook(update) {
    if (!update || typeof update !== 'object') return { handled: false };

    if (typeof update.update_id === 'number' && update.update_id >= this.lastUpdateId) {
      this.lastUpdateId = update.update_id + 1;
    }

    const messageObj = update.message || update.edited_message;
    if (!messageObj || !messageObj.chat || !messageObj.text) {
      return { handled: false };
    }

    const chatId = String(messageObj.chat.id);
    const text = messageObj.text.trim();

    // Built-in `/start` command helper so users can easily discover their Chat ID
    if (text === '/start') {
      await this.sendAlert(
        chatId,
        `✅ *Automated AI Form Filler Connected!*\nAapka Telegram Chat ID hai: \`${chatId}\`\nIs Chat ID ko apne Dashboard Profile mein save karein.`
      );
      return { handled: true, command: 'start', chatId };
    }

    const matchedOtp = this._dispatchIncomingMessage(chatId, text);
    if (matchedOtp) {
      await this.sendAlert(chatId, '✅ *OTP Received!* Form submission aage badh raha hai...');
    }

    return { handled: true, matchedOtp, chatId };
  }

  /**
   * Starts long-polling Telegram `getUpdates` to read user OTP replies without needing a public HTTPS webhook.
   */
  startPolling() {
    if (this.isPolling) return;
    this.isPolling = true;

    const pollTick = async () => {
      if (!this.isPolling) return;
      try {
        const url = `${this.baseUrl}/getUpdates?offset=${this.lastUpdateId}&timeout=10&allowed_updates=["message"]`;
        const response = await fetch(url);
        const data = await response.json();

        if (data && data.ok && Array.isArray(data.result)) {
          for (const update of data.result) {
            await this.handleIncomingWebhook(update);
          }
        }
      } catch (err) {
        this.emit('polling_error', err);
      } finally {
        if (this.isPolling) {
          this.pollingTimer = setTimeout(pollTick, this.pollingIntervalMs);
        }
      }
    };

    pollTick();
  }

  /**
   * Gracefully stops background polling.
   */
  stopPolling() {
    this.isPolling = false;
    if (this.pollingTimer) {
      clearTimeout(this.pollingTimer);
      this.pollingTimer = null;
    }
  }
}

// ============================================================================
// CONCRETE ADAPTER 2: OFFICIAL WHATSAPP CLOUD API (DROP-IN FUTURE ADAPTER)
// Ready for instant activation when scaling from Telegram to WhatsApp Cloud API
// ============================================================================
class WhatsAppCloudAdapter extends BaseNotificationAdapter {
  /**
   * @param {Object} config
   * @param {string} config.accessToken - Meta Graph API Permanent Access Token
   * @param {string} config.phoneNumberId - WhatsApp Business Phone Number ID
   */
  constructor({ accessToken, phoneNumberId }) {
    super();
    if (!accessToken || !phoneNumberId) {
      throw new Error('WhatsAppCloudAdapter requires WHATSAPP_ACCESS_TOKEN and WHATSAPP_PHONE_NUMBER_ID.');
    }
    this.accessToken = accessToken;
    this.phoneNumberId = phoneNumberId;
    this.graphUrl = `https://graph.facebook.com/v20.0/${this.phoneNumberId}/messages`;
  }

  async sendAlert(recipientPhone, messageText) {
    const response = await fetch(this.graphUrl, {
      method: 'POST',
      headers: {
        Authorization: `Bearer ${this.accessToken}`,
        'Content-Type': 'application/json',
      },
      body: JSON.stringify({
        messaging_product: 'whatsapp',
        recipient_type: 'individual',
        to: String(recipientPhone).replace(/[^0-9]/g, ''),
        type: 'text',
        text: { preview_url: false, body: messageText },
      }),
    });

    const payload = await response.json();
    if (!response.ok) {
      throw new Error(`WHATSAPP_SEND_ERROR: ${JSON.stringify(payload.error || response.statusText)}`);
    }

    return {
      delivered: true,
      provider: 'whatsapp',
      messageId: payload.messages && payload.messages[0] ? payload.messages[0].id : null,
    };
  }

  async handleIncomingWebhook(webhookBody) {
    const entry = webhookBody?.entry?.[0]?.changes?.[0]?.value;
    const message = entry?.messages?.[0];
    if (!message || message.type !== 'text') return { handled: false };

    const senderPhone = message.from;
    const text = message.text?.body || '';
    const matchedOtp = this._dispatchIncomingMessage(senderPhone, text);

    return { handled: true, matchedOtp, senderPhone };
  }
}

// ============================================================================
// UNIFIED NOTIFICATION SERVICE FACADE (PLUG-AND-PLAY SWAP BLOCK)
// To switch the entire SaaS from Telegram to WhatsApp Cloud API in the future,
// only the 10-line adapter selection block inside `createNotificationService`
// (or the `NOTIFICATION_PROVIDER` env variable) needs to change.
// ============================================================================
class NotificationService {
  /**
   * @param {BaseNotificationAdapter} adapter
   */
  constructor(adapter) {
    if (!(adapter instanceof BaseNotificationAdapter)) {
      throw new Error('NotificationService requires an instance of BaseNotificationAdapter.');
    }
    this.adapter = adapter;
  }

  async sendAlert(recipientId, messageText) {
    return this.adapter.sendAlert(recipientId, messageText);
  }

  async requestAndWaitForOtp({ recipientId, examName, timeoutMs }) {
    return this.adapter.requestAndWaitForOtp({ recipientId, examName, timeoutMs });
  }

  async handleIncomingWebhook(payload) {
    return this.adapter.handleIncomingWebhook(payload);
  }
}

/**
 * Factory function that builds the active NotificationService based on config.
 * --- [10-LINE ADAPTER SWAP BLOCK] ---
 */
function createNotificationService(options = {}) {
  const provider = (options.provider || process.env.NOTIFICATION_PROVIDER || 'telegram').toLowerCase();

  if (provider === 'whatsapp') {
    return new NotificationService(
      new WhatsAppCloudAdapter({
        accessToken: options.whatsappAccessToken || process.env.WHATSAPP_ACCESS_TOKEN,
        phoneNumberId: options.whatsappPhoneNumberId || process.env.WHATSAPP_PHONE_NUMBER_ID,
      })
    );
  }

  return new NotificationService(
    new TelegramBotAdapter({
      botToken: options.telegramBotToken || process.env.TELEGRAM_BOT_TOKEN,
      enablePolling: options.enablePolling ?? process.env.NODE_ENV !== 'test',
    })
  );
}

module.exports = {
  NotificationService,
  BaseNotificationAdapter,
  TelegramBotAdapter,
  WhatsAppCloudAdapter,
  createNotificationService,
};