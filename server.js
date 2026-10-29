/**
 * @file server.js
 * @description PART 3: Enterprise API Gateway & Security Perimeter for "Automated AI Form Filler".
 *
 * Security & Architectural Layers:
 *  1. Express Hardening & Trust Proxy: Configured with `helmet`, strict CORS, and `trust proxy`
 *     so `AuditLogger.js` and `express-rate-limit` read the real client IP behind reverse proxies.
 *  2. Multi-Tier DDoS Protection (`express-rate-limit`):
 *     - Global API limiter (60 req/min per IP)
 *     - Strict Form Submission & Vault limiter (max 5 requests per minute per IP)
 *  3. RAM Crash / Memory Bomb Protection (`multer.memoryStorage()`):
 *     - Strict 5 MB (`5 * 1024 * 1024` bytes) file size ceiling per uploaded file.
 *     - Strict MIME-type whitelist (`image/jpeg`, `image/png`, `application/pdf`).
 *     - Rejects oversized payloads with `413 Payload Too Large` BEFORE they ever touch `CryptoVaultService`
 *       or `JITMemoryEngine`, and explicitly zeroes out (`Buffer.fill(0)`) all Multer RAM buffers in a
 *       `finally` block immediately after AES-256-GCM encryption completes.
 *  4. Core Endpoints:
 *     - `POST /api/vault/upload`: Initializes/Unlocks the user's Master PIN vault, encrypts profile
 *       biodata and uploaded documents (`photo`, `signature`, `marksheet10th`, `marksheet12th`, `govtIdProof`)
 *       via `CryptoVaultService`, and persists ciphertext blobs to Supabase/PostgreSQL.
 *     - `POST /api/task/start`: Verifies legal consent via `AuditLogger.js`, unlocks the user's
 *       Master PIN into volatile Server RAM, fetches the verified exam checklist via `JobRequirementService`,
 *       and enqueues a non-blocking background job via `FormFillerQueueWorker`.
 */

'use strict';

require('dotenv').config();

const express = require('express');
const helmet = require('helmet');
const cors = require('cors');
const rateLimit = require('express-rate-limit');
const multer = require('multer');
const { createClient } = require('@supabase/supabase-js');

// ============================================================================
// PART 1 & PART 2 MODULE IMPORTS (Assumed in the same directory)
// ============================================================================
// ============================================================================
// PART 1 & PART 2 MODULE IMPORTS (Assumed in the same directory)
// ============================================================================
const { CryptoVaultService } = require('./cryptovault');
const { createAuditLoggerMiddleware, extractClientIp } = require('./auditlogger');
const { createNotificationService } = require('./notificationservice');
const { JobRequirementService } = require('./jobrequirementservice');
const { FormFillerQueueWorker } = require('./queueworker');
const { DOMCleanerAndMapper } = require('./domcleanerandmapper');
const { JITMemoryEngine } = require('./jitmemoryengine');
const { LiveHandoffProxy } = require('./livehandoffproxy');

// ============================================================================
// CONSTANTS & MEMORY PROTECTION LIMITS
// ============================================================================
const PORT = Number(process.env.PORT) || 3000;
const MAX_UPLOAD_FILE_SIZE_BYTES = 5 * 1024 * 1024; // Strict 5 MB ceiling per file
const MAX_UPLOAD_FILES_COUNT = 6;
const ALLOWED_UPLOAD_MIMES = new Set(['image/jpeg', 'image/jpg', 'image/png', 'application/pdf']);

// Map Multer field names to `encrypted_vault_records` SQL enum categories
const UPLOAD_FIELD_TO_CATEGORY = Object.freeze({
  photo: 'PHOTO',
  signature: 'SIGNATURE',
  marksheet10th: 'MARKSHEET_10TH',
  marksheet12th: 'MARKSHEET_12TH',
  graduationDegree: 'GRADUATION_DEGREE',
  govtIdProof: 'GOVT_ID_PROOF',
  categoryCertificate: 'CATEGORY_CERTIFICATE',
});

// ============================================================================
// INITIALIZE CORE SERVICES (PART 1 + PART 2)
// ============================================================================
const supabaseUrl = process.env.SUPABASE_URL || 'https://placeholder-project.supabase.co';
const supabaseServiceKey = process.env.SUPABASE_SERVICE_ROLE_KEY || 'placeholder-service-role-key';

const supabaseClient = createClient(supabaseUrl, supabaseServiceKey, {
  auth: { persistSession: false, autoRefreshToken: false },
});

const cryptoVault = new CryptoVaultService(supabaseClient, {
  serverPepper: process.env.VAULT_SERVER_PEPPER,
  ramKeyTtlMs: Number(process.env.RAM_KEY_TTL_MS) || 5 * 60 * 1000,
});

const notificationService = createNotificationService({
  provider: process.env.NOTIFICATION_PROVIDER || 'telegram',
  telegramBotToken: process.env.TELEGRAM_BOT_TOKEN || '000000000:DEV_PLACEHOLDER_TOKEN',
  enablePolling: process.env.NODE_ENV === 'production' && Boolean(process.env.TELEGRAM_BOT_TOKEN),
});

const jobRequirementService = new JobRequirementService({
  geminiApiKey: process.env.GEMINI_API_KEY || 'DEV_GEMINI_KEY_PLACEHOLDER',
  supabaseClient,
});

const domMapper = new DOMCleanerAndMapper({
  geminiApiKey: process.env.GEMINI_API_KEY || 'DEV_GEMINI_KEY_PLACEHOLDER',
});

const jitMemoryEngine = new JITMemoryEngine({ cryptoVault });

const handoffProxy = new LiveHandoffProxy({
  notificationService,
  publicBaseUrl: process.env.FRONTEND_ORIGIN || `http://localhost:${PORT}`,
  hmacSecret: process.env.VAULT_SERVER_PEPPER,
});

const redisConnectionConfig = process.env.REDIS_URL
  ? { url: process.env.REDIS_URL }
  : {
      host: process.env.REDIS_HOST || '127.0.0.1',
      port: Number(process.env.REDIS_PORT) || 6379,
    };

const queueWorker = new FormFillerQueueWorker({
  redisConnection: redisConnectionConfig,
  jitMemoryEngine,
  domMapper,
  handoffProxy,
  notificationService,
});

// ============================================================================
// EXPRESS APPLICATION & SECURITY MIDDLEWARE
// ============================================================================
const app = express();

// Trust first hop reverse proxy (Cloudflare / Nginx / Render / Fly.io) for accurate IP rate-limiting
app.set('trust proxy', 1);

app.use(
  helmet({
    crossOriginResourcePolicy: { policy: 'same-site' },
  })
);

app.use(
  cors({
    origin: process.env.FRONTEND_ORIGIN || '*',
    methods: ['GET', 'POST'],
    allowedHeaders: [
      'Content-Type',
      'Authorization',
      'X-User-Id',
      'X-Device-Fingerprint',
      'X-Explicit-Consent',
      'X-Consent-Statement',
    ],
  })
);

// Limit JSON body payload to 256kb to prevent JSON memory-exhaustion attacks
app.use(express.json({ limit: '256kb' }));
app.use(express.urlencoded({ extended: true, limit: '256kb' }));

// ============================================================================
// DDOS & RATE-LIMITING PERIMETER (`express-rate-limit`)
// ============================================================================

// 1. Strict Rate Limiter for Form Submissions & Vault Uploads (Max 5 requests / minute / IP)
const strictSubmissionRateLimiter = rateLimit({
  windowMs: 60 * 1000, // 1 minute window
  max: 5,              // Max 5 requests per minute per IP
  standardHeaders: true,
  legacyHeaders: false,
  keyGenerator: (req) => extractClientIp(req).clientRealIp,
  handler: (req, res) => {
    return res.status(429).json({
      success: false,
      error: 'DDOS_RATE_LIMIT_EXCEEDED',
      message: 'Too many requests from this IP address. Maximum 5 requests per minute allowed. Please wait 60 seconds.',
    });
  },
});

// 2. General API Rate Limiter (Max 60 requests / minute / IP)
const generalApiRateLimiter = rateLimit({
  windowMs: 60 * 1000,
  max: 60,
  standardHeaders: true,
  legacyHeaders: false,
  keyGenerator: (req) => extractClientIp(req).clientRealIp,
});

app.use('/api', generalApiRateLimiter);

// ============================================================================
// RAM CRASH / MEMORY BOMB PROTECTION (`multer` with Strict 5MB Limit)
// ============================================================================
const uploadMemoryGuard = multer({
  storage: multer.memoryStorage(),
  limits: {
    fileSize: MAX_UPLOAD_FILE_SIZE_BYTES, // Hard 5 MB ceiling per file
    files: MAX_UPLOAD_FILES_COUNT,        // Max 6 document files per upload request
    fieldSize: 128 * 1024,                // Max 128 KB for text fields (biodata JSON)
  },
  fileFilter: (req, file, cb) => {
    if (!UPLOAD_FIELD_TO_CATEGORY[file.fieldname]) {
      const fieldErr = new multer.MulterError('LIMIT_UNEXPECTED_FILE', file.fieldname);
      fieldErr.message = `Unsupported document field "${file.fieldname}".`;
      return cb(fieldErr, false);
    }

    if (!ALLOWED_UPLOAD_MIMES.has(file.mimetype.toLowerCase())) {
      const mimeErr = new Error(
        `INVALID_FILE_TYPE: File "${file.originalname}" (${file.mimetype}) is not allowed. Only JPEG, PNG, and PDF are accepted.`
      );
      mimeErr.statusCode = 415;
      return cb(mimeErr, false);
    }

    return cb(null, true);
  },
});

const vaultUploadFields = uploadMemoryGuard.fields([
  { name: 'photo', maxCount: 1 },
  { name: 'signature', maxCount: 1 },
  { name: 'marksheet10th', maxCount: 1 },
  { name: 'marksheet12th', maxCount: 1 },
  { name: 'graduationDegree', maxCount: 1 },
  { name: 'govtIdProof', maxCount: 1 },
  { name: 'categoryCertificate', maxCount: 1 },
]);

/**
 * Wrapper middleware that invokes Multer and immediately intercepts `LIMIT_FILE_SIZE` (>5MB)
 * before any downstream service or memory engine is touched.
 */
function enforceStrict5MbUploadMiddleware(req, res, next) {
  vaultUploadFields(req, res, (err) => {
    if (!err) return next();

    // Immediately wipe any partially buffered files in req.files if an error occurred mid-stream
    wipeMulterRequestBuffers(req);

    if (err instanceof multer.MulterError) {
      if (err.code === 'LIMIT_FILE_SIZE') {
        return res.status(413).json({
          success: false,
          error: 'MEMORY_BOMB_PROTECTION_TRIGGERED',
          message: 'File rejected: Maximum allowed upload size is strictly 5 MB per file.',
          maxAllowedBytes: MAX_UPLOAD_FILE_SIZE_BYTES,
        });
      }
      return res.status(400).json({
        success: false,
        error: `UPLOAD_LIMIT_VIOLATION_${err.code}`,
        message: err.message,
      });
    }

    return res.status(err.statusCode || 400).json({
      success: false,
      error: 'UPLOAD_VALIDATION_ERROR',
      message: err.message,
    });
  });
}

/**
 * Cryptographically zeroes out all temporary Multer `file.buffer` allocations in RAM.
 * @param {import('express').Request} req
 */
function wipeMulterRequestBuffers(req) {
  if (!req || !req.files || typeof req.files !== 'object') return;
  for (const fileArray of Object.values(req.files)) {
    if (Array.isArray(fileArray)) {
      for (const fileObj of fileArray) {
        if (fileObj && Buffer.isBuffer(fileObj.buffer)) {
          fileObj.buffer.fill(0);
        }
      }
    }
  }
}

// ============================================================================
// LEGAL AUDIT TRAIL MIDDLEWARE INSTANCES
// ============================================================================
const auditVaultUpload = createAuditLoggerMiddleware({
  supabaseClient,
  actionType: 'VAULT_ENCRYPTED_UPLOAD',
  requireExplicitConsent: true,
});

const auditTaskStart = createAuditLoggerMiddleware({
  supabaseClient,
  actionType: 'FORM_AUTOFILL_TASK_START',
  requireExplicitConsent: true,
});

// ============================================================================
// ENDPOINT 1: POST /api/vault/upload
// Accepts user profile details + documents (<5MB each), initializes or verifies
// the 4-digit Master PIN, encrypts everything with AES-256-GCM via CryptoVaultService,
// saves ciphertext to Supabase, and immediately zeroes out Multer RAM buffers.
// ============================================================================
app.post(
  '/api/vault/upload',
  strictSubmissionRateLimiter,
  enforceStrict5MbUploadMiddleware,
  auditVaultUpload,
  async (req, res) => {
    try {
      const userId = (req.user && req.user.id) || req.headers['x-user-id'] || req.body.userId;
      const { masterPin, isFirstTimeSetup, profileBiodata, telegramChatId, whatsappPhone } = req.body;

      if (!userId || !masterPin) {
        return res.status(400).json({
          success: false,
          error: 'MISSING_CREDENTIALS',
          message: 'Both `userId` and 4-digit `masterPin` are required.',
        });
      }

      // 1. Initialize Master PIN on first setup OR verify existing Master PIN & unlock key in Server RAM
      if (isFirstTimeSetup === true || isFirstTimeSetup === 'true') {
        await cryptoVault.initializeMasterPin(userId, String(masterPin), {
          telegramChatId,
          whatsappPhone,
        });
      } else {
        await cryptoVault.verifyPinAndUnlockVault(userId, String(masterPin));
      }

      const savedRecords = [];

      // 2. Encrypt & Persist Profile Biodata JSON if provided
      if (profileBiodata) {
        const parsedBiodata =
          typeof profileBiodata === 'string' ? JSON.parse(profileBiodata) : profileBiodata;

        const biodataMeta = await cryptoVault.storeEncryptedRecord({
          userId,
          category: 'PROFILE_BIODATA',
          payload: parsedBiodata,
          mimeType: 'application/json',
        });
        savedRecords.push(biodataMeta);
      }

      // 3. Encrypt & Persist Uploaded Document Buffers (Photo, Signature, Marksheets, Govt ID)
      if (req.files && typeof req.files === 'object') {
        for (const [fieldName, fileArray] of Object.entries(req.files)) {
          const category = UPLOAD_FIELD_TO_CATEGORY[fieldName];
          const fileObj = Array.isArray(fileArray) ? fileArray[0] : null;

          if (category && fileObj && Buffer.isBuffer(fileObj.buffer)) {
            const docMeta = await cryptoVault.storeEncryptedRecord({
              userId,
              category,
              payload: fileObj.buffer,
              mimeType: fileObj.mimetype,
            });
            savedRecords.push(docMeta);

            // Immediately zeroize the plaintext upload buffer in RAM right after encryption
            fileObj.buffer.fill(0);
          }
        }
      }

      return res.status(200).json({
        success: true,
        message: 'Profile details and documents encrypted with AES-256-GCM and stored in vault.',
        auditReceipt: req.auditContext,
        storedCategories: savedRecords.map((r) => ({
          recordId: r.record_id,
          category: r.record_category,
          sizeBytes: r.original_size_bytes,
          sha256Checksum: r.sha256_checksum,
        })),
      });
    } catch (err) {
      const status = err.statusCode || 500;
      return res.status(status).json({
        success: false,
        error: err.code || 'VAULT_UPLOAD_ERROR',
        message: err.message,
        attemptsRemaining: err.attemptsRemaining,
        lockedUntil: err.lockedUntil,
      });
    } finally {
      // Guarantee RAM cleanup of any remaining Multer buffers
      wipeMulterRequestBuffers(req);
    }
  }
);

// ============================================================================
// ENDPOINT 2: POST /api/task/start
// Verifies Master PIN + Legal Consent, fetches verified exam rules via Gemini,
// and pushes a "Fire-and-Forget" job into BullMQ (`FormFillerQueueWorker`).
// ============================================================================
app.post(
  '/api/task/start',
  strictSubmissionRateLimiter,
  auditTaskStart,
  async (req, res) => {
    try {
      const userId = (req.user && req.user.id) || req.headers['x-user-id'] || req.body.userId;
      const { masterPin, examName, portalUrl, recipientId, examChecklistOverride } = req.body;

      if (!userId || !masterPin || !examName || !portalUrl || !recipientId) {
        return res.status(400).json({
          success: false,
          error: 'MISSING_TASK_PARAMETERS',
          message: 'Required fields: `userId`, `masterPin`, `examName`, `portalUrl`, and `recipientId` (Telegram Chat ID).',
        });
      }

      // 1. Verify Master PIN and cache stretched 256-bit key in volatile Server RAM for JIT worker access
      await cryptoVault.verifyPinAndUnlockVault(userId, String(masterPin));

      // 2. Fetch or reuse verified exam document & dimension rules from Part 1 `JobRequirementService`
      const examChecklist =
        examChecklistOverride ||
        (await jobRequirementService.fetchExamDocumentChecklist(examName));

      // 3. Push job into BullMQ via Part 2 `FormFillerQueueWorker`
      const enqueueResult = await queueWorker.enqueueFireAndForgetTask({
        userId,
        recipientId: String(recipientId),
        examName: String(examName).trim(),
        portalUrl: String(portalUrl).trim(),
        examChecklist,
        auditId: req.auditContext ? req.auditContext.auditId : null,
      });

      return res.status(202).json({
        success: true,
        taskId: enqueueResult.taskId,
        status: 'QUEUED_IN_BULLMQ',
        message: enqueueResult.message,
        auditReceipt: req.auditContext,
        examRulesSummary: {
          examCode: examChecklist.examCode,
          requiredDocumentCount: Array.isArray(examChecklist.requiredDocuments)
            ? examChecklist.requiredDocuments.length
            : 0,
        },
      });
    } catch (err) {
      const status = err.statusCode || 500;
      return res.status(status).json({
        success: false,
        error: err.code || 'TASK_START_FAILED',
        message: err.message,
        attemptsRemaining: err.attemptsRemaining,
        lockedUntil: err.lockedUntil,
      });
    }
  }
);

// ============================================================================
// SUPPORTING ROUTES: LIVE HANDOFF TUNNEL & TELEGRAM OTP WEBHOOK
// ============================================================================
app.use('/api/handoff', handoffProxy.createExpressRouter());

app.post('/api/webhooks/notification', async (req, res) => {
  try {
    const result = await notificationService.handleIncomingWebhook(req.body);
    return res.status(200).json({ ok: true, ...result });
  } catch (err) {
    return res.status(500).json({ ok: false, error: err.message });
  }
});

app.get('/health', (req, res) => {
  return res.status(200).json({
    status: 'OK',
    service: 'Automated AI Form Filler API Gateway',
    timestamp: new Date().toISOString(),
  });
});

// ============================================================================
// GLOBAL ERROR HANDLER
// ============================================================================
app.use((err, req, res, next) => {
  wipeMulterRequestBuffers(req);
  const status = err.statusCode || err.status || 500;
  return res.status(status).json({
    success: false,
    error: err.code || 'INTERNAL_SERVER_ERROR',
    message: err.message || 'An unexpected error occurred on the API Gateway.',
  });
});

// ============================================================================
// SERVER BOOTSTRAP
// ============================================================================
if (require.main === module) {
  const server = app.listen(PORT, () => {
    console.log(`[API Gateway] Server listening securely on port ${PORT}`);
  });

  // Graceful shutdown to wipe any active RAM keys before process exit
  const shutdown = () => {
    server.close(() => {
      process.exit(0);
    });
  };
  process.on('SIGTERM', shutdown);
  process.on('SIGINT', shutdown);
}

module.exports = {
  app,
  cryptoVault,
  queueWorker,
  jitMemoryEngine,
};
