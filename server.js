/**
 * @file server.js
 * @description PART 3: Enterprise API Gateway & Security Perimeter for "Automated AI Form Filler".
 * (MODIFIED: Database operations completely bypassed for direct execution)
 */

'use strict';

require('dotenv').config();

const express = require('express');
const helmet = require('helmet');
const cors = require('cors');
const rateLimit = require('express-rate-limit');
const multer = require('multer');
// BYPASS: Supabase hata diya
// const { createClient } = require('@supabase/supabase-js');

// ============================================================================
// PART 1 & PART 2 MODULE IMPORTS
// ============================================================================
const { CryptoVaultService } = require('./cryptovault');
// BYPASS: Audit logger ko hata diya
// const { createAuditLoggerMiddleware, extractClientIp } = require('./auditlogger');
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
const MAX_UPLOAD_FILE_SIZE_BYTES = 5 * 1024 * 1024;
const MAX_UPLOAD_FILES_COUNT = 6;
const ALLOWED_UPLOAD_MIMES = new Set(['image/jpeg', 'image/jpg', 'image/png', 'application/pdf']);

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
// INITIALIZE CORE SERVICES (Mocked DB)
// ============================================================================
// BYPASS: Fake client bana diya taaki modules crash na hon
const mockSupabaseClient = {
  from: () => ({
    insert: async () => ({ data: [], error: null }),
    select: () => ({ eq: async () => ({ data: [], error: null }) }),
  }),
};

const cryptoVault = new CryptoVaultService(mockSupabaseClient, {
  serverPepper: process.env.VAULT_SERVER_PEPPER || 'fallback-pepper-123',
  ramKeyTtlMs: Number(process.env.RAM_KEY_TTL_MS) || 5 * 60 * 1000,
});

const notificationService = createNotificationService({
  provider: process.env.NOTIFICATION_PROVIDER || 'telegram',
  telegramBotToken: process.env.TELEGRAM_BOT_TOKEN || '000000000:DEV_PLACEHOLDER_TOKEN',
  enablePolling: false, // Turned off for quick test
});

const jobRequirementService = new JobRequirementService({
  geminiApiKey: process.env.GEMINI_API_KEY || 'DEV_GEMINI_KEY_PLACEHOLDER',
  supabaseClient: mockSupabaseClient,
});

const domMapper = new DOMCleanerAndMapper({
  geminiApiKey: process.env.GEMINI_API_KEY || 'DEV_GEMINI_KEY_PLACEHOLDER',
});

const jitMemoryEngine = new JITMemoryEngine({ cryptoVault });

const handoffProxy = new LiveHandoffProxy({
  notificationService,
  publicBaseUrl: process.env.FRONTEND_ORIGIN || `http://localhost:${PORT}`,
  hmacSecret: process.env.VAULT_SERVER_PEPPER || 'fallback-pepper-123',
});

// Redis is still needed for BullMQ Queue (Render par free Upstash chalu rehna chahiye)
const redisConnectionConfig = process.env.REDIS_URL
  ? { url: process.env.REDIS_URL }
  : { host: '127.0.0.1', port: 6379 };

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
app.set('trust proxy', 1);
app.use(helmet({ crossOriginResourcePolicy: { policy: 'same-site' } }));

app.use(
  cors({
    origin: '*', // BYPASS: Sab kuch allow kar diya
    methods: ['GET', 'POST'],
    allowedHeaders: ['Content-Type', 'Authorization', 'X-User-Id', 'X-Device-Fingerprint', 'X-Explicit-Consent', 'X-Consent-Statement'],
  })
);

app.use(express.json({ limit: '256kb' }));
app.use(express.urlencoded({ extended: true, limit: '256kb' }));

// Helper function to extract IP (since AuditLogger is bypassed)
function getClientIp(req) {
  return req.headers['x-forwarded-for'] || req.connection.remoteAddress || 'unknown';
}

const strictSubmissionRateLimiter = rateLimit({
  windowMs: 60 * 1000,
  max: 50, // Relaxed rate limit for testing
  keyGenerator: (req) => getClientIp(req),
});

const generalApiRateLimiter = rateLimit({
  windowMs: 60 * 1000,
  max: 600,
  keyGenerator: (req) => getClientIp(req),
});
app.use('/api', generalApiRateLimiter);

// ============================================================================
// RAM CRASH / MEMORY BOMB PROTECTION (`multer`)
// ============================================================================
const uploadMemoryGuard = multer({
  storage: multer.memoryStorage(),
  limits: { fileSize: MAX_UPLOAD_FILE_SIZE_BYTES, files: MAX_UPLOAD_FILES_COUNT, fieldSize: 128 * 1024 },
  fileFilter: (req, file, cb) => {
    if (!UPLOAD_FIELD_TO_CATEGORY[file.fieldname]) return cb(null, false);
    if (!ALLOWED_UPLOAD_MIMES.has(file.mimetype.toLowerCase())) return cb(null, false);
    return cb(null, true);
  },
});

const vaultUploadFields = uploadMemoryGuard.fields([
  { name: 'photo', maxCount: 1 }, { name: 'signature', maxCount: 1 },
  { name: 'marksheet10th', maxCount: 1 }, { name: 'marksheet12th', maxCount: 1 },
  { name: 'graduationDegree', maxCount: 1 }, { name: 'govtIdProof', maxCount: 1 },
  { name: 'categoryCertificate', maxCount: 1 },
]);

function enforceStrict5MbUploadMiddleware(req, res, next) {
  vaultUploadFields(req, res, (err) => {
    if (!err) return next();
    wipeMulterRequestBuffers(req);
    return res.status(400).json({ success: false, error: 'UPLOAD_ERROR', message: err.message });
  });
}

function wipeMulterRequestBuffers(req) {
  if (!req || !req.files || typeof req.files !== 'object') return;
  for (const fileArray of Object.values(req.files)) {
    if (Array.isArray(fileArray)) {
      for (const fileObj of fileArray) {
        if (fileObj && Buffer.isBuffer(fileObj.buffer)) fileObj.buffer.fill(0);
      }
    }
  }
}

// ============================================================================
// ENDPOINT 1: POST /api/vault/upload (BYPASSED DB SAVING)
// ============================================================================
app.post(
  '/api/vault/upload',
  strictSubmissionRateLimiter,
  enforceStrict5MbUploadMiddleware,
  // auditVaultUpload, // BYPASS
  async (req, res) => {
    try {
      const userId = (req.user && req.user.id) || req.headers['x-user-id'] || req.body.userId || 'dummy-user-id';
      const { masterPin } = req.body;

      if (!masterPin) throw new Error('Master PIN required');

      // RAM Key cache
      await cryptoVault.initializeMasterPin(userId, String(masterPin), { telegramChatId: '123' });

      const savedRecords = [];

      // BYPASS: Direct push for profile
      if (req.body.profileBiodata) {
        savedRecords.push({ recordId: 'mock-1', category: 'PROFILE_BIODATA', sizeBytes: 100, sha256Checksum: 'mock' });
      }

      // BYPASS: Clear buffers without saving to DB
      if (req.files && typeof req.files === 'object') {
        for (const [fieldName, fileArray] of Object.entries(req.files)) {
          const fileObj = Array.isArray(fileArray) ? fileArray[0] : null;
          if (fileObj && Buffer.isBuffer(fileObj.buffer)) {
            savedRecords.push({ recordId: 'mock-2', category: UPLOAD_FIELD_TO_CATEGORY[fieldName], sizeBytes: fileObj.buffer.length, sha256Checksum: 'mock' });
            fileObj.buffer.fill(0); // Zeroize
          }
        }
      }

      return res.status(200).json({
        success: true,
        message: 'Profile details uploaded securely (DB Bypassed).',
        storedCategories: savedRecords,
      });
    } catch (err) {
      return res.status(500).json({ success: false, error: 'VAULT_ERROR', message: err.message });
    } finally {
      wipeMulterRequestBuffers(req);
    }
  }
);

// ============================================================================
// ENDPOINT 2: POST /api/task/start (BYPASSED DB SAVING)
// ============================================================================
app.post(
  '/api/task/start',
  strictSubmissionRateLimiter,
  // auditTaskStart, // BYPASS
  async (req, res) => {
    try {
      const userId = (req.user && req.user.id) || req.headers['x-user-id'] || req.body.userId || 'dummy-user-id';
      const { masterPin, examName, portalUrl, recipientId } = req.body;

      if (!masterPin || !examName) throw new Error('Master PIN and Exam Name required');

      // Push dummy job to BullMQ queue directly
      const enqueueResult = await queueWorker.enqueueFireAndForgetTask({
        userId,
        recipientId: String(recipientId || 'dummy-chat-id'),
        examName: String(examName).trim(),
        portalUrl: String(portalUrl || 'https://ssc.nic.in').trim(),
        examChecklist: { examCode: 'MOCK_EXAM', requiredDocuments: [] },
        auditId: null,
      });

      return res.status(202).json({
        success: true,
        taskId: enqueueResult.taskId,
        status: 'QUEUED_IN_BULLMQ',
        message: enqueueResult.message || 'Task started successfully.',
      });
    } catch (err) {
      return res.status(500).json({ success: false, error: 'TASK_ERROR', message: err.message });
    }
  }
);

// ============================================================================
// SUPPORTING ROUTES
// ============================================================================
app.use('/api/handoff', handoffProxy.createExpressRouter());

app.get('/health', (req, res) => {
  return res.status(200).json({ status: 'OK', service: 'Automated AI Form Filler (Direct RAM Mode)' });
});

app.use((err, req, res, next) => {
  wipeMulterRequestBuffers(req);
  return res.status(500).json({ success: false, error: 'SERVER_ERROR', message: err.message });
});

// ============================================================================
// SERVER BOOTSTRAP
// ============================================================================
if (require.main === module) {
  const server = app.listen(PORT, () => {
    console.log(`[API Gateway] Server listening on port ${PORT} (Database Bypassed)`);
  });

  const shutdown = () => { server.close(() => { process.exit(0); }); };
  process.on('SIGTERM', shutdown);
  process.on('SIGINT', shutdown);
}

module.exports = { app, cryptoVault, queueWorker, jitMemoryEngine };
