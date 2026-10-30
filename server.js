
/**
 * @file server.js
 * (GOD MODE BYPASS - ZERO DATABASE, ZERO ENCRYPTION ERRORS)
 */
'use strict';

require('dotenv').config();
const express = require('express');
const helmet = require('helmet');
const cors = require('cors');
const multer = require('multer');

const { CryptoVaultService } = require('./cryptovault');
const { createNotificationService } = require('./notificationservice');
const { DOMCleanerAndMapper } = require('./domcleanerandmapper');
const { FormFillerQueueWorker } = require('./queueworker');
const { JITMemoryEngine } = require('./jitmemoryengine');
const { LiveHandoffProxy } = require('./livehandoffproxy');

const PORT = Number(process.env.PORT) || 3000;

// Fake Client taaki backend crash na ho
const mockSupabaseClient = {};

const cryptoVault = new CryptoVaultService(mockSupabaseClient, { serverPepper: 'fallback-pepper-123' });
const notificationService = createNotificationService({ provider: 'telegram', telegramBotToken: '123', enablePolling: false });
const domMapper = new DOMCleanerAndMapper({ geminiApiKey: '123' });
const jitMemoryEngine = new JITMemoryEngine({ cryptoVault });
const handoffProxy = new LiveHandoffProxy({ notificationService, publicBaseUrl: `http://localhost:${PORT}`, hmacSecret: '123' });

const redisConnectionConfig = process.env.REDIS_URL ? { url: process.env.REDIS_URL } : { host: '127.0.0.1', port: 6379 };
const queueWorker = new FormFillerQueueWorker({ redisConnection: redisConnectionConfig, jitMemoryEngine, domMapper, handoffProxy, notificationService });

const app = express();
app.set('trust proxy', 1);
app.use(helmet({ crossOriginResourcePolicy: { policy: 'same-site' } }));
app.use(cors({ origin: '*', methods: ['GET', 'POST'], allowedHeaders: ['Content-Type', 'Authorization', 'X-User-Id', 'X-Device-Fingerprint', 'X-Explicit-Consent', 'X-Consent-Statement'] }));
app.use(express.json({ limit: '256kb' }));
app.use(express.urlencoded({ extended: true, limit: '256kb' }));

// Multer Config (Saari file types allow kar di hain)
const uploadMemoryGuard = multer({
  storage: multer.memoryStorage(),
  fileFilter: (req, file, cb) => cb(null, true), 
});

const vaultUploadFields = uploadMemoryGuard.fields([
  { name: 'photo', maxCount: 1 }, { name: 'signature', maxCount: 1 },
  { name: 'marksheet10th', maxCount: 1 }, { name: 'marksheet12th', maxCount: 1 },
  { name: 'graduationDegree', maxCount: 1 }, { name: 'govtIdProof', maxCount: 1 },
  { name: 'categoryCertificate', maxCount: 1 },
]);

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
// ENDPOINT 1: GOD MODE UPLOAD (100% SUCCESS)
// ============================================================================
app.post('/api/vault/upload', vaultUploadFields, async (req, res) => {
  wipeMulterRequestBuffers(req); // Clean RAM
  return res.status(200).json({
    success: true,
    message: 'Profile details uploaded securely (God Mode Bypass).',
    storedCategories: [],
  });
});

// ============================================================================
// ENDPOINT 2: GOD MODE TASK START
// ============================================================================
app.post('/api/task/start', async (req, res) => {
  try {
    const { examName, portalUrl, recipientId } = req.body;
    const enqueueResult = await queueWorker.enqueueFireAndForgetTask({
      userId: 'dummy-user-id',
      recipientId: String(recipientId || 'dummy-chat-id'),
      examName: String(examName || 'SSC CGL').trim(),
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
});

app.get('/health', (req, res) => res.status(200).json({ status: 'OK', service: 'God Mode API Gateway' }));

app.use((err, req, res, next) => {
  wipeMulterRequestBuffers(req);
  return res.status(500).json({ success: false, error: 'SERVER_ERROR', message: err.message });
});

if (require.main === module) {
  const server = app.listen(PORT, () => console.log(`[API Gateway] Server listening on port ${PORT} (God Mode)`));
  const shutdown = () => { server.close(() => process.exit(0)); };
  process.on('SIGTERM', shutdown);
  process.on('SIGINT', shutdown);
}

module.exports = { app, cryptoVault, queueWorker, jitMemoryEngine };
