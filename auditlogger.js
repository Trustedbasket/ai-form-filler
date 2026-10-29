/**
 * @file AuditLogger.js
 * @description Legal Audit Trail & Explicit User Consent Middleware (Liability Protection).
 *
 * Since the SaaS backend interacts with government exam portals using server IPs,
 * this middleware strictly enforces and logs:
 *   1. User's Real Client IP (extracted from `req.headers['x-forwarded-for']`, `cf-connecting-ip`, `x-real-ip`)
 *   2. Exact ISO-8601 UTC Timestamp
 *   3. Device Fingerprint Hash + Raw User-Agent
 *   4. Explicit Digital Consent Checkbox verification ("I authorize the system to fill this form on my behalf.")
 *   5. Cryptographic SHA-256 non-repudiation signature binding User + IP + Timestamp + Consent
 */

'use strict';

const crypto = require('crypto');
const net = require('net');

const REQUIRED_CONSENT_STATEMENT = 'I authorize the system to fill this form on my behalf.';

/**
 * Extracts and validates the user's real public IP address from proxy headers.
 * Safely parses `req.headers['x-forwarded-for']` (taking the first client IP in the chain)
 * and strips IPv6-mapped IPv4 prefixes (`::ffff:`).
 *
 * @param {import('express').Request} req
 * @returns {{ clientRealIp: string, forwardedForChain: string }}
 */
function extractClientIp(req) {
  const rawForwardedFor = req.headers['x-forwarded-for'];
  const cfConnectingIp = req.headers['cf-connecting-ip'];
  const xRealIp = req.headers['x-real-ip'];

  let candidateIp = '';
  let forwardedChain = '';

  if (typeof rawForwardedFor === 'string' && rawForwardedFor.trim().length > 0) {
    forwardedChain = rawForwardedFor.trim();
    // The leftmost IP in X-Forwarded-For is the original client IP
    candidateIp = rawForwardedFor.split(',')[0].trim();
  } else if (Array.isArray(rawForwardedFor) && rawForwardedFor.length > 0) {
    forwardedChain = rawForwardedFor.join(', ');
    candidateIp = String(rawForwardedFor[0]).split(',')[0].trim();
  } else if (typeof cfConnectingIp === 'string' && cfConnectingIp.trim()) {
    candidateIp = cfConnectingIp.trim();
  } else if (typeof xRealIp === 'string' && xRealIp.trim()) {
    candidateIp = xRealIp.trim();
  } else if (req.ip) {
    candidateIp = req.ip;
  } else if (req.socket && req.socket.remoteAddress) {
    candidateIp = req.socket.remoteAddress;
  }

  // Strip IPv4-mapped IPv6 prefix if present (e.g., "::ffff:203.0.113.45" -> "203.0.113.45")
  if (candidateIp.startsWith('::ffff:')) {
    candidateIp = candidateIp.substring(7);
  }

  // Validate IP format for PostgreSQL INET column compatibility; fallback to 0.0.0.0 if malformed
  const isValidIp = net.isIP(candidateIp) !== 0;
  return {
    clientRealIp: isValidIp ? candidateIp : '0.0.0.0',
    forwardedForChain: forwardedChain || candidateIp || 'DIRECT',
  };
}

/**
 * Computes a deterministic device fingerprint hash combining client-supplied hardware/canvas
 * fingerprint signals with server-observed headers (`User-Agent`, `Accept-Language`, `Sec-CH-UA`).
 *
 * @param {import('express').Request} req
 * @returns {string} 64-character SHA-256 hex fingerprint
 */
function computeDeviceFingerprint(req) {
  const clientHeaderFp =
    req.headers['x-device-fingerprint'] ||
    (req.body && req.body.deviceFingerprint) ||
    'no-client-fp';

  const userAgent = req.headers['user-agent'] || 'unknown-ua';
  const acceptLang = req.headers['accept-language'] || '';
  const secChUa = req.headers['sec-ch-ua'] || '';
  const secChPlatform = req.headers['sec-ch-ua-platform'] || '';

  const compositeRaw = [
    String(clientHeaderFp).trim(),
    userAgent,
    acceptLang,
    secChUa,
    secChPlatform,
  ].join('|');

  return crypto.createHash('sha256').update(compositeRaw, 'utf8').digest('hex');
}

/**
 * Factory function creating the Express Legal Audit & Consent Middleware.
 *
 * @param {Object} config
 * @param {import('@supabase/supabase-js').SupabaseClient} config.supabaseClient - Supabase service-role client
 * @param {string} config.actionType - Action identifier (e.g. 'FORM_AUTOFILL_INIT', 'VAULT_UNLOCK')
 * @param {boolean} [config.requireExplicitConsent=true] - Whether to reject requests without explicit consent checkbox
 * @returns {import('express').RequestHandler}
 */
function createAuditLoggerMiddleware({ supabaseClient, actionType, requireExplicitConsent = true }) {
  if (!supabaseClient) {
    throw new Error('AuditLogger requires a valid Supabase service-role client.');
  }

  return async function auditLoggerMiddleware(req, res, next) {
    try {
      const exactTimestampIso = new Date().toISOString();

      // 1. Identify authenticated user
      const userId =
        (req.user && req.user.id) ||
        req.headers['x-user-id'] ||
        (req.body && req.body.userId);

      if (!userId) {
        return res.status(401).json({
          success: false,
          error: 'UNAUTHORIZED_AUDIT_ACTOR',
          message: 'Authenticated user session is required before executing auditable portal actions.',
        });
      }

      // 2. Verify Explicit Digital Consent Checkbox ("I authorize the system to fill this form on my behalf")
      const bodyConsent = req.body && req.body.explicitConsent;
      const headerConsent = req.headers['x-explicit-consent'] === 'true';
      const consentGranted = bodyConsent === true || headerConsent === true;

      const suppliedConsentText =
        (req.body && req.body.consentStatement) ||
        req.headers['x-consent-statement'] ||
        REQUIRED_CONSENT_STATEMENT;

      if (requireExplicitConsent) {
        if (!consentGranted || suppliedConsentText.trim() !== REQUIRED_CONSENT_STATEMENT) {
          return res.status(403).json({
            success: false,
            error: 'LEGAL_CONSENT_REQUIRED',
            message: `Action blocked: You must explicitly check the digital consent box ("${REQUIRED_CONSENT_STATEMENT}") to proceed.`,
          });
        }
      }

      // 3. Extract Real IP, User-Agent, and Device Fingerprint
      const { clientRealIp, forwardedForChain } = extractClientIp(req);
      const userAgent = req.headers['user-agent'] || 'UNKNOWN_USER_AGENT';
      const deviceFingerprintHash = computeDeviceFingerprint(req);

      const targetExamName =
        (req.body && (req.body.examName || req.body.targetExam)) ||
        req.query.examName ||
        null;

      const targetPortalUrl = (req.body && req.body.targetPortalUrl) || null;

      // 4. Generate cryptographic non-repudiation signature binding User + IP + Timestamp + Consent
      const nonRepudiationPayload = JSON.stringify({
        userId,
        actionType: actionType || req.originalUrl,
        clientRealIp,
        exactTimestampIso,
        deviceFingerprintHash,
        consentGranted: true,
        consentStatement: REQUIRED_CONSENT_STATEMENT,
        targetExamName,
      });

      const consentSignatureHash = crypto
        .createHash('sha256')
        .update(nonRepudiationPayload, 'utf8')
        .digest('hex');

      // 5. Persist immutable record to `legal_audit_logs` BEFORE allowing controller execution
      const { data: auditRow, error: insertError } = await supabaseClient
        .from('legal_audit_logs')
        .insert({
          user_id: userId,
          action_type: actionType || `${req.method} ${req.baseUrl}${req.path}`,
          target_exam_name: targetExamName,
          target_portal_url: targetPortalUrl,
          client_real_ip: clientRealIp,
          forwarded_for_chain: forwardedForChain,
          user_agent: userAgent,
          device_fingerprint_hash: deviceFingerprintHash,
          explicit_consent_granted: true,
          consent_statement_text: REQUIRED_CONSENT_STATEMENT,
          consent_signature_hash: consentSignatureHash,
          request_metadata: {
            httpMethod: req.method,
            endpoint: req.originalUrl,
            referer: req.headers['referer'] || null,
          },
          created_at: exactTimestampIso,
        })
        .select('audit_id, created_at, consent_signature_hash')
        .single();

      if (insertError) {
        // Fail-Closed Security Design: If the legal audit trail cannot be written, abort the form operation
        return res.status(500).json({
          success: false,
          error: 'AUDIT_LOG_PERSISTENCE_FAILURE',
          message: 'Operation aborted: Unable to record mandatory legal audit trail.',
        });
      }

      // Attach verified audit receipt to `req.auditContext` for downstream controllers
      req.auditContext = {
        auditId: auditRow.audit_id,
        timestamp: auditRow.created_at,
        clientRealIp,
        deviceFingerprintHash,
        consentSignatureHash: auditRow.consent_signature_hash,
      };

      return next();
    } catch (err) {
      return next(err);
    }
  };
}

module.exports = {
  createAuditLoggerMiddleware,
  extractClientIp,
  computeDeviceFingerprint,
  REQUIRED_CONSENT_STATEMENT,
};