/**
 * @file CryptoVault.js
 * @description 4-Layer Master PIN Security & Persistent AES-256-GCM Encrypted Vault.
 *
 * Security Architecture:
 *  1. Zero-PIN Persistence: The 4-digit Master PIN is NEVER stored in PostgreSQL or logs.
 *  2. Key Stretching (Argon2id + PBKDF2 Fallback): Stretches 4-digit PIN + Per-User 256-bit Salt
 *     + Server Pepper into a 256-bit (32-byte) cryptographic key inside volatile Server RAM.
 *  3. Ephemeral RAM Key Cache: Derived keys live strictly in an isolated in-memory Map with
 *     automatic TTL zeroization (`Buffer.fill(0)`) so keys never touch disk/swap.
 *  4. Brute-Force Lockout: 5 consecutive failed PIN attempts lock the user's vault for 24 hours.
 */

'use strict';

const crypto = require('crypto');

// Optional native Argon2 binding with automatic Node.js native crypto.scrypt / PBKDF2 fallback
// so the module runs out-of-the-box in any Node.js >=18 environment.
let argon2 = null;
try {
  argon2 = require('argon2');
} catch (_) {
  argon2 = null;
}

const VAULT_CANARY_PLAINTEXT = 'AUTOMATED_AI_FORM_FILLER_VAULT_OK_V1';
const MAX_PIN_ATTEMPTS = 5;
const LOCKOUT_DURATION_MS = 24 * 60 * 60 * 1000; // 24 Hours in milliseconds
const DEFAULT_RAM_KEY_TTL_MS = Number(process.env.RAM_KEY_TTL_MS) || 5 * 60 * 1000; // 5 Minutes

class CryptoVaultService {
  /**
   * @param {import('@supabase/supabase-js').SupabaseClient} supabaseClient - Service-role Supabase client
   * @param {Object} [options]
   * @param {string} [options.serverPepper] - High-entropy server-side secret pepper
   * @param {number} [options.ramKeyTtlMs] - Duration (ms) to keep stretched key in Server RAM
   */
  constructor(supabaseClient, options = {}) {
    if (!supabaseClient) {
      throw new Error('CryptoVaultService requires a valid Supabase service-role client instance.');
    }

    this.supabase = supabaseClient;
    this.serverPepper = options.serverPepper || process.env.VAULT_SERVER_PEPPER || 'default-dev-pepper-override-in-prod';
    this.ramKeyTtlMs = options.ramKeyTtlMs || DEFAULT_RAM_KEY_TTL_MS;

    /**
     * Volatile Server RAM Key Store:
     * Map<userId, { keyBuffer: Buffer, expiresAt: number, timer: NodeJS.Timeout }>
     */
    this._ramKeyStore = new Map();
  }

  // ==========================================================================
  // LAYER 1: INPUT VALIDATION & VIRTUAL KEYPAD PIN SANITIZATION
  // ==========================================================================

  /**
   * Validates that the incoming PIN is strictly a 4-digit numeric string.
   * @param {string} pin
   */
  _validatePinFormat(pin) {
    if (typeof pin !== 'string' || !/^\d{4}$/.test(pin)) {
      const err = new Error('INVALID_PIN_FORMAT: Master PIN must be strictly a 4-digit numeric string (0000-9999).');
      err.code = 'INVALID_PIN_FORMAT';
      err.statusCode = 400;
      throw err;
    }
  }

  // ==========================================================================
  // LAYER 2: KEY STRETCHING (ARGON2ID / PBKDF2-SHA512 -> 256-BIT KEY IN RAM)
  // ==========================================================================

  /**
   * Stretches a 4-digit PIN + Per-User Salt + Server Pepper into a 32-byte (256-bit) key.
   * Uses Argon2id (64 MB memory cost, 4 iterations, parallelism 2) when `argon2` native
   * addon is installed, or falls back to high-iteration PBKDF2-HMAC-SHA512 (310,000 rounds,
   * OWASP 2024 standard) via Node's built-in `crypto` module.
   *
   * @param {string} pin - 4-digit Master PIN
   * @param {string} userSaltHex - 64-char hex string (32 bytes) unique to the user
   * @returns {Promise<Buffer>} 32-byte (256-bit) raw cryptographic key buffer
   */
  async derive256BitKey(pin, userSaltHex) {
    this._validatePinFormat(pin);

    if (!userSaltHex || typeof userSaltHex !== 'string' || userSaltHex.length < 32) {
      throw new Error('INVALID_USER_SALT: Cryptographic user salt must be at least 16 bytes (32 hex chars).');
    }

    // Bind PIN with Server Pepper via HMAC-SHA256 before feeding into KDF
    const pepperedPinBuffer = crypto
      .createHmac('sha256', Buffer.from(this.serverPepper, 'utf8'))
      .update(pin, 'utf8')
      .digest();

    const saltBuffer = Buffer.from(userSaltHex, 'hex');

    try {
      if (argon2) {
        const rawHash = await argon2.hash(pepperedPinBuffer, {
          type: argon2.argon2id,
          salt: saltBuffer,
          hashLength: 32,       // 256-bit output key
          timeCost: 4,          // 4 iterations
          memoryCost: 65536,    // 64 MB RAM per derivation (blocks GPU cracking of 4-digit PIN)
          parallelism: 2,
          raw: true,
        });
        return Buffer.from(rawHash);
      }

      // Built-in OWASP-compliant PBKDF2-HMAC-SHA512 fallback (310,000 iterations -> 32 bytes)
      return await new Promise((resolve, reject) => {
        crypto.pbkdf2(pepperedPinBuffer, saltBuffer, 310000, 32, 'sha512', (err, derivedKey) => {
          if (err) return reject(err);
          resolve(derivedKey);
        });
      });
    } finally {
      // Immediately zeroize intermediate peppered PIN buffer in RAM
      pepperedPinBuffer.fill(0);
    }
  }

  /**
   * Stores the stretched 256-bit key in volatile Server RAM with an automatic zeroization timer.
   * @param {string} userId
   * @param {Buffer} keyBuffer - 32-byte key buffer
   */
  _cacheKeyInRam(userId, keyBuffer) {
    this.evictKeyFromRam(userId);

    const safeCopy = Buffer.alloc(32);
    keyBuffer.copy(safeCopy);

    const timer = setTimeout(() => {
      this.evictKeyFromRam(userId);
    }, this.ramKeyTtlMs);

    if (typeof timer.unref === 'function') {
      timer.unref();
    }

    this._ramKeyStore.set(userId, {
      keyBuffer: safeCopy,
      expiresAt: Date.now() + this.ramKeyTtlMs,
      timer,
    });
  }

  /**
   * Securely wipes a user's stretched key from Server RAM by overwriting bytes with zeroes.
   * @param {string} userId
   */
  evictKeyFromRam(userId) {
    const existing = this._ramKeyStore.get(userId);
    if (existing) {
      clearTimeout(existing.timer);
      if (Buffer.isBuffer(existing.keyBuffer)) {
        existing.keyBuffer.fill(0); // Cryptographic zeroization
      }
      this._ramKeyStore.delete(userId);
    }
  }

  /**
   * Retrieves an active stretched key from Server RAM if present and unexpired.
   * @param {string} userId
   * @returns {Buffer|null}
   */
  getActiveRamKey(userId) {
    const entry = this._ramKeyStore.get(userId);
    if (!entry) return null;
    if (Date.now() > entry.expiresAt) {
      this.evictKeyFromRam(userId);
      return null;
    }
    return entry.keyBuffer;
  }

  // ==========================================================================
  // LAYER 3: AES-256-GCM AUTHENTICATED ENCRYPTION & DECRYPTION
  // ==========================================================================

  /**
   * Encrypts arbitrary Buffer or UTF-8 string using AES-256-GCM.
   * Generates a fresh 96-bit (12-byte) IV for every single operation.
   *
   * @param {Buffer|string} plaintext - Raw document Buffer or stringified JSON
   * @param {Buffer} keyBuffer - 32-byte key from `derive256BitKey`
   * @param {string} [aadContext=''] - Optional Additional Authenticated Data (e.g., userId:category)
   * @returns {{ ivHex: string, authTagHex: string, ciphertextBase64: string, sha256Checksum: string }}
   */
  encryptAES256GCM(plaintext, keyBuffer, aadContext = '') {
    if (!Buffer.isBuffer(keyBuffer) || keyBuffer.length !== 32) {
      throw new Error('INVALID_KEY_LENGTH: AES-256-GCM requires a 32-byte (256-bit) Buffer key.');
    }

    const inputBuffer = Buffer.isBuffer(plaintext) ? plaintext : Buffer.from(String(plaintext), 'utf8');
    const iv = crypto.randomBytes(12); // 96-bit NIST-recommended IV for GCM
    const cipher = crypto.createCipheriv('aes-256-gcm', keyBuffer, iv);

    if (aadContext) {
      cipher.setAAD(Buffer.from(aadContext, 'utf8'));
    }

    const encrypted = Buffer.concat([cipher.update(inputBuffer), cipher.final()]);
    const authTag = cipher.getAuthTag();
    const sha256Checksum = crypto.createHash('sha256').update(inputBuffer).digest('hex');

    return {
      ivHex: iv.toString('hex'),
      authTagHex: authTag.toString('hex'),
      ciphertextBase64: encrypted.toString('base64'),
      sha256Checksum,
    };
  }

  /**
   * Decrypts an AES-256-GCM payload and verifies both the GCM Auth Tag and SHA-256 checksum.
   *
   * @param {Object} encryptedPayload
   * @param {string} encryptedPayload.ivHex
   * @param {string} encryptedPayload.authTagHex
   * @param {string} encryptedPayload.ciphertextBase64
   * @param {string} [encryptedPayload.sha256Checksum]
   * @param {Buffer} keyBuffer - 32-byte key
   * @param {string} [aadContext=''] - Must match AAD provided during encryption
   * @returns {Buffer} Decrypted raw Buffer
   */
  decryptAES256GCM(encryptedPayload, keyBuffer, aadContext = '') {
    if (!Buffer.isBuffer(keyBuffer) || keyBuffer.length !== 32) {
      throw new Error('INVALID_KEY_LENGTH: AES-256-GCM requires a 32-byte (256-bit) Buffer key.');
    }

    const { ivHex, authTagHex, ciphertextBase64, sha256Checksum } = encryptedPayload;
    const iv = Buffer.from(ivHex, 'hex');
    const authTag = Buffer.from(authTagHex, 'hex');
    const ciphertext = Buffer.from(ciphertextBase64, 'base64');

    const decipher = crypto.createDecipheriv('aes-256-gcm', keyBuffer, iv);
    decipher.setAuthTag(authTag);

    if (aadContext) {
      decipher.setAAD(Buffer.from(aadContext, 'utf8'));
    }

    const decryptedBuffer = Buffer.concat([decipher.update(ciphertext), decipher.final()]);

    if (sha256Checksum) {
      const computedHash = crypto.createHash('sha256').update(decryptedBuffer).digest('hex');
      if (computedHash !== sha256Checksum) {
        throw new Error('INTEGRITY_CHECK_FAILED: Decrypted payload checksum mismatch.');
      }
    }

    return decryptedBuffer;
  }

  // ==========================================================================
  // LAYER 4: MASTER PIN INITIALIZATION, VERIFICATION & 24-HOUR BRUTE-FORCE LOCK
  // ==========================================================================

  /**
   * Initializes a user's Master PIN security profile on first-time vault setup.
   * Generates a unique 32-byte cryptographic salt and encrypts a verification canary.
   *
   * @param {string} userId - Authenticated User UUID
   * @param {string} pin - 4-digit Master PIN from Virtual Keypad
   * @param {Object} [contactInfo] - Optional Telegram Chat ID or WhatsApp Phone
   */
  async initializeMasterPin(userId, pin, contactInfo = {}) {
    this._validatePinFormat(pin);

    const kdfSaltHex = crypto.randomBytes(32).toString('hex');
    const keyBuffer = await this.derive256BitKey(pin, kdfSaltHex);

    try {
      const canary = this.encryptAES256GCM(VAULT_CANARY_PLAINTEXT, keyBuffer, `canary:${userId}`);

      const { error } = await this.supabase.from('user_security_profiles').upsert(
        {
          user_id: userId,
          telegram_chat_id: contactInfo.telegramChatId || null,
          whatsapp_phone: contactInfo.whatsappPhone || null,
          kdf_salt: kdfSaltHex,
          pin_verifier_iv: canary.ivHex,
          pin_verifier_tag: canary.authTagHex,
          pin_verifier_ciphertext: canary.ciphertextBase64,
          failed_pin_attempts: 0,
          locked_until: null,
          last_failed_attempt_at: null,
          updated_at: new Date().toISOString(),
        },
        { onConflict: 'user_id' }
      );

      if (error) {
        throw new Error(`DATABASE_ERROR_INIT_PIN: ${error.message}`);
      }

      // Cache stretched key in Server RAM for immediate session operations
      this._cacheKeyInRam(userId, keyBuffer);

      return {
        initialized: true,
        ramSessionExpiresInMs: this.ramKeyTtlMs,
      };
    } finally {
      keyBuffer.fill(0);
    }
  }

  /**
   * Unlocks the user's vault by verifying the 4-digit PIN and enforces the strict
   * 5-wrong-attempts = 24-hour account lockout rule.
   *
   * @param {string} userId - Authenticated User UUID
   * @param {string} pin - 4-digit Master PIN entered via Virtual Keypad
   * @returns {Promise<{ unlocked: boolean, keyBuffer: Buffer }>}
   */
  async verifyPinAndUnlockVault(userId, pin) {
    this._validatePinFormat(pin);

    const { data: profile, error } = await this.supabase
      .from('user_security_profiles')
      .select('*')
      .eq('user_id', userId)
      .single();

    if (error || !profile) {
      const notFoundErr = new Error('SECURITY_PROFILE_NOT_FOUND: Please set up your 4-digit Master PIN first.');
      notFoundErr.code = 'SECURITY_PROFILE_NOT_FOUND';
      notFoundErr.statusCode = 404;
      throw notFoundErr;
    }

    // 1. Check if account is currently locked due to brute-force attempts
    const now = new Date();
    if (profile.locked_until && new Date(profile.locked_until) > now) {
      const remainingMinutes = Math.ceil((new Date(profile.locked_until).getTime() - now.getTime()) / 60000);
      const lockErr = new Error(
        `ACCOUNT_LOCKED_BRUTE_FORCE: Vault is locked due to ${MAX_PIN_ATTEMPTS} failed PIN attempts. Try again in ${remainingMinutes} minutes.`
      );
      lockErr.code = 'ACCOUNT_LOCKED_BRUTE_FORCE';
      lockErr.statusCode = 429;
      lockErr.lockedUntil = profile.locked_until;
      throw lockErr;
    }

    // If a previous lock window has expired, reset counter before testing
    let currentFailures = profile.failed_pin_attempts || 0;
    if (profile.locked_until && new Date(profile.locked_until) <= now) {
      currentFailures = 0;
    }

    // 2. Stretch the candidate PIN into a 256-bit key in RAM
    const candidateKey = await this.derive256BitKey(pin, profile.kdf_salt);

    try {
      // 3. Attempt to decrypt the AES-256-GCM verification canary
      const decryptedCanary = this.decryptAES256GCM(
        {
          ivHex: profile.pin_verifier_iv,
          authTagHex: profile.pin_verifier_tag,
          ciphertextBase64: profile.pin_verifier_ciphertext,
        },
        candidateKey,
        `canary:${userId}`
      ).toString('utf8');

      if (decryptedCanary !== VAULT_CANARY_PLAINTEXT) {
        throw new Error('CANARY_MISMATCH');
      }

      // 4. PIN is valid: Reset failed attempts counter if needed
      if (currentFailures > 0 || profile.locked_until) {
        await this.supabase
          .from('user_security_profiles')
          .update({
            failed_pin_attempts: 0,
            locked_until: null,
            updated_at: now.toISOString(),
          })
          .eq('user_id', userId);
      }

      // Cache stretched key in Server RAM and return active reference
      this._cacheKeyInRam(userId, candidateKey);
      return {
        unlocked: true,
        keyBuffer: this.getActiveRamKey(userId),
      };
    } catch (decryptErr) {
      // 5. PIN is WRONG: Increment failure counter and lock for 24h on 5th attempt
      const updatedFailures = currentFailures + 1;
      const shouldLock = updatedFailures >= MAX_PIN_ATTEMPTS;
      const lockedUntilIso = shouldLock
        ? new Date(now.getTime() + LOCKOUT_DURATION_MS).toISOString()
        : null;

      await this.supabase
        .from('user_security_profiles')
        .update({
          failed_pin_attempts: updatedFailures,
          last_failed_attempt_at: now.toISOString(),
          locked_until: lockedUntilIso,
          updated_at: now.toISOString(),
        })
        .eq('user_id', userId);

      this.evictKeyFromRam(userId);

      if (shouldLock) {
        const lockErr = new Error(
          'ACCOUNT_LOCKED_24H: You have entered an incorrect Master PIN 5 times. Your vault is locked for 24 hours.'
        );
        lockErr.code = 'ACCOUNT_LOCKED_24H';
        lockErr.statusCode = 429;
        lockErr.lockedUntil = lockedUntilIso;
        throw lockErr;
      }

      const attemptsRemaining = MAX_PIN_ATTEMPTS - updatedFailures;
      const pinErr = new Error(
        `INVALID_MASTER_PIN: Incorrect PIN entered. ${attemptsRemaining} attempt(s) remaining before a 24-hour security lockout.`
      );
      pinErr.code = 'INVALID_MASTER_PIN';
      pinErr.statusCode = 401;
      pinErr.attemptsRemaining = attemptsRemaining;
      throw pinErr;
    } finally {
      candidateKey.fill(0);
    }
  }

  // ==========================================================================
  // PERSISTENT VAULT STORAGE OPERATIONS (ENCRYPTED UPLOAD & RETRIEVAL)
  // ==========================================================================

  /**
   * Encrypts and stores a user's profile JSON or binary document (Photo, Signature, Marksheet, ID)
   * inside `encrypted_vault_records` using the stretched 256-bit key in Server RAM.
   *
   * @param {Object} params
   * @param {string} params.userId
   * @param {string} [params.pin] - Optional if key is already unlocked in Server RAM
   * @param {string} params.category - e.g. 'PROFILE_BIODATA', 'PHOTO', 'SIGNATURE', 'MARKSHEET_10TH'
   * @param {Buffer|Object|string} params.payload - Raw file Buffer or Biodata JSON object
   * @param {string} [params.mimeType='application/json']
   */
  async storeEncryptedRecord({ userId, pin, category, payload, mimeType = 'application/json' }) {
    let keyBuffer = this.getActiveRamKey(userId);
    if (!keyBuffer) {
      if (!pin) {
        throw new Error('VAULT_LOCKED: Master PIN is required to unlock the vault in Server RAM.');
      }
      const unlockResult = await this.verifyPinAndUnlockVault(userId, pin);
      keyBuffer = unlockResult.keyBuffer;
    }

    const normalizedBuffer = Buffer.isBuffer(payload)
      ? payload
      : Buffer.from(typeof payload === 'string' ? payload : JSON.stringify(payload), 'utf8');

    const aadContext = `${userId}:${category}`;
    const encrypted = this.encryptAES256GCM(normalizedBuffer, keyBuffer, aadContext);

    const { data, error } = await this.supabase
      .from('encrypted_vault_records')
      .upsert(
        {
          user_id: userId,
          record_category: category,
          original_mime_type: mimeType,
          original_size_bytes: normalizedBuffer.length,
          iv_hex: encrypted.ivHex,
          auth_tag_hex: encrypted.authTagHex,
          ciphertext_base64: encrypted.ciphertextBase64,
          sha256_checksum: encrypted.sha256Checksum,
          updated_at: new Date().toISOString(),
        },
        { onConflict: 'user_id,record_category' }
      )
      .select('record_id, record_category, original_mime_type, original_size_bytes, sha256_checksum, updated_at')
      .single();

    if (error) {
      throw new Error(`VAULT_WRITE_FAILED: ${error.message}`);
    }

    return data;
  }

  /**
   * Retrieves and decrypts a stored vault record into Server RAM for automated form filling.
   *
   * @param {Object} params
   * @param {string} params.userId
   * @param {string} [params.pin] - Optional if key is already unlocked in Server RAM
   * @param {string} params.category - e.g. 'PROFILE_BIODATA', 'PHOTO', 'SIGNATURE'
   * @returns {Promise<{ category: string, mimeType: string, data: Buffer|Object }>}
   */
  async retrieveDecryptedRecord({ userId, pin, category }) {
    let keyBuffer = this.getActiveRamKey(userId);
    if (!keyBuffer) {
      if (!pin) {
        throw new Error('VAULT_LOCKED: Master PIN is required to decrypt vault records.');
      }
      const unlockResult = await this.verifyPinAndUnlockVault(userId, pin);
      keyBuffer = unlockResult.keyBuffer;
    }

    const { data: record, error } = await this.supabase
      .from('encrypted_vault_records')
      .select('*')
      .eq('user_id', userId)
      .eq('record_category', category)
      .single();

    if (error || !record) {
      throw new Error(`VAULT_RECORD_NOT_FOUND: No encrypted record found for category "${category}".`);
    }

    const aadContext = `${userId}:${category}`;
    const decryptedBuffer = this.decryptAES256GCM(
      {
        ivHex: record.iv_hex,
        authTagHex: record.auth_tag_hex,
        ciphertextBase64: record.ciphertext_base64,
        sha256Checksum: record.sha256_checksum,
      },
      keyBuffer,
      aadContext
    );

    const parsedData =
      record.original_mime_type === 'application/json'
        ? JSON.parse(decryptedBuffer.toString('utf8'))
        : decryptedBuffer;

    return {
      recordId: record.record_id,
      category: record.record_category,
      mimeType: record.original_mime_type,
      sizeBytes: record.original_size_bytes,
      data: parsedData,
    };
  }
}

module.exports = {
  CryptoVaultService,
  VAULT_CANARY_PLAINTEXT,
  MAX_PIN_ATTEMPTS,
  LOCKOUT_DURATION_MS,
};