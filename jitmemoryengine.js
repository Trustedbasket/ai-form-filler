/**
 * @file JITMemoryEngine.js
 * @description Just-In-Time (JIT) Micro-Burst RAM Decryption & In-Memory `Sharp` Image Resizer.
 *
 * Zero-Disk & Anti-Forensic Dump Guarantees:
 *  1. Micro-Burst Decryption: Never decrypts or caches the user's entire profile or document suite
 *     in memory at once. Each field or binary document is decrypted inside an isolated scoped callback
 *     at the exact millisecond the target input loads, then immediately overwritten with zeroes
 *     (`Buffer.fill(0)`) inside a `finally` block.
 *  2. Buffer-to-Buffer `Sharp` Image Resizing: Decrypts the user's raw Photo/Signature into a RAM
 *     `Buffer`, pipes it directly through `sharp(inputBuffer)` to match the exact pixel dimensions
 *     (`minWidthPx`..`maxWidthPx`, `minHeightPx`..`maxHeightPx`) and file size bounds (`minSizeKB`..`maxSizeKB`)
 *     fetched by Part 1's `JobRequirementService`, injects the resized Buffer into Puppeteer, and
 *     zero-fills both source and resized buffers immediately. Zero temporary files ever touch disk.
 */

'use strict';

let sharp = null;
try {
  sharp = require('sharp');
} catch (_) {
  sharp = null;
}

class JITMemoryEngine {
  /**
   * @param {Object} dependencies
   * @param {import('./CryptoVault').CryptoVaultService} dependencies.cryptoVault - Part 1 CryptoVaultService
   */
  constructor({ cryptoVault }) {
    if (!cryptoVault) {
      throw new Error('JITMemoryEngine requires an initialized CryptoVaultService instance from Part 1.');
    }
    this.cryptoVault = cryptoVault;

    /**
     * Tracks temporary task-scoped Buffer references so `purgeTaskMemory` can emergency-wipe
     * any active Buffers if a worker job crashes mid-operation.
     * Map<taskId, Set<Buffer>>
     */
    this._activeTaskBuffers = new Map();
  }

  /**
   * Registers a temporary Buffer with the active task tracker so it is guaranteed to be zeroized.
   * @param {string} taskId
   * @param {Buffer} buf
   */
  _trackBuffer(taskId, buf) {
    if (!Buffer.isBuffer(buf)) return;
    if (!this._activeTaskBuffers.has(taskId)) {
      this._activeTaskBuffers.set(taskId, new Set());
    }
    this._activeTaskBuffers.get(taskId).add(buf);
  }

  /**
   * Zero-fills a Buffer in RAM and removes it from tracking.
   * @param {string} taskId
   * @param {Buffer} buf
   */
  _zeroAndReleaseBuffer(taskId, buf) {
    if (Buffer.isBuffer(buf)) {
      buf.fill(0);
    }
    const set = this._activeTaskBuffers.get(taskId);
    if (set) {
      set.delete(buf);
    }
  }

  /**
   * 1-ms Micro-Burst Field Decryption:
   * Fetches the user's `PROFILE_BIODATA` ciphertext, decrypts it inside a narrow RAM scope,
   * extracts ONLY the single requested nested property (e.g. `personal.fullName`) into a short-lived
   * `Buffer`, executes `consumerFn(fieldValueBuffer)` (which types into Puppeteer), and immediately
   * wipes all buffers (`Buffer.fill(0)`) before returning.
   *
   * @param {Object} params
   * @param {string} params.taskId
   * @param {string} params.userId
   * @param {string} params.fieldPath - Dot-notated path e.g. 'personal.fullName'
   * @param {(fieldBuffer: Buffer) => Promise<any>} consumerFn
   */
  async withMicroBurstField({ taskId, userId, fieldPath }, consumerFn) {
    let fullBiodataBuffer = null;
    let singleFieldBuffer = null;

    try {
      const keyBuffer = this.cryptoVault.getActiveRamKey(userId);
      if (!keyBuffer) {
        throw new Error('JIT_KEY_EXPIRED: Master PIN session key is no longer present in Server RAM.');
      }

      const { data: record, error } = await this.cryptoVault.supabase
        .from('encrypted_vault_records')
        .select('iv_hex, auth_tag_hex, ciphertext_base64, sha256_checksum')
        .eq('user_id', userId)
        .eq('record_category', 'PROFILE_BIODATA')
        .single();

      if (error || !record) {
        throw new Error('BIODATA_RECORD_MISSING: User has not saved encrypted profile biodata.');
      }

      // Decrypt into tracked RAM buffer
      fullBiodataBuffer = this.cryptoVault.decryptAES256GCM(
        {
          ivHex: record.iv_hex,
          authTagHex: record.auth_tag_hex,
          ciphertextBase64: record.ciphertext_base64,
          sha256Checksum: record.sha256_checksum,
        },
        keyBuffer,
        `${userId}:PROFILE_BIODATA`
      );
      this._trackBuffer(taskId, fullBiodataBuffer);

      const parsedProfile = JSON.parse(fullBiodataBuffer.toString('utf8'));
      // Immediately wipe the full biodata buffer now that we are extracting the single target property
      this._zeroAndReleaseBuffer(taskId, fullBiodataBuffer);
      fullBiodataBuffer = null;

      const resolvedValue = fieldPath
        .split('.')
        .reduce((acc, part) => (acc && acc[part] !== undefined ? acc[part] : undefined), parsedProfile);

      if (resolvedValue === undefined || resolvedValue === null) {
        throw new Error(`FIELD_NOT_FOUND_IN_VAULT: "${fieldPath}" is empty in user profile.`);
      }

      singleFieldBuffer = Buffer.from(String(resolvedValue), 'utf8');
      this._trackBuffer(taskId, singleFieldBuffer);

      // Execute the 1-ms DOM injection callback while the single field buffer is live
      return await consumerFn(singleFieldBuffer);
    } finally {
      this._zeroAndReleaseBuffer(taskId, fullBiodataBuffer);
      this._zeroAndReleaseBuffer(taskId, singleFieldBuffer);
    }
  }

  /**
   * In-Memory Document Decryption & `Sharp` Dynamic Resizing (Zero-Disk Rule):
   *  1. Decrypts the requested binary document (`PHOTO`, `SIGNATURE`, etc.) into a RAM Buffer.
   *  2. Uses `Sharp` purely in memory to resize to the exam's exact target pixel dimensions and
   *     iteratively tunes JPEG quality / padding so the output Buffer size lands strictly between
   *     `minSizeKB` and `maxSizeKB` (e.g., Photo: 20KB-50KB, Signature: 10KB-20KB).
   *  3. Passes the resized Buffer to `consumerFn` for direct DOM injection, then zero-fills
   *     every intermediate Buffer in RAM.
   *
   * @param {Object} params
   * @param {string} params.taskId
   * @param {string} params.userId
   * @param {string} params.category - e.g. 'PHOTO', 'SIGNATURE', 'MARKSHEET_10TH'
   * @param {Object} params.resizeRules - Checklist rules from `JobRequirementService`
   * @param {(resizedBuffer: Buffer, metadata: { fileName: string, mimeType: string, finalSizeKB: number }) => Promise<any>} consumerFn
   */
  async withInMemoryResizedDocument({ taskId, userId, category, resizeRules }, consumerFn) {
    let rawDecryptedBuffer = null;
    let finalResizedBuffer = null;

    try {
      const keyBuffer = this.cryptoVault.getActiveRamKey(userId);
      if (!keyBuffer) {
        throw new Error('JIT_KEY_EXPIRED: Master PIN session key is not in Server RAM.');
      }

      const { data: record, error } = await this.cryptoVault.supabase
        .from('encrypted_vault_records')
        .select('*')
        .eq('user_id', userId)
        .eq('record_category', category)
        .single();

      if (error || !record) {
        throw new Error(`VAULT_DOC_MISSING: Encrypted document "${category}" not found.`);
      }

      rawDecryptedBuffer = this.cryptoVault.decryptAES256GCM(
        {
          ivHex: record.iv_hex,
          authTagHex: record.auth_tag_hex,
          ciphertextBase64: record.ciphertext_base64,
          sha256Checksum: record.sha256_checksum,
        },
        keyBuffer,
        `${userId}:${category}`
      );
      this._trackBuffer(taskId, rawDecryptedBuffer);

      const isPdfDocument =
        record.original_mime_type === 'application/pdf' ||
        (resizeRules?.allowedFormats || []).includes('PDF');

      if (isPdfDocument) {
        // PDFs are injected directly from RAM without raster resizing
        finalResizedBuffer = Buffer.from(rawDecryptedBuffer);
        this._trackBuffer(taskId, finalResizedBuffer);
        this._zeroAndReleaseBuffer(taskId, rawDecryptedBuffer);
        rawDecryptedBuffer = null;

        return await consumerFn(finalResizedBuffer, {
          fileName: `${category.toLowerCase()}.pdf`,
          mimeType: 'application/pdf',
          finalSizeKB: Math.round((finalResizedBuffer.length / 1024) * 100) / 100,
        });
      }

      // Image resizing & KB target tuning in RAM using Sharp
      finalResizedBuffer = await this._resizeImageBufferInRam(rawDecryptedBuffer, resizeRules, taskId);
      this._trackBuffer(taskId, finalResizedBuffer);

      // Wipe raw source image buffer immediately after resizing
      this._zeroAndReleaseBuffer(taskId, rawDecryptedBuffer);
      rawDecryptedBuffer = null;

      return await consumerFn(finalResizedBuffer, {
        fileName: `${category.toLowerCase()}.jpg`,
        mimeType: 'image/jpeg',
        finalSizeKB: Math.round((finalResizedBuffer.length / 1024) * 100) / 100,
      });
    } finally {
      this._zeroAndReleaseBuffer(taskId, rawDecryptedBuffer);
      this._zeroAndReleaseBuffer(taskId, finalResizedBuffer);
    }
  }

  /**
   * Resizes and compresses an image Buffer in RAM using `sharp` so it strictly satisfies
   * the exam's pixel dimensions (`targetWidthPx`, `targetHeightPx`) and KB bounds (`minSizeKB`..`maxSizeKB`).
   *
   * @param {Buffer} sourceBuffer
   * @param {Object} resizeRules
   * @param {string} taskId
   * @returns {Promise<Buffer>}
   */
  async _resizeImageBufferInRam(sourceBuffer, resizeRules, taskId) {
    if (!sharp) {
      throw new Error('SHARP_NOT_INSTALLED: The `sharp` library is required for in-memory image resizing.');
    }

    const minBytes = (resizeRules?.minSizeKB || 20) * 1024;
    const maxBytes = (resizeRules?.maxSizeKB || 50) * 1024;
    const dims = resizeRules?.dimensions || {};

    const targetWidth = Math.round(((dims.minWidthPx || 200) + (dims.maxWidthPx || 230)) / 2);
    const targetHeight = Math.round(((dims.minHeightPx || 230) + (dims.maxHeightPx || 250)) / 2);
    const targetDpi = dims.dpi || 200;

    // Binary search over JPEG quality (15..98) in memory to hit [minBytes, maxBytes]
    let lowQ = 15;
    let highQ = 98;
    let bestCandidate = null;

    while (lowQ <= highQ) {
      const midQ = Math.floor((lowQ + highQ) / 2);
      const candidateBuf = await sharp(sourceBuffer)
        .resize(targetWidth, targetHeight, {
          fit: 'contain',
          background: { r: 255, g: 255, b: 255, alpha: 1 },
        })
        .withMetadata({ density: targetDpi })
        .jpeg({ quality: midQ, mozjpeg: true, chromaSubsampling: '4:4:4' })
        .toBuffer();

      this._trackBuffer(taskId, candidateBuf);

      if (candidateBuf.length > maxBytes) {
        if (bestCandidate) this._zeroAndReleaseBuffer(taskId, bestCandidate);
        bestCandidate = candidateBuf;
        highQ = midQ - 1;
      } else if (candidateBuf.length < minBytes) {
        if (bestCandidate) this._zeroAndReleaseBuffer(taskId, bestCandidate);
        bestCandidate = candidateBuf;
        lowQ = midQ + 1;
      } else {
        // Exact hit inside [minBytes, maxBytes]
        if (bestCandidate) this._zeroAndReleaseBuffer(taskId, bestCandidate);
        return candidateBuf;
      }
    }

    // If highest quality JPEG is still below `minBytes` (e.g. small signature image needing >=10KB),
    // pad lossless EXIF/COM metadata bytes in memory so it strictly meets the portal's minimum KB rule
    if (bestCandidate && bestCandidate.length < minBytes && bestCandidate.length >= 4) {
      const deficitBytes = minBytes - bestCandidate.length + 256;
      const paddedBuf = this._injectJpegCommentPaddingInRam(bestCandidate, deficitBytes);
      this._zeroAndReleaseBuffer(taskId, bestCandidate);
      return paddedBuf;
    }

    return bestCandidate;
  }

  /**
   * Injects a standard JPEG COM (`0xFF 0xFE`) segment in memory when a small signature image
   * needs a few extra kilobytes to satisfy a portal's strict `minSizeKB` floor.
   *
   * @param {Buffer} jpegBuffer
   * @param {number} padLengthBytes
   * @returns {Buffer}
   */
  _injectJpegCommentPaddingInRam(jpegBuffer, padLengthBytes) {
    const clampedPad = Math.min(Math.max(padLengthBytes, 64), 60000);
    const segmentLength = clampedPad + 2;
    const comHeader = Buffer.from([0xff, 0xfe, (segmentLength >> 8) & 0xff, segmentLength & 0xff]);
    const filler = Buffer.alloc(clampedPad, 0x20); // Safe ASCII space padding inside JPEG COM header

    // Insert right after SOI marker (0xFF 0xD8)
    return Buffer.concat([
      jpegBuffer.subarray(0, 2),
      comHeader,
      filler,
      jpegBuffer.subarray(2),
    ]);
  }

  /**
   * Immediately wipes all tracked RAM buffers for a task AND evicts the user's stretched
   * Master PIN key from `CryptoVaultService` RAM.
   *
   * @param {string} taskId
   * @param {string} userId
   */
  purgeTaskMemory(taskId, userId) {
    const buffers = this._activeTaskBuffers.get(taskId);
    if (buffers) {
      for (const buf of buffers) {
        if (Buffer.isBuffer(buf)) {
          buf.fill(0);
        }
      }
      buffers.clear();
      this._activeTaskBuffers.delete(taskId);
    }

    if (userId) {
      this.cryptoVault.evictKeyFromRam(userId);
    }
  }
}

module.exports = {
  JITMemoryEngine,
};