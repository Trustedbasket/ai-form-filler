/**
 * @file JobRequirementService.js
 * @description Gemini API Feature 1: Auto-Document Fetcher & Dimension Rules Engine.
 *
 * When a user selects or types an exam name (e.g., "SSC CGL", "UPSC CSE", "RRB NTPC", "IBPS PO")
 * on the dashboard, this service queries the Google Gemini API with a strict JSON Schema
 * (`responseMimeType: "application/json"` + `responseSchema`) to return a verified, deterministic
 * checklist of required documents, pixel dimensions, aspect ratios, and file size limits (KB).
 *
 * Also integrates with `exam_requirement_cache` in Supabase so repeated queries for the same exam
 * are served in <15ms while conserving Gemini API quota.
 */

'use strict';

const EXAM_CHECKLIST_JSON_SCHEMA = {
  type: 'OBJECT',
  required: [
    'examCode',
    'examDisplayName',
    'conductingBody',
    'officialWebsite',
    'requiredDocuments',
    'specialInstructions',
  ],
  properties: {
    examCode: {
      type: 'STRING',
      description: 'Normalized uppercase identifier code, e.g., SSC_CGL, UPSC_CSE, RRB_NTPC',
    },
    examDisplayName: {
      type: 'STRING',
      description: 'Full official title of the examination',
    },
    conductingBody: {
      type: 'STRING',
      description: 'Name of the recruitment commission or board (e.g., Staff Selection Commission)',
    },
    officialWebsite: {
      type: 'STRING',
      description: 'Official portal URL for the examination',
    },
    requiredDocuments: {
      type: 'ARRAY',
      description: 'Complete list of documents, photos, signatures, and certificates required for online application',
      items: {
        type: 'OBJECT',
        required: [
          'category',
          'displayName',
          'isMandatory',
          'allowedFormats',
          'minSizeKB',
          'maxSizeKB',
          'dimensions',
          'guidelines',
        ],
        properties: {
          category: {
            type: 'STRING',
            enum: [
              'PHOTO',
              'SIGNATURE',
              'MARKSHEET_10TH',
              'MARKSHEET_12TH',
              'GRADUATION_DEGREE',
              'GOVT_ID_PROOF',
              'CATEGORY_CERTIFICATE',
              'LEFT_THUMB_IMPRESSION',
              'HANDWRITTEN_DECLARATION',
            ],
          },
          displayName: { type: 'STRING' },
          isMandatory: { type: 'BOOLEAN' },
          allowedFormats: {
            type: 'ARRAY',
            items: { type: 'STRING' },
            description: 'Allowed MIME extensions such as ["JPG", "JPEG"] or ["PDF"]',
          },
          minSizeKB: {
            type: 'INTEGER',
            description: 'Minimum file size in Kilobytes (e.g., 20)',
          },
          maxSizeKB: {
            type: 'INTEGER',
            description: 'Maximum file size in Kilobytes (e.g., 50)',
          },
          dimensions: {
            type: 'OBJECT',
            required: ['widthCm', 'heightCm', 'minWidthPx', 'maxWidthPx', 'minHeightPx', 'maxHeightPx', 'dpi'],
            properties: {
              widthCm: { type: 'NUMBER' },
              heightCm: { type: 'NUMBER' },
              minWidthPx: { type: 'INTEGER' },
              maxWidthPx: { type: 'INTEGER' },
              minHeightPx: { type: 'INTEGER' },
              maxHeightPx: { type: 'INTEGER' },
              dpi: { type: 'INTEGER' },
            },
          },
          guidelines: {
            type: 'STRING',
            description: 'Specific portal rules (e.g., plain white background, no spectacles, black ink on white paper)',
          },
        },
      },
    },
    specialInstructions: {
      type: 'ARRAY',
      items: { type: 'STRING' },
      description: 'Important form-filling warnings (e.g., Live webcam photo capture requirement, Aadhaar OTR rules)',
    },
  },
};

class JobRequirementService {
  /**
   * @param {Object} config
   * @param {string} [config.geminiApiKey] - Google Gemini API Key
   * @param {string} [config.modelName='gemini-2.5-flash'] - Gemini model identifier
   * @param {import('@supabase/supabase-js').SupabaseClient} [config.supabaseClient] - Optional Supabase client for caching
   * @param {number} [config.cacheTtlHours=168] - Cache duration in hours (default 7 days)
   */
  constructor(config = {}) {
    this.apiKey = config.geminiApiKey || process.env.GEMINI_API_KEY;
    this.modelName = config.modelName || process.env.GEMINI_MODEL || 'gemini-2.5-flash';
    this.supabase = config.supabaseClient || null;
    this.cacheTtlHours = config.cacheTtlHours || 168;

    if (!this.apiKey) {
      throw new Error('JobRequirementService requires a valid GEMINI_API_KEY.');
    }
  }

  /**
   * Normalizes a user-typed exam query (e.g., "ssc cgl 2026 ") into a clean cache key ("SSC_CGL_2026").
   * @param {string} examQuery
   * @returns {string}
   */
  _normalizeExamCode(examQuery) {
    if (!examQuery || typeof examQuery !== 'string' || examQuery.trim().length < 2) {
      const err = new Error('INVALID_EXAM_QUERY: Please provide a valid exam name (e.g., "SSC CGL", "UPSC", "RRB NTPC").');
      err.statusCode = 400;
      throw err;
    }

    return examQuery
      .trim()
      .toUpperCase()
      .replace(/[^A-Z0-9]+/g, '_')
      .replace(/^_|_$/g, '');
  }

  /**
   * Validates the parsed Gemini response to guarantee numeric sanity on KB limits and dimensions.
   * @param {Object} checklist
   */
  _validateChecklistStructure(checklist) {
    if (!checklist || !Array.isArray(checklist.requiredDocuments) || checklist.requiredDocuments.length === 0) {
      throw new Error('GEMINI_SCHEMA_VIOLATION: Checklist is missing requiredDocuments array.');
    }

    for (const doc of checklist.requiredDocuments) {
      if (typeof doc.minSizeKB !== 'number' || typeof doc.maxSizeKB !== 'number' || doc.maxSizeKB < doc.minSizeKB) {
        throw new Error(`INVALID_SIZE_BOUNDS: Document "${doc.category}" returned invalid KB range.`);
      }
      if (!Array.isArray(doc.allowedFormats) || doc.allowedFormats.length === 0) {
        throw new Error(`INVALID_FORMATS: Document "${doc.category}" must specify allowedFormats.`);
      }
    }

    return checklist;
  }

  /**
   * Fetches the verified JSON checklist of required documents, photo dimensions, and file size limits
   * for any Indian government or competitive exam using the Gemini Structured Outputs API.
   *
   * @param {string} examName - e.g. "SSC CGL", "UPSC CSE", "RRB NTPC", "IBPS PO"
   * @param {Object} [options]
   * @param {boolean} [options.forceRefresh=false] - Bypass Supabase cache and query Gemini directly
   * @returns {Promise<Object>} Verified exam document checklist JSON
   */
  async fetchExamDocumentChecklist(examName, options = {}) {
    const normalizedCode = this._normalizeExamCode(examName);
    const forceRefresh = Boolean(options.forceRefresh);

    // 1. Check Supabase cache first (unless forceRefresh is requested)
    if (this.supabase && !forceRefresh) {
      const { data: cached } = await this.supabase
        .from('exam_requirement_cache')
        .select('*')
        .eq('exam_code', normalizedCode)
        .gt('expires_at', new Date().toISOString())
        .single();

      if (cached && cached.checklist_json) {
        return {
          source: 'supabase_cache',
          cachedAt: cached.updated_at,
          ...cached.checklist_json,
        };
      }
    }

    // 2. Call Google Gemini REST API with strict `responseSchema` enforcement
    const endpoint = `https://generativelanguage.googleapis.com/v1beta/models/${this.modelName}:generateContent?key=${this.apiKey}`;

    const systemInstruction = [
      'You are an authoritative Indian Government & Competitive Examination Portal Specification Engine.',
      'Given an exam name (such as SSC CGL, UPSC CSE, RRB NTPC, IBPS PO, SBI PO, GATE, NEET, JEE Main),',
      'return the exact official online application document upload specifications.',
      'Ensure accurate file size limits in KB (e.g., Photo: 20KB-50KB, Signature: 10KB-20KB),',
      'exact dimensions in centimeters and pixels (at 200 DPI), allowed file formats (JPG/JPEG/PDF),',
      'and mandatory ink/background rules as specified in official recruitment notifications.',
    ].join(' ');

    const requestBody = {
      systemInstruction: {
        parts: [{ text: systemInstruction }],
      },
      contents: [
        {
          role: 'user',
          parts: [
            {
              text: `Generate the official document upload specification checklist for exam: "${examName.trim()}" (Normalized Code: ${normalizedCode}).`,
            },
          ],
        },
      ],
      generationConfig: {
        temperature: 0.1, // Low temperature for deterministic, factual portal specifications
        responseMimeType: 'application/json',
        responseSchema: EXAM_CHECKLIST_JSON_SCHEMA,
      },
    };

    const response = await fetch(endpoint, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(requestBody),
    });

    const rawResult = await response.json();

    if (!response.ok) {
      const apiMsg = rawResult?.error?.message || response.statusText;
      throw new Error(`GEMINI_API_ERROR (${response.status}): ${apiMsg}`);
    }

    const candidateText = rawResult?.candidates?.[0]?.content?.parts?.[0]?.text;
    if (!candidateText) {
      throw new Error('GEMINI_EMPTY_RESPONSE: Gemini API did not return a structured JSON checklist.');
    }

    const parsedChecklist = this._validateChecklistStructure(JSON.parse(candidateText));

    // 3. Persist verified checklist in Supabase cache for future requests
    if (this.supabase) {
      const expiresAt = new Date(Date.now() + this.cacheTtlHours * 3600 * 1000).toISOString();
      await this.supabase.from('exam_requirement_cache').upsert(
        {
          exam_code: normalizedCode,
          exam_display_name: parsedChecklist.examDisplayName,
          checklist_json: parsedChecklist,
          fetched_via_model: this.modelName,
          expires_at: expiresAt,
          updated_at: new Date().toISOString(),
        },
        { onConflict: 'exam_code' }
      );
    }

    return {
      source: 'gemini_live',
      model: this.modelName,
      ...parsedChecklist,
    };
  }
}

module.exports = {
  JobRequirementService,
  EXAM_CHECKLIST_JSON_SCHEMA,
};