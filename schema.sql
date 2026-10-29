-- ============================================================================
-- AUTOMATED AI FORM FILLER - PART 1 PRODUCTION DATABASE SCHEMA (SUPABASE / POSTGRESQL)
-- Includes:
--   1. user_security_profiles (Salt, PIN Verification Tag, Brute-Force Lockout)
--   2. encrypted_vault_records (AES-256-GCM Encrypted Profile & Document Blobs)
--   3. legal_audit_logs (Immutable IP, Timestamp, Device Fingerprint & Consent Trail)
--   4. exam_requirement_cache (Verified Gemini API Exam Document Rules Cache)
-- ============================================================================

-- Enable UUID & Cryptographic extensions
CREATE EXTENSION IF NOT EXISTS "uuid-ossp";
CREATE EXTENSION IF NOT EXISTS "pgcrypto";

-- ============================================================================
-- 1. USER SECURITY PROFILES (Zero-PIN Storage + Brute-Force Rate Limiting)
-- Note: The 4-digit Master PIN is NEVER stored here. We store only the unique
-- cryptographic salt and an AES-GCM verification tag used to validate key derivation.
-- ============================================================================
CREATE TABLE IF NOT EXISTS public.user_security_profiles (
    user_id UUID PRIMARY KEY REFERENCES auth.users(id) ON DELETE CASCADE,
    telegram_chat_id VARCHAR(64) UNIQUE,
    whatsapp_phone VARCHAR(32),
    kdf_salt VARCHAR(128) NOT NULL,                  -- 32-byte hex salt for Argon2id
    pin_verifier_iv VARCHAR(64) NOT NULL,            -- 12-byte IV for verificationcanary
    pin_verifier_tag VARCHAR(64) NOT NULL,           -- 16-byte GCM auth tag for canary
    pin_verifier_ciphertext TEXT NOT NULL,           -- Encrypted canary string ("VAULT_OK_V1")
    failed_pin_attempts INT NOT NULL DEFAULT 0,      -- Increments on wrong PIN
    locked_until TIMESTAMPTZ DEFAULT NULL,           -- Set to NOW() + 24 hours on 5th failure
    last_failed_attempt_at TIMESTAMPTZ DEFAULT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

-- ============================================================================
-- 2. PERSISTENT ENCRYPTED VAULT (AES-256-GCM Encrypted Personal Data & Docs)
-- Stores encrypted JSON profile data and encrypted binary documents (Photo,
-- Signature, 10th/12th Marksheet, Govt ID) with unique per-record IV and Auth Tag.
-- ============================================================================
CREATE TABLE IF NOT EXISTS public.encrypted_vault_records (
    record_id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    user_id UUID NOT NULL REFERENCES public.user_security_profiles(user_id) ON DELETE CASCADE,
    record_category VARCHAR(50) NOT NULL CHECK (
        record_category IN (
            'PROFILE_BIODATA',
            'PHOTO',
            'SIGNATURE',
            'MARKSHEET_10TH',
            'MARKSHEET_12TH',
            'GRADUATION_DEGREE',
            'GOVT_ID_PROOF',
            'CATEGORY_CERTIFICATE'
        )
    ),
    original_mime_type VARCHAR(100) NOT NULL DEFAULT 'application/json',
    original_size_bytes INT NOT NULL DEFAULT 0,
    iv_hex VARCHAR(64) NOT NULL,                     -- 12-byte (96-bit) unique AES-GCM IV
    auth_tag_hex VARCHAR(64) NOT NULL,               -- 16-byte (128-bit) AES-GCM integrity tag
    ciphertext_base64 TEXT NOT NULL,                 -- AES-256-GCM encrypted payload
    sha256_checksum VARCHAR(64) NOT NULL,            -- Plaintext integrity checksum (verified post-decryption)
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    UNIQUE (user_id, record_category)
);

CREATE INDEX IF NOT EXISTS idx_vault_user_category 
    ON public.encrypted_vault_records(user_id, record_category);

-- ============================================================================
-- 3. LEGAL AUDIT LOGS & USER CONSENT (Liability Protection Table)
-- Immutable append-only audit trail recording every sensitive action or form
-- submission with Real IP, Timestamp, Device Fingerprint, and Explicit Consent.
-- ============================================================================
CREATE TABLE IF NOT EXISTS public.legal_audit_logs (
    audit_id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    user_id UUID NOT NULL REFERENCES auth.users(id) ON DELETE RESTRICT,
    action_type VARCHAR(100) NOT NULL,               -- e.g., 'VAULT_UNLOCK', 'FORM_AUTOFILL_SUBMIT'
    target_exam_name VARCHAR(150),                   -- e.g., 'SSC CGL 2026', 'UPSC CSE'
    target_portal_url TEXT,
    client_real_ip INET NOT NULL,                    -- Extracted safely from x-forwarded-for
    forwarded_for_chain TEXT,                        -- Full raw proxy chain for forensic trace
    user_agent TEXT NOT NULL,                        -- Raw User-Agent header
    device_fingerprint_hash VARCHAR(128) NOT NULL,   -- Client + Server composite fingerprint
    explicit_consent_granted BOOLEAN NOT NULL CHECK (explicit_consent_granted = TRUE),
    consent_statement_text TEXT NOT NULL DEFAULT 'I authorize the system to fill this form on my behalf.',
    consent_signature_hash VARCHAR(128) NOT NULL,    -- SHA-256 proof binding User + IP + Timestamp + Statement
    request_metadata JSONB DEFAULT '{}'::jsonb,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_audit_user_time 
    ON public.legal_audit_logs(user_id, created_at DESC);
CREATE INDEX IF NOT EXISTS idx_audit_real_ip 
    ON public.legal_audit_logs(client_real_ip);

-- Prevent UPDATE or DELETE on legal_audit_logs (Strict Immutability Trigger)
CREATE OR REPLACE FUNCTION public.prevent_audit_log_modification()
RETURNS TRIGGER AS $$
BEGIN
    RAISE EXCEPTION 'SECURITY VIOLATION: legal_audit_logs table is strictly append-only and immutable.';
END;
$$ LANGUAGE plpgsql;

DROP TRIGGER IF EXISTS trg_immutable_audit_logs ON public.legal_audit_logs;
CREATE TRIGGER trg_immutable_audit_logs
BEFORE UPDATE OR DELETE ON public.legal_audit_logs
FOR EACH ROW EXECUTE FUNCTION public.prevent_audit_log_modification();

-- ============================================================================
-- 4. EXAM REQUIREMENT CACHE (Gemini API Verified Checklist Cache)
-- ============================================================================
CREATE TABLE IF NOT EXISTS public.exam_requirement_cache (
    exam_code VARCHAR(100) PRIMARY KEY,              -- Normalized slug e.g. 'SSC_CGL'
    exam_display_name VARCHAR(200) NOT NULL,
    checklist_json JSONB NOT NULL,                   -- Structured document & dimension rules
    fetched_via_model VARCHAR(64) NOT NULL,
    expires_at TIMESTAMPTZ NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

-- ============================================================================
-- ROW LEVEL SECURITY (RLS) POLICIES
-- ============================================================================
ALTER TABLE public.user_security_profiles ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.encrypted_vault_records ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.legal_audit_logs ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.exam_requirement_cache ENABLE ROW LEVEL SECURITY;

-- Users can only read their own security profile status (lockout status)
CREATE POLICY "Users can view own security profile"
    ON public.user_security_profiles FOR SELECT
    USING (auth.uid() = user_id);

-- Users can only view their own encrypted vault blobs
CREATE POLICY "Users can view own encrypted vault records"
    ON public.encrypted_vault_records FOR SELECT
    USING (auth.uid() = user_id);

-- Users can view their own legal audit history, but cannot modify or delete
CREATE POLICY "Users can view own legal audit logs"
    ON public.legal_audit_logs FOR SELECT
    USING (auth.uid() = user_id);

-- Authenticated users can read cached exam checklists
CREATE POLICY "Authenticated users can read exam cache"
    ON public.exam_requirement_cache FOR SELECT
    TO authenticated
    USING (true);