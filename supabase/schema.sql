CREATE TABLE IF NOT EXISTS public.scans (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    url TEXT NOT NULL,
    domain TEXT NOT NULL,
    trust_score INTEGER NOT NULL CHECK (trust_score >= 0 AND trust_score <= 100),
    risk_level TEXT NOT NULL CHECK (risk_level IN ('Safe', 'Low Risk', 'Medium Risk', 'High Risk', 'Critical')),
    domain_age_days INTEGER,
    registrar TEXT NOT NULL DEFAULT 'Unknown',
    https_enabled BOOLEAN NOT NULL,
    suspicious_patterns TEXT[] NOT NULL DEFAULT '{}',
    ghost_summary TEXT NOT NULL,
    ghost_summary_en TEXT NOT NULL,
    ai_explanation TEXT NOT NULL,
    recommendations TEXT[] NOT NULL DEFAULT '{}',
    consequences JSONB NOT NULL DEFAULT '[]',
    crawled_page_content JSONB,
    scorecard JSONB,
    threat_assessment JSONB,
    created_at TIMESTAMPTZ NOT NULL DEFAULT timezone('utc'::text, now())
);

ALTER TABLE public.scans ADD COLUMN IF NOT EXISTS ghost_summary_en TEXT;
ALTER TABLE public.scans ADD COLUMN IF NOT EXISTS crawled_page_content JSONB;
ALTER TABLE public.scans ADD COLUMN IF NOT EXISTS scorecard JSONB;
ALTER TABLE public.scans ADD COLUMN IF NOT EXISTS threat_assessment JSONB;

CREATE INDEX IF NOT EXISTS idx_scans_created_at ON public.scans (created_at DESC);
CREATE INDEX IF NOT EXISTS idx_scans_domain ON public.scans (domain);
