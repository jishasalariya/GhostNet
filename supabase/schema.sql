CREATE TABLE IF NOT EXISTS public.scans (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    url TEXT NOT NULL,
    domain TEXT NOT NULL,
    trust_score INTEGER NOT NULL CHECK (trust_score >= 0 AND trust_score <= 100),
    risk_level TEXT NOT NULL CHECK (risk_level IN ('Safe', 'Low Risk', 'Medium Risk', 'High Risk', 'Critical')),
    domain_age_days INTEGER,
    registrar TEXT,
    https_enabled BOOLEAN NOT NULL,
    suspicious_patterns TEXT[] DEFAULT '{}',
    ghost_summary TEXT NOT NULL,
    ai_explanation TEXT NOT NULL,
    recommendations TEXT[] DEFAULT '{}',
    consequences JSONB NOT NULL DEFAULT '[]',
    created_at TIMESTAMPTZ NOT NULL DEFAULT timezone('utc'::text, now())
);

CREATE INDEX IF NOT EXISTS idx_scans_created_at ON public.scans (created_at DESC);

CREATE INDEX IF NOT EXISTS idx_scans_domain ON public.scans (domain);
