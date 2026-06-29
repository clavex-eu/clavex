ALTER TABLE organizations
  ADD COLUMN IF NOT EXISTS ai_anthropic_key TEXT;
