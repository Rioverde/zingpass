-- +goose Up
ALTER TABLE users ADD COLUMN email_status TEXT NOT NULL DEFAULT 'unverified';
ALTER TABLE users ADD CONSTRAINT users_email_status_check
    CHECK (email_status IN ('unverified', 'verified', 'pending', 'bounced', 'blocked'));

CREATE TABLE email_verifications (
    id         UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    user_id    UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    token_hash TEXT NOT NULL UNIQUE,
    expires_at TIMESTAMPTZ NOT NULL,
    used_at    TIMESTAMPTZ,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX email_verifications_user_active_idx
    ON email_verifications (user_id) WHERE used_at IS NULL;

-- +goose Down
DROP TABLE IF EXISTS email_verifications;
ALTER TABLE users DROP CONSTRAINT IF EXISTS users_email_status_check;
ALTER TABLE users DROP COLUMN IF EXISTS email_status;
