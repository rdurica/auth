CREATE TABLE auth_users (
    id                              BIGSERIAL PRIMARY KEY,
    uuid                            UUID NOT NULL UNIQUE,
    email                           VARCHAR(180) NOT NULL UNIQUE,
    password_hash                   TEXT NOT NULL,
    first_name                      VARCHAR(20) NOT NULL,
    last_name                       VARCHAR(20) NOT NULL,
    phone                           VARCHAR(20),
    roles                           JSONB NOT NULL DEFAULT '["USER"]'::jsonb,
    is_active                       BOOLEAN NOT NULL DEFAULT TRUE,
    is_email_verified               BOOLEAN NOT NULL DEFAULT FALSE,
    email_verification_token        CHAR(64),
    email_verification_token_expires_at TIMESTAMPTZ,
    last_verification_email_sent_at TIMESTAMPTZ,
    verification_email_attempts     INTEGER NOT NULL DEFAULT 0,
    password_reset_token            CHAR(64),
    password_reset_token_expires_at TIMESTAMPTZ,
    last_password_reset_email_sent_at TIMESTAMPTZ,
    password_reset_attempts         INTEGER NOT NULL DEFAULT 0,
    created_at                      TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE UNIQUE INDEX auth_users_email_verification_token_uidx
    ON auth_users (email_verification_token)
    WHERE email_verification_token IS NOT NULL;

CREATE UNIQUE INDEX auth_users_password_reset_token_uidx
    ON auth_users (password_reset_token)
    WHERE password_reset_token IS NOT NULL;

CREATE TABLE auth_refresh_tokens (
    id          BIGSERIAL PRIMARY KEY,
    user_uuid   UUID NOT NULL REFERENCES auth_users (uuid) ON DELETE CASCADE,
    token       CHAR(64) NOT NULL UNIQUE,
    issued_at   TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    expires_at  TIMESTAMPTZ NOT NULL,
    revoked_at  TIMESTAMPTZ
);

CREATE INDEX auth_refresh_tokens_user_uuid_idx ON auth_refresh_tokens (user_uuid);
CREATE INDEX auth_refresh_tokens_active_idx
    ON auth_refresh_tokens (user_uuid, expires_at)
    WHERE revoked_at IS NULL;
