-- name: CreateUser :one
INSERT INTO auth_users (
    uuid, email, password_hash, first_name, last_name, phone, roles,
    is_active, is_email_verified,
    email_verification_token, email_verification_token_expires_at,
    last_verification_email_sent_at, verification_email_attempts,
    created_at
) VALUES (
    $1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14
) RETURNING id;

-- name: UpdateUser :exec
UPDATE auth_users SET
    email = $2,
    password_hash = $3,
    first_name = $4,
    last_name = $5,
    phone = $6,
    roles = $7,
    is_active = $8,
    is_email_verified = $9,
    email_verification_token = $10,
    email_verification_token_expires_at = $11,
    last_verification_email_sent_at = $12,
    verification_email_attempts = $13,
    password_reset_token = $14,
    password_reset_token_expires_at = $15,
    last_password_reset_email_sent_at = $16,
    password_reset_attempts = $17
WHERE id = $1;

-- name: GetUserByEmail :one
SELECT * FROM auth_users WHERE email = $1;

-- name: GetUserByUUID :one
SELECT * FROM auth_users WHERE uuid = $1;

-- name: GetUserByVerificationToken :one
SELECT * FROM auth_users WHERE email_verification_token = $1;

-- name: GetUserByPasswordResetToken :one
SELECT * FROM auth_users WHERE password_reset_token = $1;
