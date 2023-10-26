CREATE TABLE valid_tokens
(
    id         SERIAL PRIMARY KEY,
    token      VARCHAR(255) NOT NULL,
    user_id INT NOT NULL REFERENCES Users (id) ON DELETE CASCADE,
    created_at TIMESTAMPTZ DEFAULT NOW()
--     token_expiration TIMESTAMPTZ
)