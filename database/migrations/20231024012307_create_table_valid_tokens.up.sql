CREATE TABLE valid_tokens
(
    id         SERIAL PRIMARY KEY,
    token      VARCHAR(255) NOT NULL,
    refresh_token VARCHAR(255),
    user_id INT NOT NULL REFERENCES Users (id) ON DELETE CASCADE,
    created_at TIMESTAMPTZ DEFAULT NOW()
)