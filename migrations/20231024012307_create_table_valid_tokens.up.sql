CREATE TABLE valid_tokens
(
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    token      VARCHAR(255) NOT NULL,
    refresh_token VARCHAR(255),
    user_id UUID NOT NULL REFERENCES Users (id) ON DELETE CASCADE,
    created_at TIMESTAMPTZ DEFAULT NOW()
)