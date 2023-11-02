SET timezone = 'Asia/Jakarta';

CREATE TABLE Users (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    username VARCHAR(255) UNIQUE NOT NULL,
    password VARCHAR(255) NOT NULL,
    role VARCHAR(255) DEFAULT 'pegawai' CHECK (role IN ('pegawai', 'admin')),
    created_at TIMESTAMPTZ DEFAULT NOW()
);
