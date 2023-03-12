CREATE TABLE IF NOT EXISTS users (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    email TEXT NOT NULL,
    password TEXT NOT NULL,
    isAdmin BOOLEAN DEFAULT false
);

CREATE TABLE IF NOT EXISTS uploads (
    ID INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id INTEGER NOT NULL,
    originalFileName TEXT,
    uploadDate TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP
);

INSERT INTO users (email, password, isAdmin) VALUES ("admin@vulnerable-filehoster.de", "3cc31cd246149aec68079241e71e98f6", true);