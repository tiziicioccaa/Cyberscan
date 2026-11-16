-- Selecciona la base donde se almacenan los análisis y las cuentas.
USE cyberscan_db;

-- Guarda las credenciales de forma persistente; la contraseña se almacena como hash scrypt.
CREATE TABLE IF NOT EXISTS user_accounts (
    id INT UNSIGNED AUTO_INCREMENT PRIMARY KEY,
    username VARCHAR(80) NOT NULL,
    email VARCHAR(254) NOT NULL,
    password_hash VARCHAR(255) NOT NULL,
    avatar MEDIUMTEXT NULL,
    created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    UNIQUE KEY uq_user_accounts_email (email)
) ENGINE=InnoDB;

-- Guarda hashes de tokens de sesión para que puedan revocarse sin almacenar el token original.
CREATE TABLE IF NOT EXISTS auth_sessions (
    token_hash CHAR(64) CHARACTER SET ascii COLLATE ascii_bin PRIMARY KEY,
    account_id INT UNSIGNED NOT NULL,
    expires_at DATETIME NOT NULL,
    created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    INDEX idx_auth_sessions_expires_at (expires_at),
    CONSTRAINT fk_auth_sessions_account
        FOREIGN KEY (account_id) REFERENCES user_accounts (id)
        ON DELETE CASCADE
) ENGINE=InnoDB;
