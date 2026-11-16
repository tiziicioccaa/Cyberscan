-- Crea la base de datos local del plugin si todavía no existe.
CREATE DATABASE IF NOT EXISTS cyberscan_db
    CHARACTER SET utf8mb4
    COLLATE utf8mb4_unicode_ci;

-- Selecciona la base de datos que usará el plugin.
USE cyberscan_db;

-- Crea la tabla de registros de análisis.
CREATE TABLE IF NOT EXISTS scan_logs (
    id INT AUTO_INCREMENT PRIMARY KEY,
    target_type ENUM('url', 'file', 'email') NOT NULL,
    target_value VARCHAR(2048) NOT NULL,
    status ENUM('safe', 'suspicious', 'malicious') NOT NULL,
    risk_score INT NOT NULL,
    details TEXT,
    created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    CONSTRAINT chk_scan_logs_risk_score CHECK (risk_score BETWEEN 0 AND 100),
    INDEX idx_scan_logs_created_at (created_at),
    INDEX idx_scan_logs_status (status),
    INDEX idx_scan_logs_target_type (target_type)
) ENGINE=InnoDB;

-- Guarda las cuentas creadas desde el sitio; nunca almacena contraseñas en texto plano.
CREATE TABLE IF NOT EXISTS user_accounts (
    id INT UNSIGNED AUTO_INCREMENT PRIMARY KEY,
    username VARCHAR(80) NOT NULL,
    email VARCHAR(254) NOT NULL,
    password_hash VARCHAR(255) NOT NULL,
    avatar MEDIUMTEXT NULL,
    created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    UNIQUE KEY uq_user_accounts_email (email)
) ENGINE=InnoDB;

-- Mantiene las sesiones revocables guardando solo el hash de cada token.
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

-- Agrega registros demostrativos: dominios .example y correos reservados para documentación.
-- Los resultados son datos ficticios de prueba y no representan análisis reales.
INSERT INTO scan_logs (target_type, target_value, status, risk_score, details, created_at) VALUES
    ('url', 'https://portal.example/', 'safe', 4, 'Registro de demostración: no se observan indicadores adversos en el conjunto de prueba.', '2026-10-28 09:15:00'),
    ('url', 'http://login-secure.example/account', 'suspicious', 64, 'Registro ficticio: nombre de ruta similar a inicio de sesión; requiere revisión manual.', '2026-10-29 11:42:00'),
    ('url', 'https://download-malware.example/payload', 'malicious', 96, 'Registro ficticio para pruebas: clasificado como malicioso en el conjunto de demostración.', '2026-10-30 14:08:00'),
    ('url', 'https://docs.example/security', 'safe', 2, 'Registro de demostración: sin hallazgos relevantes en el conjunto de prueba.', '2026-11-01 08:35:00'),
    ('file', 'informe_anual.pdf', 'safe', 3, 'Registro de demostración: archivo marcado como seguro en los datos de prueba.', '2026-11-02 16:20:00'),
    ('file', 'factura_urgente.xlsm', 'suspicious', 72, 'Registro ficticio: documento con macros; no abrir hasta verificar origen y contenido.', '2026-11-03 10:05:00'),
    ('file', 'actualizador_falso.exe', 'malicious', 99, 'Registro ficticio para pruebas: ejecutable marcado como malicioso.', '2026-11-05 13:30:00'),
    ('file', 'backup_cifrado.zip', 'suspicious', 55, 'Registro ficticio: archivo comprimido con contenido aún no verificado.', '2026-11-07 17:12:00'),
    ('email', 'aviso@empresa.example', 'safe', 5, 'Registro de demostración: remitente reservado para documentación, sin señal de alerta en el ejemplo.', '2026-11-08 09:50:00'),
    ('email', 'seguridad-urgente@example.org', 'suspicious', 68, 'Registro ficticio: asunto o remitente con lenguaje de urgencia; verificar por canal alternativo.', '2026-11-09 12:25:00'),
    ('email', 'premio-inmediato@example.net', 'malicious', 91, 'Registro ficticio para pruebas: mensaje de premio inesperado clasificado como malicioso.', '2026-11-11 15:45:00'),
    ('email', 'notificaciones@example.com', 'safe', 1, 'Registro de demostración: ejemplo de correo seguro para validar estadísticas.', '2026-11-12 07:40:00');
