-- Agrega las tablas de Sentinel a la base existente sin borrar ni modificar datos previos.
USE cyberscan_db;

CREATE TABLE IF NOT EXISTS sentinel_policies (
    id INT UNSIGNED AUTO_INCREMENT PRIMARY KEY,
    target_type VARCHAR(24) NOT NULL,
    pattern VARCHAR(255) NOT NULL,
    action VARCHAR(16) NOT NULL,
    risk_level TINYINT UNSIGNED NOT NULL,
    description VARCHAR(1000) NOT NULL,
    created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    UNIQUE KEY uq_sentinel_policies_pattern (pattern),
    INDEX idx_sentinel_policies_risk_level (risk_level)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

CREATE TABLE IF NOT EXISTS sentinel_audit_log (
    id BIGINT UNSIGNED AUTO_INCREMENT PRIMARY KEY,
    account_id INT UNSIGNED NOT NULL,
    operation VARCHAR(40) NOT NULL,
    evaluated_resource VARCHAR(2048) NOT NULL,
    result VARCHAR(24) NOT NULL,
    created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    INDEX idx_sentinel_audit_account_created (account_id, created_at),
    CONSTRAINT fk_sentinel_audit_account
        FOREIGN KEY (account_id) REFERENCES user_accounts (id)
        ON DELETE CASCADE
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

CREATE TABLE IF NOT EXISTS sentinel_knowledge_base (
    id INT UNSIGNED AUTO_INCREMENT PRIMARY KEY,
    keywords VARCHAR(1000) NOT NULL,
    title VARCHAR(255) NOT NULL,
    response TEXT NOT NULL,
    UNIQUE KEY uq_sentinel_knowledge_title (title)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

CREATE TABLE IF NOT EXISTS sentinel_chat_history (
    id BIGINT UNSIGNED AUTO_INCREMENT PRIMARY KEY,
    account_id INT UNSIGNED NOT NULL,
    question VARCHAR(1000) NOT NULL,
    answer TEXT NOT NULL,
    source VARCHAR(255) NOT NULL,
    created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    INDEX idx_sentinel_chat_account_created (account_id, id),
    CONSTRAINT fk_sentinel_chat_account
        FOREIGN KEY (account_id) REFERENCES user_accounts (id)
        ON DELETE CASCADE
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

INSERT IGNORE INTO sentinel_policies (target_type, pattern, action, risk_level, description) VALUES
    ('EXTENSION', '.exe', 'BLOQUEAR', 95, 'Ejecutable de Windows restringido por política institucional.'),
    ('EXTENSION', '.xlsm', 'BLOQUEAR', 80, 'Hoja de cálculo con macros potencialmente maliciosas.'),
    ('EXTENSION', '.bat', 'BLOQUEAR', 90, 'Script por lotes no autorizado.'),
    ('DOMINIO', 'phishing-test.com', 'BLOQUEAR', 100, 'Dominio reportado en lista negra interna.'),
    ('DOMINIO', 'malware-drop.net', 'BLOQUEAR', 98, 'Servidor conocido de distribución de malware.'),
    ('DOMINIO', 'github.com', 'PERMITIR', 5, 'Repositorio oficial de desarrollo confiable.'),
    ('PALABRA_CLAVE', 'free-nitro-gift', 'BLOQUEAR', 85, 'Patrón frecuente en campañas de ingeniería social.');

INSERT IGNORE INTO sentinel_knowledge_base (keywords, title, response) VALUES
    ('ransomware,secuestro,cifrado,rescate', 'Ransomware (secuestro de datos)', 'El ransomware cifra tus archivos y exige un rescate. Aísla el equipo de la red, no pagues y restaura desde copias de seguridad offline.'),
    ('troyano,trojan,disfrazado,falso', 'Troyano', 'Un troyano se oculta en software aparentemente legítimo. Descarga programas solo desde fuentes oficiales y mantén el sistema actualizado.'),
    ('phishing,correo,enlace,suplantacion,banco', 'Phishing e ingeniería social', 'El phishing busca robar información mediante correos o sitios falsos. Verifica el dominio del remitente y evita iniciar sesión desde enlaces inesperados.'),
    ('gusano,worm,red,propagacion', 'Gusano informático', 'Un gusano puede propagarse automáticamente por una red. Mantén el sistema operativo actualizado y utiliza un firewall.'),
    ('spyware,keylogger,espia,teclado', 'Spyware y keyloggers', 'El spyware puede vigilar tu actividad. Usa un gestor de contraseñas y ejecuta análisis con herramientas de seguridad confiables.'),
    ('virus,malware,infectado,lento', 'Malware', 'Si sospechas una infección, desconecta el equipo de la red, ejecuta un análisis antimalware y cambia tus claves desde un dispositivo limpio.');
