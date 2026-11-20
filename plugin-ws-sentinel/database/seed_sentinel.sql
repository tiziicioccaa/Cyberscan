-- ============================================================================
-- Volcado de datos de prueba (Dump / Seed SQL) - Plugin Web Service Sentinel AI
-- Archivo: seed_sentinel.sql
-- Motor SGBD: SQLite 3 (sentinel.db)
-- Uso para restauración en desarrollo:
--   sqlite3 sentinel.db < seed_sentinel.sql
-- ============================================================================

PRAGMA foreign_keys = OFF;
BEGIN TRANSACTION;

-- 1. Limpieza preventiva de tablas existentes para restauración limpia
DROP TABLE IF EXISTS auditoria_ws;
DROP TABLE IF EXISTS historial_chat_ia;
DROP TABLE IF EXISTS conocimiento_ia;
DROP TABLE IF EXISTS politicas_seguridad;

-- ============================================================================
-- 2. ESTRUCTURA DE TABLAS (DDL)
-- ============================================================================

CREATE TABLE politicas_seguridad (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    tipo_objetivo TEXT NOT NULL CHECK(tipo_objetivo IN ('DOMINIO', 'EXTENSION', 'PALABRA_CLAVE')),
    patron TEXT NOT NULL,
    accion TEXT NOT NULL CHECK(accion IN ('BLOQUEAR', 'PERMITIR')),
    nivel_riesgo INTEGER NOT NULL DEFAULT 50 CHECK(nivel_riesgo >= 0 AND nivel_riesgo <= 100),
    descripcion TEXT NOT NULL,
    creado_en DATETIME DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE historial_chat_ia (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    usuario_email TEXT NOT NULL,
    pregunta TEXT NOT NULL,
    respuesta TEXT NOT NULL,
    fuente TEXT NOT NULL,
    creado_en DATETIME DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE auditoria_ws (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    operacion_soap TEXT NOT NULL,
    recurso_evaluado TEXT NOT NULL,
    resultado TEXT NOT NULL,
    fecha_hora DATETIME DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE conocimiento_ia (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    palabra_clave TEXT NOT NULL,
    respuesta TEXT NOT NULL
);

-- ============================================================================
-- 3. DATOS DE PRUEBA (DML - INSERTS)
-- ============================================================================

-- 3.1 Políticas de seguridad preventivas (Listas blancas y negras)
INSERT INTO politicas_seguridad (id, tipo_objetivo, patron, accion, nivel_riesgo, descripcion) VALUES
(1, 'EXTENSION', '.exe', 'BLOQUEAR', 90, 'Ejecutable de Windows restringido por política institucional.'),
(2, 'EXTENSION', '.xlsm', 'BLOQUEAR', 85, 'Hoja de cálculo con macros potencialmente maliciosas.'),
(3, 'EXTENSION', '.bat', 'BLOQUEAR', 95, 'Script por lotes no autorizado.'),
(4, 'EXTENSION', '.vbs', 'BLOQUEAR', 95, 'Script de Visual Basic bloqueado por riesgo de ejecución remota.'),
(5, 'DOMINIO', 'phishing-test.com', 'BLOQUEAR', 100, 'Dominio reportado en lista negra interna.'),
(6, 'DOMINIO', 'malware-drop.net', 'BLOQUEAR', 100, 'Servidor conocido de distribución de payloads.'),
(7, 'PALABRA_CLAVE', 'free-nitro-gift', 'BLOQUEAR', 80, 'Patrón frecuente en campañas de ingeniería social.'),
(8, 'DOMINIO', 'github.com', 'PERMITIR', 5, 'Repositorio oficial confiable incluido en lista blanca.'),
(9, 'EXTENSION', '.pdf', 'PERMITIR', 10, 'Documento estándar permitido sujeto a escaneo VirusTotal.');

-- 3.2 Base de conocimiento local de respaldo (Offline Fallback)
INSERT INTO conocimiento_ia (id, palabra_clave, respuesta) VALUES
(1, 'ransomware', 'El ransomware es un tipo de malware que cifra los archivos del sistema y exige un rescate económico para restaurar el acceso. Se recomienda mantener copias de seguridad aisladas y no ejecutar adjuntos desconocidos.'),
(2, 'phishing', 'El phishing es una técnica de ingeniería social que suplanta la identidad de entidades legítimas mediante correos o sitios web falsos para robar credenciales o datos bancarios.'),
(3, 'troyano', 'Un troyano se disfraza como un programa legítimo para engañar al usuario y abrir una puerta trasera (backdoor) que permite el acceso remoto no autorizado.'),
(4, 'malware', 'Malware es el término general para cualquier software malicioso diseñado para dañar, infiltrarse o tomar control de un sistema sin consentimiento.');

-- 3.3 Historial de conversaciones de prueba con Sentinel AI
INSERT INTO historial_chat_ia (id, usuario_email, pregunta, respuesta, fuente) VALUES
(1, 'alumno@escuela.edu.ar', '¿Qué es el Ransomware?', 'El ransomware es un software malicioso que secuestra datos mediante cifrado y pide un rescate. Nunca pagues el rescate y mantén respaldos desconectados.', 'IA Generativa (llama-3.3-70b-versatile)'),
(2, 'alumno@escuela.edu.ar', '¿Cómo detectar Phishing?', 'Verifica siempre el dominio real del remitente, desconfía de mensajes con urgencia extrema y nunca ingreses contraseñas desde enlaces recibidos por correo.', 'IA Generativa (llama-3.3-70b-versatile)'),
(3, 'admin@cyberscan.local', '¿Por qué se bloquea la extensión .bat?', 'Los archivos .bat ejecutan comandos directos en la consola de Windows y suelen usarse para automatizar descargas maliciosas o modificar configuraciones críticas.', 'IA Generativa (llama-3.3-70b-versatile)');

-- 3.4 Registros de auditoría de operaciones SOAP
INSERT INTO auditoria_ws (id, operacion_soap, recurso_evaluado, resultado) VALUES
(1, 'EvaluarRecurso', 'factura_pendiente.exe', 'BLOQUEAR'),
(2, 'EvaluarRecurso', 'http://phishing-test.com/login', 'BLOQUEAR'),
(3, 'EvaluarRecurso', 'https://github.com/cyberscan', 'PERMITIR'),
(4, 'EvaluarRecurso', 'manual_usuario.pdf', 'PERMITIR'),
(5, 'EvaluarRecurso', 'https://ejemplo-nuevo.org', 'SIN_REGLA');

COMMIT;
PRAGMA foreign_keys = ON;
