

DROP TABLE IF EXISTS politicas_seguridad;
DROP TABLE IF EXISTS auditoria_ws;
DROP TABLE IF EXISTS conocimiento_ia;
DROP TABLE IF EXISTS historial_chat_ia;

CREATE TABLE politicas_seguridad (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    tipo_objetivo TEXT NOT NULL CHECK(tipo_objetivo IN ('DOMINIO', 'EXTENSION', 'PALABRA_CLAVE')),
    patron TEXT NOT NULL UNIQUE,
    accion TEXT NOT NULL CHECK(accion IN ('BLOQUEAR', 'PERMITIR')),
    nivel_riesgo INTEGER NOT NULL CHECK(nivel_riesgo BETWEEN 0 AND 100),
    descripcion TEXT NOT NULL,
    creado_en DATETIME DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE auditoria_ws (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    operacion_soap TEXT NOT NULL,
    recurso_evaluado TEXT NOT NULL,
    resultado TEXT NOT NULL,
    fecha DATETIME DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE conocimiento_ia (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    palabras_clave TEXT NOT NULL,
    titulo TEXT NOT NULL,
    respuesta TEXT NOT NULL
);

CREATE TABLE historial_chat_ia (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    usuario_email TEXT NOT NULL,
    pregunta TEXT NOT NULL,
    respuesta TEXT NOT NULL,
    fuente TEXT NOT NULL,
    fecha DATETIME DEFAULT CURRENT_TIMESTAMP
);

INSERT INTO politicas_seguridad (tipo_objetivo, patron, accion, nivel_riesgo, descripcion) VALUES
('EXTENSION', '.exe', 'BLOQUEAR', 95, 'Ejecutable de Windows restringido por política institucional.'),
('EXTENSION', '.xlsm', 'BLOQUEAR', 80, 'Hoja de cálculo con macros potencialmente maliciosas.'),
('EXTENSION', '.bat', 'BLOQUEAR', 90, 'Script por lotes no autorizado.'),
('DOMINIO', 'phishing-test.com', 'BLOQUEAR', 100, 'Dominio reportado en lista negra interna.'),
('DOMINIO', 'malware-drop.net', 'BLOQUEAR', 98, 'Servidor conocido de distribución de payloads.'),
('DOMINIO', 'google.com', 'PERMITIR', 0, 'Dominio corporativo verificado en lista blanca.'),
('DOMINIO', 'github.com', 'PERMITIR', 0, 'Repositorio oficial de desarrollo confiable.'),
('PALABRA_CLAVE', 'free-nitro-gift', 'BLOQUEAR', 85, 'Patrón típico de campañas de ingeniería social.');

INSERT INTO conocimiento_ia (palabras_clave, titulo, respuesta) VALUES
('ransomware,secuestro,cifrado,rescate', 'Ransomware (Secuestro de Datos)', 'El ransomware cifra tus archivos y exige un rescate. Nunca pagues: desconecta el equipo de la red de inmediato y restaura desde copias de seguridad offline.'),
('troyano,trojan,disfrazado,falso', 'Troyano (Trojan Horse)', 'Un troyano se oculta dentro de software aparentemente legítimo para abrir puertas traseras y robar credenciales. Descarga programas solo desde sitios oficiales.'),
('phishing,correo,enlace,suplantacion,banco', 'Phishing e Ingeniería Social', 'El phishing busca engañarte con correos o webs clonadas para robar contraseñas. Verifica el dominio real del remitente y activa el doble factor (2FA).'),
('gusano,worm,red,propagacion', 'Gusano Informático (Worm)', 'Un gusano se replica automáticamente por la red explotando vulnerabilidades sin intervención humana. Mantén el sistema operativo y el firewall actualizados.'),
('spyware,keylogger,espia,teclado', 'Spyware y Keyloggers', 'El spyware espía tu actividad y los keyloggers registran tus teclas. Usa un gestor de contraseñas y ejecuta un análisis antimalware.'),
('virus,malware,infectado,lento', 'Infección por Virus / Malware General', 'Si sospechas de infección: 1) Desconecta Internet. 2) Inicia en Modo Seguro. 3) Ejecuta un análisis completo con antivirus y cambia tus claves desde otro equipo limpio.');
