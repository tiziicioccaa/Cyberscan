# Cyberscan

Una plataforma web educativa e interactiva para aprendizaje de **ciberseguridad** con herramientas prácticas de análisis y validación de seguridad.

![Cyberscan](https://img.shields.io/badge/Platform-Web-blue) ![License](https://img.shields.io/badge/License-ISC-green) ![JavaScript](https://img.shields.io/badge/Language-JavaScript-yellow)

---

## 🎯 Descripción General

**Cyberscan** (conocido también como **Infortech**) es una aplicación web moderna que combina:

- **Educación en Ciberseguridad**: Glosario interactivo con términos y conceptos clave
- **Análisis de Seguridad**: Análisis de URLs y archivos mediante **VirusTotal API**
- **Herramientas de Protección**: Generador y validador de contraseñas, verificación de filtraciones
- **Autenticación Integrada**: Registro e inicio de sesión con cuentas persistentes en MySQL
- **Historial de Análisis**: Registros locales en el navegador y resultados persistentes en MySQL

---

## ✨ Características Principales

### 1. 🔐 Autenticación y Gestión de Usuarios
- Registro de nuevas cuentas
- Inicio de sesión seguro
- Contraseñas almacenadas como hash scrypt en el servidor
- Foto de perfil personalizable (Base64)
- Cierre de sesión
- Correo único por cuenta y validación de formato (sin confirmar que el buzón exista)
- Sesiones revocables guardadas en MySQL
- La recuperación de contraseña está deshabilitada hasta contar con un método seguro de verificación

### 2. 🌐 Análisis de URLs
- Verifica la seguridad de cualquier URL
- Utiliza **VirusTotal API** para detección de malware
- Análisis de contenido HTML (título, encabezados)
- Estadísticas de detectores maliciosos/sospechosos/seguros
- Información detallada de amenazas detectadas

### 3. 📁 Análisis de Archivos
- Subida y análisis de archivos (máx 25MB)
- Verificación mediante VirusTotal
- Detalle de amenazas detectadas
- Historial de análisis

### 4. ✉️ Detección de Filtraciones
- Consulta Have I Been Pwned para verificar filtraciones conocidas
- Guarda en MySQL el correo consultado y los nombres, fechas y tipos de datos expuestos
- Requiere configurar `HIBP_API_KEY` en el servidor; la dirección también se envía a HIBP
- Alertas visuales (rojo/verde)

### 5. 🔑 Generador de Contraseñas
- Generación de contraseñas aleatorias
- Configuración de longitud (8-32 caracteres)
- Opciones de incluir números y símbolos especiales
- Copiar al portapapeles con un click

### 6. 🛡️ Validador de Contraseñas
- Análisis en tiempo real de fortaleza
- Indicador visual (barra de progreso)
- Clasificación: Débil, Moderada, Fuerte
- Recomendaciones de seguridad

### 7. 📚 Glosario Educativo
- Términos clave de ciberseguridad
- Definiciones claras y concisas
- Ejemplos: Phishing, Ransomware, SQL Injection, Hashing
- Interfaz interactiva con grid responsivo

### 8. 📊 Historial de Análisis
- Registro local de los análisis recientes y almacenamiento persistente en MySQL
- Almacenamiento de hasta 20 registros
- Clasificación por tipo (URL, Archivo, Filtración)
- Indicador de seguridad (verde = seguro, rojo = peligro)
- Opción de limpiar historial

---

## 🛠️ Stack Tecnológico

### Frontend
- **HTML5** - Estructura semántica
- **CSS3** - Estilos con Tailwind CSS
- **JavaScript (Vanilla)** - Lógica interactiva
- **LocalStorage API** - Token de sesión e historial local de análisis

### Backend
- **Node.js** - Runtime
- **Express.js** - Framework web
- **Multer** - Manejo de subidas de archivos
- **CORS** - Control de acceso
- **Node-Fetch** - Peticiones HTTP
- **Form-Data** - Manejo de datos multipart

### APIs Externas
- **VirusTotal API** - Análisis de seguridad
- **Have I Been Pwned API** - Consulta de filtraciones de correos
- **AllOrigins** - Proxy CORS para análisis de contenido

## 📁 Organización del código

- `cyberscan-plugin/`: generación del PDF y su endpoint de descarga.
- `routes/`: endpoints REST de autenticación, escaneos y estadísticas.
- `database/`: conexión MySQL, persistencia de análisis y scripts SQL.
- `services/`: cálculos compartidos de estadísticas usados por la API y el reporte.

---

## 📋 Requisitos Previos

- Node.js v14+ instalado
- npm o yarn
- Una clave API de VirusTotal (gratuita)
- Una clave API de Have I Been Pwned para búsquedas de correos
- Navegador moderno (Chrome, Firefox, Safari, Edge)

---

## 🚀 Instalación y Uso

instalar node.js
instalar wampserver
instalar workbench

Configura las variables `VIRUSTOTAL_API_KEY` y las variables de MySQL (`DB_HOST`, `DB_PORT`, `DB_USER`, `DB_PASSWORD`, `DB_NAME`) en el entorno del servidor. Para una instalación nueva, usa `database/cyberscan_dump.sql`. Si ya existe la base de datos, aplica `database/migrate_scan_target_value.sql` si aún no ampliaste `scan_logs.target_value`, y aplica `database/migrate_user_accounts.sql` para crear las tablas de cuentas y sesiones. Las cuentas nuevas se guardan en MySQL; la aplicación comprueba el formato del correo, pero no verifica la existencia ni la propiedad del buzón. Las contraseñas se almacenan con scrypt y no se puede recuperar una contraseña olvidada desde la interfaz.

Poner estos comandos en la powershell para iniciar node.js:

- Set-ExecutionPolicy RemoteSigned -Scope CurrentUser

- fnm env --use-on-cd | Out-String | Invoke-Expression

- fnm use 26

- npm start

$env:HAVEIBEENPWNED_API_KEY = "00000000000000000000000000000000"
$env:VIRUSTOTAL_API_KEY = "5a1a960b5f4208734ff5cafd5768a6f7091b5fc8669317ef8ef0366872d91478"

$env:DB_HOST = "localhost"
$env:DB_PORT = "3306"
$env:DB_USER = "root"
$env:DB_PASSWORD = ""
$env:DB_NAME = "cyberscan_db"

### 1. Clonar el repositorio
```bash
git clone https://github.com/tiziicioccaa/Cyberscan.git
cd Cyberscan
