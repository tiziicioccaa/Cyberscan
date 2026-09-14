# Cyberscan

Una plataforma web educativa e interactiva para aprendizaje de **ciberseguridad** con herramientas prácticas de análisis y validación de seguridad.

![Cyberscan](https://img.shields.io/badge/Platform-Web-blue) ![License](https://img.shields.io/badge/License-ISC-green) ![JavaScript](https://img.shields.io/badge/Language-JavaScript-yellow)

---

## 🎯 Descripción General

**Cyberscan** (conocido también como **Infortech**) es una aplicación web moderna que combina:

- **Educación en Ciberseguridad**: Glosario interactivo con términos y conceptos clave
- **Análisis de Seguridad**: Análisis de URLs y archivos mediante **VirusTotal API**
- **Herramientas de Protección**: Generador y validador de contraseñas, verificación de filtraciones
- **Autenticación Integrada**: Sistema de registro, login y recuperación de contraseña
- **Historial Local**: Almacenamiento de análisis realizados en el navegador

---

## ✨ Características Principales

### 1. 🔐 Autenticación y Gestión de Usuarios
- Registro de nuevas cuentas
- Inicio de sesión seguro
- Recuperación/cambio de contraseña
- Foto de perfil personalizable (Base64)
- Cierre de sesión
- Almacenamiento seguro en localStorage

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
- Verifica si un correo electrónico fue expuesto en filtraciones públicas
- Consulta bases de datos de brechas conocidas
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
- Registro local de todos los análisis realizados
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
- **LocalStorage API** - Almacenamiento local

### Backend
- **Node.js** - Runtime
- **Express.js** - Framework web
- **Multer** - Manejo de subidas de archivos
- **CORS** - Control de acceso
- **Node-Fetch** - Peticiones HTTP
- **Form-Data** - Manejo de datos multipart

### APIs Externas
- **VirusTotal API** - Análisis de seguridad
- **AllOrigins** - Proxy CORS para análisis de contenido

---

## 📋 Requisitos Previos

- Node.js v14+ instalado
- npm o yarn
- Una clave API de VirusTotal (gratuita)
- Navegador moderno (Chrome, Firefox, Safari, Edge)

---

## 🚀 Instalación y Uso

### 1. Clonar el repositorio
```bash
git clone https://github.com/tiziicioccaa/Cyberscan.git
cd Cyberscan
