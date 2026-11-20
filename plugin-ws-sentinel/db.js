/**
 * @file db.js
 * @description Módulo de persistencia y acceso a datos para el Plugin Web Service Sentinel AI.
 * Gestiona la conexión embebida con SQLite 3, inicializa automáticamente el esquema relacional
 * (4 tablas con restricciones de integridad) y expone funciones asíncronas basadas en Promesas
 * para ejecutar consultas SQL de lectura y escritura desde ws-server.js.
 */
'use strict';

const sqlite3 = require('sqlite3').verbose();
const path = require('path');
const fs = require('fs');

// Define y crea el directorio ./database si aún no existe en el sistema de archivos
const dbDir = path.join(__dirname, 'database');
if (!fs.existsSync(dbDir)) fs.mkdirSync(dbDir, { recursive: true });

// Ruta absoluta al archivo de base de datos relacional embebida
const dbPath = path.join(dbDir, 'sentinel.sqlite');

/**
 * Instancia única de conexión con la base de datos SQLite.
 * Si el archivo sentinel.sqlite no existe, el motor lo crea automáticamente.
 */
const db = new sqlite3.Database(dbPath, (err) => {
    if (err) console.error('[WS Sentinel] Error al abrir SQLite:', err.message);
    else console.log('[WS Sentinel] Base de datos SQLite conectada en:', dbPath);
});

/**
 * Inicialización secuencial del esquema relacional (DDL).
 * db.serialize() garantiza que cada sentencia CREATE TABLE se ejecute en orden
 * antes de que el servidor SOAP comience a recibir peticiones.
 */
db.serialize(() => {
    // 1. Tabla de reglas preventivas (lista blanca y lista negra por dominio, extensión o palabra clave)
    db.run(`CREATE TABLE IF NOT EXISTS politicas_seguridad (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        tipo_objetivo TEXT NOT NULL CHECK(tipo_objetivo IN ('DOMINIO', 'EXTENSION', 'PALABRA_CLAVE')),
        patron TEXT NOT NULL UNIQUE,
        accion TEXT NOT NULL CHECK(accion IN ('BLOQUEAR', 'PERMITIR')),
        nivel_riesgo INTEGER NOT NULL CHECK(nivel_riesgo BETWEEN 0 AND 100),
        descripcion TEXT NOT NULL,
        creado_en DATETIME DEFAULT CURRENT_TIMESTAMP
    )`);

    // 2. Bitácora de auditoría que registra cada evaluación preventiva procesada por el Web Service
    db.run(`CREATE TABLE IF NOT EXISTS auditoria_ws (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        operacion_soap TEXT NOT NULL,
        recurso_evaluado TEXT NOT NULL,
        resultado TEXT NOT NULL,
        fecha DATETIME DEFAULT CURRENT_TIMESTAMP
    )`);

    // 3. Base de conocimiento local utilizada como respaldo automático en modo offline (sin internet)
    db.run(`CREATE TABLE IF NOT EXISTS conocimiento_ia (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        palabras_clave TEXT NOT NULL,
        titulo TEXT NOT NULL,
        respuesta TEXT NOT NULL
    )`);

    // 4. Historial conversacional del Asistente Sentinel AI segregado por correo electrónico de usuario
    db.run(`CREATE TABLE IF NOT EXISTS historial_chat_ia (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        usuario_email TEXT NOT NULL,
        pregunta TEXT NOT NULL,
        respuesta TEXT NOT NULL,
        fuente TEXT NOT NULL,
        fecha DATETIME DEFAULT CURRENT_TIMESTAMP
    )`);
});

/**
 * Ejecuta una consulta SQL de selección (SELECT) de forma asíncrona,
 * envolviendo el método basado en callbacks db.all() dentro de una Promesa.
 *
 * @param {string} sql - Sentencia SQL parametrizada (con marcadores ?).
 * @param {Array<any>} [params=[]] - Valores a enlazar en los marcadores de posición.
 * @returns {Promise<Array<Object>>} Arreglo de filas resultantes de la consulta.
 */
function allAsync(sql, params = []) {
    return new Promise((resolve, reject) => {
        db.all(sql, params, (err, rows) => (err ? reject(err) : resolve(rows)));
    });
}

/**
 * Ejecuta una sentencia SQL de modificación de datos (INSERT, UPDATE, DELETE)
 * de forma asíncrona, retornando el ID autogenerado y la cantidad de filas afectadas.
 *
 * @param {string} sql - Sentencia SQL parametrizada (con marcadores ?).
 * @param {Array<any>} [params=[]] - Valores a enlazar en los marcadores de posición.
 * @returns {Promise<{lastID: number, changes: number}>} Metadatos de la operación ejecutada.
 */
function runAsync(sql, params = []) {
    return new Promise((resolve, reject) => {
        db.run(sql, params, function (err) {
            if (err) reject(err);
            else resolve({ lastID: this.lastID, changes: this.changes });
        });
    });
}

module.exports = { db, allAsync, runAsync };
