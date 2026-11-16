'use strict'; // Habilita validaciones estrictas de JavaScript en este módulo.

const mysql = require('mysql2/promise'); // Importa la API de MySQL compatible con async/await.

const pool = mysql.createPool({ // Crea un pool reutilizable para evitar conexiones individuales por petición.
    host: process.env.DB_HOST || 'localhost', // Permite cambiar el host con una variable de entorno.
    port: Number(process.env.DB_PORT || 3306), // Usa el puerto MySQL habitual, configurable externamente.
    user: process.env.DB_USER || 'root', // Mantiene root como valor por defecto para desarrollo local.
    password: process.env.DB_PASSWORD || '', // Permite contraseña vacía local o una credencial externa.
    database: process.env.DB_NAME || 'cyberscan_db', // Selecciona la base de datos del plugin.
    waitForConnections: true, // Encola solicitudes si todas las conexiones están ocupadas.
    connectionLimit: Number(process.env.DB_CONNECTION_LIMIT || 10), // Limita el número de conexiones concurrentes.
    queueLimit: 0, // No limita el tamaño de la cola de solicitudes al pool.
    charset: 'utf8mb4', // Soporta caracteres Unicode completos en objetivos y detalles.
    enableKeepAlive: true, // Mantiene conexiones TCP activas cuando el sistema operativo lo permite.
}); // Finaliza la configuración del pool.

async function verifyDatabaseConnection() { // Comprueba la conexión al iniciar sin detener el servidor principal.
    let connection; // Conserva la conexión temporal para poder liberarla siempre.
    try { // Captura fallos de configuración o de disponibilidad de MySQL.
        connection = await pool.getConnection(); // Solicita una conexión al pool.
        console.info('[Cyberscan Plugin] Conexión a MySQL establecida.'); // Informa que la base de datos responde.
    } catch (error) { // Maneja errores sin tumbar la aplicación base.
        console.error(`[Cyberscan Plugin] No se pudo conectar a MySQL: ${error.message}`); // Explica el fallo en consola.
        console.error('[Cyberscan Plugin] Verifica MySQL, cyberscan_db y las variables DB_HOST, DB_USER, DB_PASSWORD y DB_NAME.'); // Sugiere las verificaciones relevantes.
    } finally { // Ejecuta la liberación incluso si la conexión falló.
        if (connection) connection.release(); // Devuelve la conexión al pool si fue obtenida.
    } // Termina el bloque de manejo de conexión.
} // Finaliza la función de verificación inicial.

verifyDatabaseConnection(); // Ejecuta una comprobación informativa al cargar las rutas del plugin.

module.exports = pool; // Expone el pool para las rutas API del plugin.
