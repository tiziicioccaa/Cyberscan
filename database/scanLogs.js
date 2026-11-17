'use strict';

const pool = require('./db');

// Inserta un análisis normalizado y devuelve el identificador asignado por MySQL.
async function recordScan({ targetType, targetValue, status, riskScore, details }) {
    const [result] = await pool.execute(
        'INSERT INTO scan_logs (target_type, target_value, status, risk_score, details) VALUES (?, ?, ?, ?, ?)',
        [targetType, targetValue, status, riskScore, String(details || '').trim().slice(0, 10000)],
    );
    return result.insertId;
}

module.exports = { recordScan };
