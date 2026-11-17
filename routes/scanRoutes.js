'use strict';

const express = require('express');
const { recordScan } = require('../database/scanLogs');
const { getStatistics } = require('../services/scanStatistics');

// Agrupa las rutas REST relacionadas con el registro y las estadísticas de análisis.
const router = express.Router();
const allowedTypes = new Set(['url', 'file', 'email']);
const allowedStatuses = new Set(['safe', 'suspicious', 'malicious']);

router.use(express.json({ limit: '16kb' }));

// Persiste un análisis validado, enviado por un cliente de la API.
router.post('/log-scan', async (req, res) => {
    const { target_type: targetType, target_value: rawTarget, status, risk_score: rawRisk, details } = req.body || {};
    const targetValue = typeof rawTarget === 'string' ? rawTarget.trim() : '';
    const riskScore = Number(rawRisk);
    if (!allowedTypes.has(targetType)) {
        return res.status(400).json({ error: "target_type debe ser 'url', 'file' o 'email'." });
    }
    if (!allowedStatuses.has(status)) {
        return res.status(400).json({ error: "status debe ser 'safe', 'suspicious' o 'malicious'." });
    }
    if (!targetValue || targetValue.length > 2048) {
        return res.status(400).json({ error: 'target_value es obligatorio y debe tener hasta 2048 caracteres.' });
    }
    if (!Number.isInteger(riskScore) || riskScore < 0 || riskScore > 100) {
        return res.status(400).json({ error: 'risk_score debe ser un entero entre 0 y 100.' });
    }
    if (details !== undefined && details !== null && typeof details !== 'string') {
        return res.status(400).json({ error: 'details debe ser texto.' });
    }

    try {
        const id = await recordScan({ targetType, targetValue, status, riskScore, details });
        return res.status(201).json({ id, message: 'Análisis registrado.' });
    } catch (error) {
        console.error(`[Cyberscan API] Error al guardar un análisis: ${error.message}`);
        return res.status(503).json({ error: 'No se pudo guardar el análisis. Verifica la conexión con MySQL.' });
    }
});

// Devuelve métricas agregadas para otros consumidores de la API.
router.get('/stats', async (req, res) => {
    try {
        const stats = await getStatistics();
        return res.json(stats);
    } catch (error) {
        console.error(`[Cyberscan API] Error al consultar estadísticas: ${error.message}`);
        return res.status(503).json({ error: 'No se pudieron consultar las estadísticas. Verifica la conexión con MySQL.' });
    }
});

module.exports = router;
