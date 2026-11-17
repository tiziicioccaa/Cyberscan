'use strict';

const express = require('express');
const pool = require('../database/db');
const { getStatistics } = require('../services/scanStatistics');
const { PDFDocument, generatePdf } = require('./pdfGenerator');

// Este router contiene exclusivamente la descarga del informe PDF.
const router = express.Router();

// Reúne las estadísticas y el historial y transmite el PDF sin crear archivos temporales.
router.get('/report/pdf', async (req, res) => {
    try {
        const stats = await getStatistics();
        const [history] = await pool.query(
            'SELECT id, target_type, target_value, status, risk_score, details, created_at FROM scan_logs ORDER BY created_at DESC, id DESC',
        );
        const document = new PDFDocument({ size: 'A4', margins: { top: 48, right: 48, bottom: 52, left: 48 }, bufferPages: false });
        // Si el flujo falla antes o después de iniciar la descarga, responde o cierra la conexión.
        document.on('error', (error) => {
            console.error(`[Cyberscan PDF] Error al generar PDF: ${error.message}`);
            if (!res.headersSent) res.status(500).end('No se pudo generar el informe PDF.');
            else res.destroy(error);
        });
        res.setHeader('Content-Type', 'application/pdf');
        res.setHeader('Content-Disposition', 'attachment; filename="Reporte_Ciberseguridad.pdf"');
        res.setHeader('Cache-Control', 'no-store');
        document.pipe(res);
        generatePdf(document, { stats, history });
        document.end();
    } catch (error) {
        console.error(`[Cyberscan PDF] Error al preparar el informe: ${error.message}`);
        return res.status(503).json({ error: 'No se pudo preparar el informe. Verifica la conexión con MySQL.' });
    }
});

module.exports = router;
