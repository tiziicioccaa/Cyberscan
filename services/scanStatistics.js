'use strict';

const pool = require('../database/db');

// Calcula un porcentaje seguro y redondeado para los reportes y la API.
function percentage(part, total) {
    return total === 0 ? 0 : Number(((part / total) * 100).toFixed(2));
}

// Convierte los agregados SQL a la estructura que consumen la API y el PDF.
function createStats(summaryRow, typeRows) {
    const total = Number(summaryRow.total || 0);
    const byStatus = {
        safe: Number(summaryRow.safe_count || 0),
        suspicious: Number(summaryRow.suspicious_count || 0),
        malicious: Number(summaryRow.malicious_count || 0),
    };
    const byType = { url: 0, file: 0, email: 0 };
    typeRows.forEach((row) => { byType[row.target_type] = Number(row.count || 0); });
    const statusMetrics = Object.fromEntries(
        Object.entries(byStatus).map(([status, count]) => [status, { count, percentage: percentage(count, total) }]),
    );
    const typeMetrics = Object.fromEntries(
        Object.entries(byType).map(([type, count]) => [type, { count, percentage: percentage(count, total) }]),
    );
    const threatCount = byStatus.suspicious + byStatus.malicious;
    return {
        total,
        byStatus: statusMetrics,
        byType: typeMetrics,
        threatDetectionRate: percentage(threatCount, total),
        averageRiskScore: Number(summaryRow.average_risk_score || 0),
    };
}

// Lee los conteos de análisis y calcula sus distribuciones por tipo y estado.
async function getStatistics(connection = pool) {
    const [summaryRows] = await connection.query(
        "SELECT COUNT(*) AS total, SUM(status = 'safe') AS safe_count, SUM(status = 'suspicious') AS suspicious_count, SUM(status = 'malicious') AS malicious_count, AVG(risk_score) AS average_risk_score FROM scan_logs",
    );
    const [typeRows] = await connection.query(
        'SELECT target_type, COUNT(*) AS count FROM scan_logs GROUP BY target_type',
    );
    return createStats(summaryRows[0], typeRows);
}

module.exports = { getStatistics };
