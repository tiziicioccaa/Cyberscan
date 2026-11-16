'use strict'; // Habilita validaciones estrictas de JavaScript en este módulo.

const express = require('express'); // Importa Express para definir un router independiente.
const pool = require('./db'); // Importa el pool MySQL propio del plugin.
const { PDFDocument, generatePdf } = require('./pdfGenerator'); // Importa la construcción del informe PDF.

const router = express.Router(); // Crea un router que el servidor principal montará bajo /api/plugin.
const allowedTypes = new Set(['url', 'file', 'email']); // Define los tipos admitidos por el esquema SQL.
const allowedStatuses = new Set(['safe', 'suspicious', 'malicious']); // Define los estados admitidos por el esquema SQL.

router.use(express.json({ limit: '16kb' })); // Analiza JSON del plugin con un límite reducido de tamaño.

function percentage(part, total) { // Calcula porcentajes sin dividir por cero.
    return total === 0 ? 0 : Number(((part / total) * 100).toFixed(2)); // Devuelve porcentaje con dos decimales.
} // Finaliza el cálculo de porcentaje.

function createStats(summaryRow, typeRows) { // Da forma consistente a las métricas de los endpoints.
    const total = Number(summaryRow.total || 0); // Normaliza el total que devuelve el driver MySQL.
    const byStatus = { // Prepara los conteos de cada estado.
        safe: Number(summaryRow.safe_count || 0), // Convierte los seguros a número.
        suspicious: Number(summaryRow.suspicious_count || 0), // Convierte los sospechosos a número.
        malicious: Number(summaryRow.malicious_count || 0), // Convierte los maliciosos a número.
    }; // Finaliza los conteos por estado.
    const byType = { url: 0, file: 0, email: 0 }; // Inicializa los tipos incluso cuando no hay registros.
    typeRows.forEach((row) => { byType[row.target_type] = Number(row.count || 0); }); // Agrega cada conteo agrupado por tipo.
    const statusMetrics = Object.fromEntries( // Convierte conteos a objetos con cantidad y porcentaje.
        Object.entries(byStatus).map(([status, count]) => [status, { count, percentage: percentage(count, total) }]), // Calcula cada porcentaje.
    ); // Finaliza la estructura de métricas por estado.
    const typeMetrics = Object.fromEntries( // Convierte conteos por tipo a métricas completas.
        Object.entries(byType).map(([type, count]) => [type, { count, percentage: percentage(count, total) }]), // Calcula cada porcentaje.
    ); // Finaliza la estructura de métricas por tipo.
    const threatCount = byStatus.suspicious + byStatus.malicious; // Agrupa resultados que requieren atención.
    return { // Devuelve la estructura pública compartida por stats y PDF.
        total, // Expone el número global de análisis.
        byStatus: statusMetrics, // Expone conteos y porcentajes para cada estado.
        byType: typeMetrics, // Expone conteos y porcentajes para URL, archivo y correo.
        threatDetectionRate: percentage(threatCount, total), // Expone sospechosos más maliciosos sobre el total.
        averageRiskScore: Number(summaryRow.average_risk_score || 0), // Expone la media del puntaje de riesgo.
    }; // Finaliza el objeto de métricas.
} // Finaliza la normalización de estadísticas.

async function getStatistics(connection = pool) { // Consulta agregados y los normaliza para respuestas y PDF.
    const [summaryRows] = await connection.query( // Cuenta estados y calcula el riesgo promedio en una consulta.
        "SELECT COUNT(*) AS total, SUM(status = 'safe') AS safe_count, SUM(status = 'suspicious') AS suspicious_count, SUM(status = 'malicious') AS malicious_count, AVG(risk_score) AS average_risk_score FROM scan_logs", // Mantiene el query en SQL parametrizable y acotado.
    ); // Finaliza la consulta agregada.
    const [typeRows] = await connection.query( // Agrupa análisis por el tipo almacenado.
        'SELECT target_type, COUNT(*) AS count FROM scan_logs GROUP BY target_type', // Solo lee columnas agregadas.
    ); // Finaliza el agregado por tipo.
    return createStats(summaryRows[0], typeRows); // Devuelve métricas estructuradas.
} // Finaliza la consulta compartida.

router.post('/log-scan', async (req, res) => { // Registra un análisis enviado por el frontend o por otro cliente.
    const { target_type: targetType, target_value: rawTarget, status, risk_score: rawRisk, details } = req.body || {}; // Extrae los campos esperados con nombres SQL.
    const targetValue = typeof rawTarget === 'string' ? rawTarget.trim() : ''; // Normaliza el objetivo recibido.
    const riskScore = Number(rawRisk); // Convierte el puntaje para poder validarlo como entero.
    if (!allowedTypes.has(targetType)) { // Verifica el tipo antes de consultar MySQL.
        return res.status(400).json({ error: "target_type debe ser 'url', 'file' o 'email'." }); // Devuelve error de validación explícito.
    } // Finaliza validación del tipo.
    if (!allowedStatuses.has(status)) { // Verifica el estado permitido por el enum.
        return res.status(400).json({ error: "status debe ser 'safe', 'suspicious' o 'malicious'." }); // Devuelve error de validación explícito.
    } // Finaliza validación del estado.
    if (!targetValue || targetValue.length > 255) { // Asegura un objetivo no vacío y compatible con VARCHAR(255).
        return res.status(400).json({ error: 'target_value es obligatorio y debe tener hasta 255 caracteres.' }); // Rechaza objetivos inválidos.
    } // Finaliza validación del objetivo.
    if (!Number.isInteger(riskScore) || riskScore < 0 || riskScore > 100) { // Valida rango y formato entero del riesgo.
        return res.status(400).json({ error: 'risk_score debe ser un entero entre 0 y 100.' }); // Rechaza puntajes fuera de rango.
    } // Finaliza validación del riesgo.
    if (details !== undefined && details !== null && typeof details !== 'string') { // Acepta únicamente texto en los detalles.
        return res.status(400).json({ error: 'details debe ser texto.' }); // Rechaza tipos de datos incorrectos.
    } // Finaliza validación del detalle.

    const safeDetails = String(details || '').trim().slice(0, 10000); // Limita el texto para evitar registros excesivamente grandes.
    try { // Ejecuta el INSERT con parámetros para prevenir inyección SQL.
        const [result] = await pool.execute( // Inserta únicamente columnas validadas.
            'INSERT INTO scan_logs (target_type, target_value, status, risk_score, details) VALUES (?, ?, ?, ?, ?)', // Usa placeholders en cada campo externo.
            [targetType, targetValue, status, riskScore, safeDetails], // Vincula valores de forma segura.
        ); // Finaliza el INSERT parametrizado.
        return res.status(201).json({ id: result.insertId, message: 'Análisis registrado.' }); // Confirma el id generado.
    } catch (error) { // Gestiona errores de base de datos sin exponerlos al cliente.
        console.error(`[Cyberscan Plugin] Error al guardar un análisis: ${error.message}`); // Conserva detalles técnicos en consola.
        return res.status(503).json({ error: 'No se pudo guardar el análisis. Verifica la conexión con MySQL.' }); // Informa indisponibilidad de almacenamiento.
    } // Finaliza manejo del INSERT.
}); // Finaliza endpoint POST de registro.

router.get('/stats', async (req, res) => { // Devuelve métricas generales de análisis.
    try { // Consulta las métricas y responde en JSON.
        const stats = await getStatistics(); // Lee los agregados almacenados.
        return res.json(stats); // Devuelve totales, porcentajes y distribuciones.
    } catch (error) { // Gestiona errores de disponibilidad de MySQL.
        console.error(`[Cyberscan Plugin] Error al consultar estadísticas: ${error.message}`); // Registra el detalle técnico en el servidor.
        return res.status(503).json({ error: 'No se pudieron consultar las estadísticas. Verifica la conexión con MySQL.' }); // Devuelve un error seguro y accionable.
    } // Finaliza manejo del endpoint de estadísticas.
}); // Finaliza endpoint GET de métricas.

router.get('/report/pdf', async (req, res) => { // Genera un informe ejecutivo descargable desde los registros actuales.
    try { // Lee resumen e historial antes de iniciar la descarga.
        const stats = await getStatistics(); // Obtiene las métricas globales del informe.
        const [history] = await pool.query( // Lee el historial completo necesario para el detalle.
            'SELECT id, target_type, target_value, status, risk_score, details, created_at FROM scan_logs ORDER BY created_at DESC, id DESC', // Ordena de lo más reciente a lo más antiguo.
        ); // Finaliza la consulta del historial.
        const document = new PDFDocument({ size: 'A4', margins: { top: 48, right: 48, bottom: 52, left: 48 }, bufferPages: false }); // Crea un PDF A4 con márgenes ejecutivos.
        document.on('error', (error) => { // Maneja fallos durante la escritura del flujo PDF.
            console.error(`[Cyberscan Plugin] Error al generar PDF: ${error.message}`); // Conserva el error en los logs del backend.
            if (!res.headersSent) res.status(500).end('No se pudo generar el informe PDF.'); // Responde con error si todavía no comenzó la descarga.
            else res.destroy(error); // Cierra la conexión si el flujo ya comenzó a transmitirse.
        }); // Finaliza el listener de errores del PDF.
        res.setHeader('Content-Type', 'application/pdf'); // Marca el contenido como PDF.
        res.setHeader('Content-Disposition', 'attachment; filename="Reporte_Ciberseguridad.pdf"'); // Fuerza la descarga con el nombre solicitado.
        res.setHeader('Cache-Control', 'no-store'); // Evita guardar el informe en cachés compartidas.
        document.pipe(res); // Transmite el documento al navegador sin escribir archivos temporales.
        generatePdf(document, { stats, history }); // Construye encabezado, análisis, métricas e historial.
        document.end(); // Finaliza el documento para completar la descarga.
    } catch (error) { // Gestiona errores de consultas previas a la generación.
        console.error(`[Cyberscan Plugin] Error al preparar el PDF: ${error.message}`); // Registra el error interno.
        return res.status(503).json({ error: 'No se pudo preparar el informe. Verifica la conexión con MySQL.' }); // Informa indisponibilidad antes de iniciar el PDF.
    } // Finaliza el manejo del endpoint de reporte.
}); // Finaliza endpoint GET de descarga PDF.

module.exports = router; // Expone exclusivamente las rutas para montarlas desde server.js.
