const express = require('express');
const cors = require('cors');
const fetch = require('node-fetch');
const multer = require('multer');
const FormData = require('form-data');
const crypto = require('crypto');
const { recordScan } = require('./database/scanLogs');

const app = express();
// Habilita llamadas desde el frontend y decodifica JSON con un límite para reducir cargas excesivas.
app.use(cors());
app.use(express.json({ limit: '16kb' }));

// Publica las rutas de escaneos y estadísticas bajo su prefijo de API existente.
app.use('/api/plugin', require('./routes/scanRoutes'));
// Mantiene la descarga PDF separada del resto de las rutas del plugin.
app.use('/api/plugin', require('./cyberscan-plugin/pdfRoutes'));
// Publica las rutas de registro, inicio/cierre de sesión y perfil de usuario.
app.use('/api/auth', require('./routes/authRoutes'));
// Integra Sentinel en la misma API y reutiliza la sesión y el pool MySQL existentes.
app.use('/api/sentinel', require('./routes/sentinelRoutes'));

// Mantiene los archivos en memoria durante la petición y rechaza cargas mayores a 25 MB.
const upload = multer({ storage: multer.memoryStorage(), limits: { fileSize: 25 * 1024 * 1024 } });

// Las credenciales se leen del entorno para no incluirlas en el código fuente.
const apiKey = process.env.VIRUSTOTAL_API_KEY;
const hibpApiKey = process.env.HIBP_API_KEY;

if (!apiKey) {
    console.warn('VIRUSTOTAL_API_KEY no está configurada: los escaneos VirusTotal responderán con HTTP 503; el plugin PDF seguirá disponible.');
}
if (!hibpApiKey) {
    console.warn('HIBP_API_KEY no está configurada: las consultas de filtraciones responderán con HTTP 503.');
}

// Resume las estadísticas de un proveedor en una categoría y un puntaje de riesgo.
function getScanAssessment(stats) {
    const counts = Object.values(stats || {}).reduce((total, value) => total + (Number(value) || 0), 0);
    const malicious = Number(stats && stats.malicious) || 0;
    const suspicious = Number(stats && stats.suspicious) || 0;
    return {
        status: malicious > 0 ? 'malicious' : suspicious > 0 ? 'suspicious' : 'safe',
        riskScore: counts ? Math.min(100, Math.round(((malicious + suspicious * 0.5) / counts) * 100)) : 0,
    };
}

// Reduce y serializa los hallazgos de VirusTotal para almacenarlos en el historial.
function getVirusTotalDetails(stats, results, metadata) {
    const allDetections = Object.entries(results || {})
        .filter(([, result]) => result && (result.category === 'malicious' || result.category === 'suspicious'))
        .map(([engine, result]) => ({
            engine: engine.slice(0, 100),
            category: result.category,
            result: typeof result.result === 'string' ? result.result.slice(0, 200) : null,
        }));
    return JSON.stringify({
        provider: 'VirusTotal',
        stats,
        detections: allDetections.slice(0, 40),
        detectionsTruncated: allDetections.length > 40,
        metadata,
    });
}

// Guarda en MySQL el resultado ya normalizado de un análisis de URL o archivo.
async function saveVirusTotalScan(targetType, targetValue, stats, results, metadata) {
    const assessment = getScanAssessment(stats);
    return recordScan({
        targetType,
        targetValue,
        status: assessment.status,
        riskScore: assessment.riskScore,
        details: getVirusTotalDetails(stats, results, metadata),
    });
}

// Consulta VirusTotal por URL; si aún no existe, solicita un análisis y vuelve a consultarlo.
app.get('/analizar', async (req, res) => {
    const urlToAnalyze = typeof req.query.url === 'string' ? req.query.url.trim() : '';
    if (!urlToAnalyze) return res.status(400).json({ error: 'Falta la URL' });
    if (urlToAnalyze.length > 2048) return res.status(400).json({ error: 'La URL supera los 2048 caracteres.' });
    let parsedUrl;
    try {
        parsedUrl = new URL(urlToAnalyze);
    } catch (error) {
        return res.status(400).json({ error: 'La URL no tiene un formato válido.' });
    }
    if (!['http:', 'https:'].includes(parsedUrl.protocol)) {
        return res.status(400).json({ error: 'Solo se admiten URLs http o https.' });
    }
    if (!apiKey) return res.status(503).json({ error: 'El escaneo de URL requiere configurar VIRUSTOTAL_API_KEY.' });

    try {
        const urlId = Buffer.from(urlToAnalyze).toString('base64').replace(/=/g, '').replace(/\+/g, '-').replace(/\//g, '_');
        const headers = { 'x-apikey': apiKey };
        let response = await fetch(`https://www.virustotal.com/api/v3/urls/${urlId}`, { headers });

        if (response.status === 404) {
            const form = new URLSearchParams({ url: urlToAnalyze });
            response = await fetch('https://www.virustotal.com/api/v3/urls', {
                method: 'POST',
                headers: { ...headers, 'Content-Type': 'application/x-www-form-urlencoded' },
                body: form.toString(),
            });
            if (!response.ok) return res.status(502).json({ error: 'VirusTotal no pudo iniciar el análisis de la URL.' });
            await response.json();
            await new Promise(resolve => setTimeout(resolve, 15000));
            response = await fetch(`https://www.virustotal.com/api/v3/urls/${urlId}`, { headers });
        }
        if (!response.ok) return res.status(502).json({ error: 'No se pudo obtener el resultado de VirusTotal.' });

        const data = await response.json();
        const attributes = data.data.attributes;
        const stats = attributes.last_analysis_stats;
        const analyzedEngines = Object.values(stats || {}).reduce((total, count) => total + (Number(count) || 0), 0);
        if (!analyzedEngines) {
            return res.status(202).json({ status: 'En proceso', message: 'VirusTotal todavía está analizando la URL. Inténtalo nuevamente en unos segundos.' });
        }
        try {
            await saveVirusTotalScan('url', urlToAnalyze, stats, attributes.last_analysis_results, {
                title: attributes.title || null,
                url: attributes.url || urlToAnalyze,
            });
        } catch (error) {
            console.error(`[Cyberscan Plugin] No se pudo guardar el análisis de URL: ${error.message}`);
            return res.status(503).json({ error: 'La URL se analizó, pero no se pudo guardar el resultado en MySQL.' });
        }
        return res.json({
            status: 'Encontrado',
            stats,
            results: attributes.last_analysis_results,
            meta: { title: attributes.title, url: attributes.url },
        });
    } catch (error) {
        console.error(`[Cyberscan] Error al analizar URL: ${error.message}`);
        return res.status(502).json({ error: 'No se pudo completar el análisis de la URL.' });
    }
});

// Recibe un archivo, lo envía a VirusTotal, espera su análisis y persiste el resultado.
app.post('/analizar-archivo', upload.single('file'), async (req, res) => {
    if (!req.file) return res.status(400).json({ error: 'No se subió ningún archivo' });
    if (!apiKey) return res.status(503).json({ error: 'El escaneo de archivos requiere configurar VIRUSTOTAL_API_KEY.' });

    console.log(`Recibiendo archivo: ${req.file.originalname}`);

    try {
        const formData = new FormData();
        formData.append('file', req.file.buffer, req.file.originalname);

        const uploadResp = await fetch('https://www.virustotal.com/api/v3/files', {
            method: 'POST',
            headers: { 'x-apikey': apiKey, ...formData.getHeaders() },
            body: formData
        });

        if (!uploadResp.ok) return res.status(502).json({ error: 'VirusTotal no pudo recibir el archivo.' });
        
        const uploadData = await uploadResp.json();
        const analysisId = uploadData.data.id;
        let analysisResp;
        let analysisData;
        for (let attempt = 0; attempt < 4; attempt += 1) {
            if (attempt > 0) await new Promise(resolve => setTimeout(resolve, 20000));
            analysisResp = await fetch(`https://www.virustotal.com/api/v3/analyses/${analysisId}`, {
                headers: { 'x-apikey': apiKey }
            });
            if (!analysisResp.ok) return res.status(502).json({ error: 'No se pudo obtener el resultado del análisis en VirusTotal.' });
            analysisData = await analysisResp.json();
            if (analysisData.data.attributes.status === 'completed') break;
        }
        
        const attributes = analysisData.data.attributes;
        if (attributes.status !== 'completed') {
            return res.status(202).json({ status: 'En proceso', message: 'VirusTotal todavía está analizando el archivo. Inténtalo nuevamente más tarde.' });
        }
        const stats = attributes.stats;
        const sha256 = crypto.createHash('sha256').update(req.file.buffer).digest('hex');
        const metadata = {
            fileName: req.file.originalname,
            sha256,
            fileInfo: analysisData.meta && analysisData.meta.file_info ? analysisData.meta.file_info : null,
        };
        try {
            await saveVirusTotalScan('file', req.file.originalname, stats, attributes.results, metadata);
        } catch (error) {
            console.error(`[Cyberscan Plugin] No se pudo guardar el análisis del archivo: ${error.message}`);
            return res.status(503).json({ error: 'El archivo se analizó, pero no se pudo guardar el resultado en MySQL.' });
        }

        return res.json({
            status: 'Encontrado',
            stats,
            results: attributes.results,
            meta: { file_info: metadata.fileInfo || { sha256 } },
        });

    } catch (error) {
        console.error(`[Cyberscan] Error al analizar archivo: ${error.message}`);
        return res.status(502).json({ error: 'No se pudo completar el análisis del archivo.' });
    }
});

// Consulta Have I Been Pwned para un correo y guarda un resumen de las filtraciones encontradas.
app.post('/api/plugin/scan-email', async (req, res) => {
    const email = req.body && typeof req.body.email === 'string' ? req.body.email.trim() : '';
    if (!/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email) || email.length > 254) {
        return res.status(400).json({ error: 'Ingresa una dirección de correo válida.' });
    }
    if (!hibpApiKey) {
        return res.status(503).json({ error: 'La consulta de filtraciones requiere configurar HIBP_API_KEY en el servidor.' });
    }

    try {
        const response = await fetch(`https://haveibeenpwned.com/api/v3/breachedAccount/${encodeURIComponent(email)}?truncateResponse=false`, {
            headers: {
                'hibp-api-key': hibpApiKey,
                'user-agent': 'Cyberscan breach-check',
            },
            timeout: 15000,
        });
        let breaches = [];
        if (response.status === 200) {
            breaches = await response.json();
            if (!Array.isArray(breaches)) throw new Error('Respuesta inesperada de HIBP.');
        } else if (response.status !== 404) {
            console.error(`[Cyberscan] HIBP respondió HTTP ${response.status}.`);
            return res.status(502).json({ error: 'El proveedor de filtraciones no pudo completar la consulta. Inténtalo más tarde.' });
        }

        const status = breaches.length ? 'suspicious' : 'safe';
        const riskScore = breaches.length ? Math.min(100, 25 + breaches.length * 10) : 0;
        const results = breaches.map(breach => ({
            name: breach.Name,
            domain: breach.Domain || null,
            breachDate: breach.BreachDate || null,
            dataClasses: breach.DataClasses || [],
        }));
        const storedBreaches = results.slice(0, 25).map(breach => ({
            ...breach,
            dataClasses: breach.dataClasses.slice(0, 12).map(dataClass => String(dataClass).slice(0, 80)),
        }));
        const details = JSON.stringify({
            provider: 'Have I Been Pwned',
            breachCount: results.length,
            breaches: storedBreaches,
            truncated: results.length > storedBreaches.length,
        });
        let id;
        try {
            id = await recordScan({
                targetType: 'email',
                targetValue: email,
                status,
                riskScore,
                details,
            });
        } catch (error) {
            console.error(`[Cyberscan Plugin] No se pudo guardar el análisis del correo: ${error.message}`);
            return res.status(503).json({ error: 'El correo se consultó, pero no se pudo guardar el resultado en MySQL.' });
        }
        return res.json({ id, status, breachCount: results.length, breaches: results });
    } catch (error) {
        console.error(`[Cyberscan] Error al consultar HIBP: ${error.message}`);
        return res.status(502).json({ error: 'No se pudo completar la consulta de filtraciones.' });
    }
});

// Inicia el servidor HTTP en el puerto indicado por el entorno o en el puerto local por defecto.
const PORT = process.env.PORT || 3000;
app.listen(PORT, () => console.log(`Servidor escuchando en puerto ${PORT}`));
