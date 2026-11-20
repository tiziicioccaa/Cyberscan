/**
 * @file ws-server.js
 * @description Servidor Web Service SOAP/XML independiente (Puerto 4000).
 * Implementa el complemento (plugin) Sentinel AI para Cyberscan, proveyendo:
 *  - Evaluación preventiva de recursos (dominios, extensiones y palabras clave) contra SQLite.
 *  - Administración CRUD de políticas de seguridad mediante sobres SOAP 1.1.
 *  - Asistente conversacional de ciberseguridad con autodetección de modelos LLM en Groq Cloud
 *    y respaldo automático ante fallos de red usando la base de conocimiento local en SQLite.
 *  - Persistencia de historial de chat por usuario y bitácora de auditoría SOAP.
 */
'use strict';

// Carga automática del archivo .env local si existe (nativo en Node.js 20.12+)
try { process.loadEnvFile(); } catch (_) {}

const express = require('express');
const cors = require('cors');
const fs = require('fs');
const path = require('path');
const { allAsync, runAsync } = require('./db');

const app = express();

// Habilita peticiones cross-origin desde el frontend (puerto 5500)
app.use(cors());

// Configura el middleware para recibir el cuerpo de las peticiones SOAP en formato texto plano/XML (máx. 64 KB)
app.use(express.text({ type: ['text/xml', 'application/soap+xml', 'application/xml', '*/*'], limit: '64kb' }));

// Carga en memoria el contrato formal WSDL 1.1 del servicio al iniciar el servidor
const wsdlContent = fs.readFileSync(path.join(__dirname, 'sentinel.wsdl'), 'utf8');

/**
 * Escapa caracteres especiales de XML (&, <, >, ", ') para evitar inyección XML
 * o rupturas de estructura al construir respuestas SOAP dinámicas.
 *
 * @param {string|number} str - Valor de entrada a sanitizar.
 * @returns {string} Cadena segura para ser incrustada dentro de etiquetas XML.
 */
function escapeXml(str) {
    return String(str ?? '')
        .replace(/&/g, '&amp;')
        .replace(/</g, '&lt;')
        .replace(/>/g, '&gt;')
        .replace(/"/g, '&quot;')
        .replace(/'/g, '&apos;');
}

/**
 * Extrae el contenido textual de una etiqueta XML específica dentro de un sobre SOAP,
 * soportando prefijos de espacio de nombres opcionales (ej. <tns:recurso> o <recurso>).
 *
 * @param {string} xml - Documento XML completo recibido en la petición.
 * @param {string} tagName - Nombre de la etiqueta XML a buscar.
 * @returns {string|null} Contenido recortado de la etiqueta o null si no existe.
 */
function extractTag(xml, tagName) {
    const regex = new RegExp(`<(?:[a-zA-Z0-9_-]+:)?${tagName}[^>]*>([\\s\\S]*?)<\\/(?:[a-zA-Z0-9_-]+:)?${tagName}>`, 'i');
    const match = xml.match(regex);
    return match ? match[1].trim() : null;
}

/**
 * Envuelve un fragmento XML de respuesta dentro de la estructura estándar
 * <soap:Envelope> y <soap:Body> según la especificación SOAP 1.1.
 *
 * @param {string} bodyXml - Cuerpo XML de la operación resuelta.
 * @returns {string} Documento SOAP completo listo para ser enviado al cliente.
 */
function wrapSoapEnvelope(bodyXml) {
    return `<?xml version="1.0" encoding="UTF-8"?>
<soap:Envelope xmlns:soap="http://schemas.xmlsoap.org/soap/envelope/" xmlns:tns="http://cyberscan.local/ws/sentinel">
  <soap:Body>
    ${bodyXml}
  </soap:Body>
</soap:Envelope>`;
}

/**
 * Construye y envía una respuesta estándar de error <soap:Fault> con código HTTP 400
 * cuando el cliente envía parámetros faltantes, inválidos o una operación desconocida.
 *
 * @param {import('express').Response} res - Objeto de respuesta HTTP de Express.
 * @param {string} code - Código de falla SOAP (ej. 'soap:Client' o 'soap:Server').
 * @param {string} message - Descripción legible del error ocurrido.
 */
function sendSoapFault(res, code, message) {
    res.status(400).type('text/xml; charset=utf-8').send(wrapSoapEnvelope(`
    <soap:Fault>
      <faultcode>${escapeXml(code)}</faultcode>
      <faultstring>${escapeXml(message)}</faultstring>
    </soap:Fault>`));
}

/**
 * Busca una respuesta en la base de conocimiento local (tabla conocimiento_ia en SQLite)
 * cuando no hay conexión a internet o la API externa de IA no está disponible (Modo Offline).
 *
 * @param {string} pregunta - Consulta realizada por el usuario.
 * @returns {Promise<{respuesta: string, fuente: string}>} Respuesta local y origen.
 */
async function buscarConocimientoLocal(pregunta) {
    const consultaNorm = pregunta.toLowerCase();
    const registros = await allAsync('SELECT palabras_clave, titulo, respuesta FROM conocimiento_ia');

    for (const item of registros) {
        const claves = item.palabras_clave.split(',').map(k => k.trim().toLowerCase());
        if (claves.some(clave => clave && consultaNorm.includes(clave))) {
            return {
                respuesta: `${item.titulo}: ${item.respuesta}`,
                fuente: 'Motor Experto Sentinel (SQLite Local)'
            };
        }
    }

    return {
        respuesta: 'Puedo ayudarte a identificar amenazas como Ransomware, Troyanos, Phishing, Gusanos, Spyware o analizar riesgos de archivos y enlaces. ¿Sobre qué amenaza específica deseas consultar?',
        fuente: 'Motor Experto Sentinel (SQLite Local)'
    };
}

/**
 * Resuelve consultas usando IA en la nube (Groq) en texto plano prolijo,
 * priorizando modelos conversacionales activos y recurriendo a SQLite local si falla la red.
 *
 * @param {string} pregunta - Consulta en lenguaje natural ingresada por el usuario.
 * @returns {Promise<{respuesta: string, fuente: string}>} Objeto con la respuesta generada y el modelo utilizado.
 */
async function generarRespuestaIA(pregunta) {
    // Lee la API Key desde el archivo .env local o variable de entorno del sistema
    const aiApiKey = process.env.GROQ_API_KEY || '';
    if (!aiApiKey) {
        return buscarConocimientoLocal(pregunta);
    }

    try {
        let candidatos = ['llama-3.3-70b-versatile', 'qwen/qwen3-32b', 'openai/gpt-oss-120b', 'openai/gpt-oss-20b'];

        // Consulta dinámica de modelos disponibles en la cuenta de Groq
        const modelsResp = await globalThis.fetch('https://api.groq.com/openai/v1/models', {
            headers: { 'Authorization': `Bearer ${aiApiKey}` }
        });

        if (modelsResp.ok) {
            const modelsData = await modelsResp.json();
            const validos = (modelsData.data || [])
                .map(m => m.id)
                .filter(id => !/whisper|guard|tts|orpheus|canopy|embed|vision|compound/i.test(id));

            // Priorizar Llama 3.3 / 3.1 primero si está disponible
            const llama = validos.filter(id => id.includes('llama'));
            const otros = validos.filter(id => !id.includes('llama'));
            if (validos.length > 0) candidatos = [...llama, ...otros];
        }

        // Itera sobre los modelos candidatos hasta obtener una respuesta válida
        for (const modelo of candidatos) {
            const resp = await globalThis.fetch('https://api.groq.com/openai/v1/chat/completions', {
                method: 'POST',
                headers: {
                    'Authorization': `Bearer ${aiApiKey}`,
                    'Content-Type': 'application/json'
                },
                body: JSON.stringify({
                    model: modelo,
                    messages: [
                        {
                            role: 'system',
                            content: 'Eres Sentinel AI, un asistente inteligente y conversacional integrado en Cyberscan. Responde en español de forma clara, directa y natural. IMPORTANTE: Escribe únicamente en texto plano sin usar Markdown (no uses asteriscos **, ni almohadillas ###, ni tablas con |, ni bloques de código). Separa las ideas con puntos y párrafos breves y concisos.'
                        },
                        { role: 'user', content: pregunta }
                    ],
                    max_tokens: 450
                })
            });

            const data = await resp.json();
            if (resp.ok) {
                let texto = data.choices?.[0]?.message?.content?.trim();
                if (texto) {
                    // Limpieza extra por si el modelo incluye algún símbolo Markdown residual
                    texto = texto
                        .replace(/<think>[\s\S]*?<\/think>/gi, '')
                        .replace(/[#*`]/g, '')
                        .replace(/\|/g, ' - ')
                        .replace(/\n{3,}/g, '\n\n')
                        .trim();

                    return {
                        respuesta: texto,
                        fuente: `IA Generativa (${modelo})`
                    };
                }
            }
        }

        return buscarConocimientoLocal(pregunta);
    } catch (err) {
        console.error('[WS Sentinel IA] Error de red, usando respaldo local:', err.message);
        return buscarConocimientoLocal(pregunta);
    }
}

/**
 * Endpoint HTTP GET /ws/sentinel
 * Devuelve el contrato formal WSDL 1.1 cuando se consulta con ?wsdl.
 */
app.get('/ws/sentinel', (req, res) => {
    if ('wsdl' in req.query) {
        return res.type('text/xml; charset=utf-8').send(wsdlContent);
    }
    res.status(200).type('text/plain').send('Web Service SOAP Sentinel activo. Consulta ?wsdl para ver el contrato.');
});

/**
 * Endpoint HTTP POST /ws/sentinel
 * Punto único de entrada del Web Service SOAP. Procesa los sobres XML y despacha
 * las operaciones EvaluarRecurso, ListarReglas, AgregarRegla, EliminarRegla,
 * ConsultarAsistenteIA y ObtenerHistorialIA.
 */
app.post('/ws/sentinel', async (req, res) => {
    const xmlBody = typeof req.body === 'string' ? req.body : '';
    if (!xmlBody.includes('Envelope')) {
        return sendSoapFault(res, 'soap:Client', 'El cuerpo de la petición no es un sobre SOAP válido.');
    }

    try {
        // 1. EvaluarRecurso: contrasta URLs o nombres de archivo contra las políticas de SQLite
        if (xmlBody.includes('EvaluarRecursoRequest')) {
            const recurso = (extractTag(xmlBody, 'recurso') || '').toLowerCase();
            if (!recurso) return sendSoapFault(res, 'soap:Client', 'Falta el parámetro obligatorio <recurso>.');

            const reglas = await allAsync('SELECT * FROM politicas_seguridad ORDER BY nivel_riesgo DESC');
            let coincidencia = null;

            for (const r of reglas) {
                const patron = r.patron.toLowerCase();
                if (r.tipo_objetivo === 'EXTENSION' && recurso.endsWith(patron)) {
                    coincidencia = r;
                    break;
                }
                if ((r.tipo_objetivo === 'DOMINIO' || r.tipo_objetivo === 'PALABRA_CLAVE') && recurso.includes(patron)) {
                    coincidencia = r;
                    break;
                }
            }

            const accion = coincidencia ? coincidencia.accion : 'SIN_REGLA';
            const nivelRiesgo = coincidencia ? coincidencia.nivel_riesgo : 10;
            const motivo = coincidencia
                ? `[Política #${coincidencia.id} - ${coincidencia.tipo_objetivo}] ${coincidencia.descripcion}`
                : 'El recurso no coincide con ninguna lista negra o blanca local. Se sugiere escaneo externo.';

            // Registra la evaluación preventiva en la bitácora de auditoría
            await runAsync(
                'INSERT INTO auditoria_ws (operacion_soap, recurso_evaluado, resultado) VALUES (?, ?, ?)',
                ['EvaluarRecurso', recurso.slice(0, 500), accion]
            );

            return res.status(200).type('text/xml; charset=utf-8').send(wrapSoapEnvelope(`
            <tns:EvaluarRecursoResponse>
              <accion>${escapeXml(accion)}</accion>
              <nivelRiesgo>${nivelRiesgo}</nivelRiesgo>
              <motivo>${escapeXml(motivo)}</motivo>
            </tns:EvaluarRecursoResponse>`));
        }

        // 2. ListarReglas: devuelve todas las políticas activas registradas en SQLite
        if (xmlBody.includes('ListarReglasRequest')) {
            const reglas = await allAsync('SELECT * FROM politicas_seguridad ORDER BY id DESC');
            const itemsXml = reglas.map(r => `
              <regla>
                <id>${r.id}</id>
                <tipoObjetivo>${escapeXml(r.tipo_objetivo)}</tipoObjetivo>
                <patron>${escapeXml(r.patron)}</patron>
                <accion>${escapeXml(r.accion)}</accion>
                <nivelRiesgo>${r.nivel_riesgo}</nivelRiesgo>
                <descripcion>${escapeXml(r.descripcion)}</descripcion>
              </regla>`).join('');

            return res.status(200).type('text/xml; charset=utf-8').send(wrapSoapEnvelope(`
            <tns:ListarReglasResponse>
              <total>${reglas.length}</total>
              <reglas>${itemsXml}</reglas>
            </tns:ListarReglasResponse>`));
        }

        // 3. AgregarRegla: valida e inserta una nueva política de seguridad en SQLite
        if (xmlBody.includes('AgregarReglaRequest')) {
            const tipoObjetivo = (extractTag(xmlBody, 'tipoObjetivo') || '').toUpperCase();
            const patron = (extractTag(xmlBody, 'patron') || '').trim().toLowerCase();
            const accion = (extractTag(xmlBody, 'accion') || '').toUpperCase();
            const nivelRiesgo = Number(extractTag(xmlBody, 'nivelRiesgo'));
            const descripcion = (extractTag(xmlBody, 'descripcion') || '').trim();

            if (!['DOMINIO', 'EXTENSION', 'PALABRA_CLAVE'].includes(tipoObjetivo)) {
                return sendSoapFault(res, 'soap:Client', 'tipoObjetivo debe ser DOMINIO, EXTENSION o PALABRA_CLAVE.');
            }
            if (!['BLOQUEAR', 'PERMITIR'].includes(accion)) {
                return sendSoapFault(res, 'soap:Client', 'accion debe ser BLOQUEAR o PERMITIR.');
            }
            if (!patron || !descripcion || Number.isNaN(nivelRiesgo) || nivelRiesgo < 0 || nivelRiesgo > 100) {
                return sendSoapFault(res, 'soap:Client', 'Datos de regla inválidos o incompletos.');
            }

            const result = await runAsync(
                'INSERT INTO politicas_seguridad (tipo_objetivo, patron, accion, nivel_riesgo, descripcion) VALUES (?, ?, ?, ?, ?)',
                [tipoObjetivo, patron, accion, nivelRiesgo, descripcion]
            );

            return res.status(200).type('text/xml; charset=utf-8').send(wrapSoapEnvelope(`
            <tns:AgregarReglaResponse>
              <id>${result.lastID}</id>
              <mensaje>Política registrada correctamente en SQLite.</mensaje>
            </tns:AgregarReglaResponse>`));
        }

        // 4. EliminarRegla: borra una política existente a partir de su ID
        if (xmlBody.includes('EliminarReglaRequest')) {
            const id = Number(extractTag(xmlBody, 'id'));
            if (!Number.isInteger(id) || id <= 0) {
                return sendSoapFault(res, 'soap:Client', 'El ID de la regla debe ser un entero positivo.');
            }
            const result = await runAsync('DELETE FROM politicas_seguridad WHERE id = ?', [id]);
            return res.status(200).type('text/xml; charset=utf-8').send(wrapSoapEnvelope(`
            <tns:EliminarReglaResponse>
              <eliminado>${result.changes > 0}</eliminado>
            </tns:EliminarReglaResponse>`));
        }

        // 5. ConsultarAsistenteIA: procesa la pregunta del usuario y guarda el historial en SQLite
        if (xmlBody.includes('ConsultarAsistenteIARequest')) {
            const usuarioEmail = (extractTag(xmlBody, 'usuarioEmail') || '').trim().toLowerCase();
            const pregunta = (extractTag(xmlBody, 'pregunta') || '').trim();

            if (!usuarioEmail || !usuarioEmail.includes('@')) {
                return sendSoapFault(res, 'soap:Client', 'Se requiere una sesión de usuario válida para consultar la IA.');
            }
            if (!pregunta || pregunta.length > 1000) {
                return sendSoapFault(res, 'soap:Client', 'La pregunta es obligatoria y debe tener hasta 1000 caracteres.');
            }

            const { respuesta, fuente } = await generarRespuestaIA(pregunta);
            await runAsync(
                'INSERT INTO historial_chat_ia (usuario_email, pregunta, respuesta, fuente) VALUES (?, ?, ?, ?)',
                [usuarioEmail, pregunta, respuesta, fuente]
            );

            return res.status(200).type('text/xml; charset=utf-8').send(wrapSoapEnvelope(`
            <tns:ConsultarAsistenteIAResponse>
              <respuesta>${escapeXml(respuesta)}</respuesta>
              <fuente>${escapeXml(fuente)}</fuente>
            </tns:ConsultarAsistenteIAResponse>`));
        }

        // 6. ObtenerHistorialIA: recupera las últimas 20 conversaciones del usuario autenticado
        if (xmlBody.includes('ObtenerHistorialIARequest')) {
            const usuarioEmail = (extractTag(xmlBody, 'usuarioEmail') || '').trim().toLowerCase();
            if (!usuarioEmail) return sendSoapFault(res, 'soap:Client', 'Falta usuarioEmail.');

            const mensajes = await allAsync(
                'SELECT pregunta, respuesta, fuente FROM historial_chat_ia WHERE usuario_email = ? ORDER BY id ASC LIMIT 20',
                [usuarioEmail]
            );
            const itemsXml = mensajes.map(m => `
              <mensaje>
                <pregunta>${escapeXml(m.pregunta)}</pregunta>
                <respuesta>${escapeXml(m.respuesta)}</respuesta>
                <fuente>${escapeXml(m.fuente)}</fuente>
              </mensaje>`).join('');

            return res.status(200).type('text/xml; charset=utf-8').send(wrapSoapEnvelope(`
            <tns:ObtenerHistorialIAResponse>
              <mensajes>${itemsXml}</mensajes>
            </tns:ObtenerHistorialIAResponse>`));
        }

        return sendSoapFault(res, 'soap:Client', 'Operación SOAP no reconocida. Consulta /ws/sentinel?wsdl');
    } catch (err) {
        console.error('[WS Sentinel] Error interno:', err.message);
        return sendSoapFault(res, 'soap:Server', err.message);
    }
});

// Inicializa el servidor SOAP en el puerto configurado (por defecto 4000)
const WS_PORT = process.env.WS_PORT || 4000;
if (require.main === module) {
    app.listen(WS_PORT, () => {
        console.log(`[WS Sentinel] Web Service SOAP escuchando en http://localhost:${WS_PORT}/ws/sentinel`);
        console.log(`[WS Sentinel] Contrato WSDL en http://localhost:${WS_PORT}/ws/sentinel?wsdl`);
    });
}

module.exports = app;
