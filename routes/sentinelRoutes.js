'use strict';

const express = require('express');
const { authenticate } = require('./authRoutes');
const {
    addPolicy,
    deletePolicy,
    evaluateResource,
    getChatHistory,
    getPolicies,
    saveChatExchange,
} = require('../services/sentinelService');

const router = express.Router();

router.use(express.json({ limit: '16kb' }));
router.use(authenticate);

function asyncRoute(handler) {
    return (req, res, next) => Promise.resolve(handler(req, res, next)).catch(next);
}

router.get('/chat/history', asyncRoute(async (req, res) => {
    return res.json({ messages: await getChatHistory(req.account.id) });
}));

router.post('/chat', asyncRoute(async (req, res) => {
    const question = typeof (req.body && req.body.question) === 'string' ? req.body.question.trim() : '';
    if (!question || question.length > 1000) {
        return res.status(400).json({ error: 'La pregunta es obligatoria y debe tener hasta 1000 caracteres.' });
    }

    return res.json(await saveChatExchange(req.account.id, question));
}));

router.get('/policies', asyncRoute(async (req, res) => {
    return res.json({ policies: await getPolicies() });
}));

router.post('/policies/evaluate', asyncRoute(async (req, res) => {
    const resource = typeof (req.body && req.body.resource) === 'string' ? req.body.resource.trim() : '';
    if (!resource || resource.length > 2048) {
        return res.status(400).json({ error: 'El recurso es obligatorio y debe tener hasta 2048 caracteres.' });
    }

    return res.json(await evaluateResource(req.account.id, resource));
}));

router.post('/policies', asyncRoute(async (req, res) => {
    const body = req.body || {};
    const policy = {
        targetType: typeof body.targetType === 'string' ? body.targetType.toUpperCase() : '',
        pattern: typeof body.pattern === 'string' ? body.pattern.trim().toLowerCase() : '',
        action: typeof body.action === 'string' ? body.action.toUpperCase() : '',
        riskLevel: Number(body.riskLevel),
        description: typeof body.description === 'string' ? body.description.trim() : '',
    };

    if (!['DOMINIO', 'EXTENSION', 'PALABRA_CLAVE'].includes(policy.targetType)) {
        return res.status(400).json({ error: 'El tipo debe ser DOMINIO, EXTENSION o PALABRA_CLAVE.' });
    }
    if (!['BLOQUEAR', 'PERMITIR'].includes(policy.action)) {
        return res.status(400).json({ error: 'La acción debe ser BLOQUEAR o PERMITIR.' });
    }
    if (!policy.pattern || policy.pattern.length > 255 || !policy.description || policy.description.length > 1000
        || !Number.isInteger(policy.riskLevel) || policy.riskLevel < 0 || policy.riskLevel > 100) {
        return res.status(400).json({ error: 'Completa el patrón, la descripción y un riesgo entero entre 0 y 100.' });
    }

    try {
        const id = await addPolicy(policy);
        return res.status(201).json({ id, message: 'Política registrada.' });
    } catch (error) {
        if (error.code === 'ER_DUP_ENTRY') {
            return res.status(409).json({ error: 'Ya existe una política con ese patrón.' });
        }
        throw error;
    }
}));

router.delete('/policies/:id', asyncRoute(async (req, res) => {
    const id = Number(req.params.id);
    if (!Number.isInteger(id) || id <= 0) {
        return res.status(400).json({ error: 'El ID de la política debe ser un entero positivo.' });
    }

    const deleted = await deletePolicy(id);
    return deleted
        ? res.status(204).end()
        : res.status(404).json({ error: 'No se encontró la política.' });
}));

router.use((error, req, res, next) => {
    console.error(`[Cyberscan Sentinel] Error en la API: ${error.message}`);
    return res.status(503).json({ error: 'No se pudo completar la operación. Verifica la conexión con MySQL e inténtalo nuevamente.' });
});

module.exports = router;
