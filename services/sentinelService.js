'use strict';

const fetch = require('node-fetch');
const pool = require('../database/db');

const DEFAULT_MODELS = [
    'llama-3.3-70b-versatile',
    'qwen/qwen3-32b',
    'openai/gpt-oss-120b',
    'openai/gpt-oss-20b',
];

async function findLocalAnswer(question) {
    const [entries] = await pool.execute(
        'SELECT keywords, title, response FROM sentinel_knowledge_base ORDER BY id',
    );
    const normalizedQuestion = question.toLowerCase();

    for (const entry of entries) {
        const keywords = entry.keywords.split(',').map(keyword => keyword.trim().toLowerCase());
        if (keywords.some(keyword => keyword && normalizedQuestion.includes(keyword))) {
            return {
                answer: `${entry.title}: ${entry.response}`,
                source: 'Motor experto Sentinel (MySQL local)',
            };
        }
    }

    return {
        answer: 'Puedo ayudarte a identificar amenazas como ransomware, troyanos, phishing, gusanos o spyware. ¿Sobre qué amenaza específica deseas consultar?',
        source: 'Motor experto Sentinel (MySQL local)',
    };
}

async function generateAnswer(question) {
    const apiKey = process.env.GROQ_API_KEY;
    if (!apiKey) return findLocalAnswer(question);

    try {
        let models = DEFAULT_MODELS;
        const modelsResponse = await fetch('https://api.groq.com/openai/v1/models', {
            headers: { Authorization: `Bearer ${apiKey}` },
            timeout: 15000,
        });

        if (modelsResponse.ok) {
            const modelsData = await modelsResponse.json();
            const availableModels = (Array.isArray(modelsData.data) ? modelsData.data : [])
                .map(model => model.id)
                .filter(id => typeof id === 'string' && !/whisper|guard|tts|orpheus|canopy|embed|vision|compound/i.test(id));
            const llamaModels = availableModels.filter(id => id.includes('llama'));
            if (availableModels.length) {
                models = [...llamaModels, ...availableModels.filter(id => !id.includes('llama'))];
            }
        }

        for (const model of models) {
            const response = await fetch('https://api.groq.com/openai/v1/chat/completions', {
                method: 'POST',
                headers: {
                    Authorization: `Bearer ${apiKey}`,
                    'Content-Type': 'application/json',
                },
                body: JSON.stringify({
                    model,
                    messages: [
                        {
                            role: 'system',
                            content: 'Eres Sentinel AI, un asistente integrado en Cyberscan. Responde en español, de forma clara y directa, en texto plano y con párrafos breves.',
                        },
                        { role: 'user', content: question },
                    ],
                    max_tokens: 450,
                }),
                timeout: 20000,
            });

            if (!response.ok) {
                console.warn(`[Cyberscan Sentinel] Groq respondió HTTP ${response.status} para el modelo ${model}.`);
                continue;
            }

            const data = await response.json();
            const answer = data.choices && data.choices[0] && data.choices[0].message
                ? data.choices[0].message.content.trim()
                : '';
            if (answer) {
                return {
                    answer: answer.replace(/<think>[\s\S]*?<\/think>/gi, '').trim(),
                    source: `IA generativa (${model})`,
                };
            }
        }

        console.warn('[Cyberscan Sentinel] Groq no devolvió una respuesta; se utilizará el conocimiento local.');
    } catch (error) {
        console.error(`[Cyberscan Sentinel] Falló la consulta a Groq; se utilizará el conocimiento local: ${error.message}`);
    }

    return findLocalAnswer(question);
}

async function getChatHistory(accountId) {
    const [rows] = await pool.execute(
        `SELECT question, answer, source, created_at
         FROM sentinel_chat_history
         WHERE account_id = ?
         ORDER BY id DESC
         LIMIT 20`,
        [accountId],
    );
    return rows.reverse();
}

async function saveChatExchange(accountId, question) {
    const result = await generateAnswer(question);
    await pool.execute(
        'INSERT INTO sentinel_chat_history (account_id, question, answer, source) VALUES (?, ?, ?, ?)',
        [accountId, question, result.answer, result.source],
    );
    return result;
}

async function getPolicies() {
    const [rows] = await pool.execute(
        `SELECT id, target_type AS targetType, pattern, action, risk_level AS riskLevel, description
         FROM sentinel_policies
         ORDER BY id DESC`,
    );
    return rows;
}

async function addPolicy(policy) {
    const [result] = await pool.execute(
        `INSERT INTO sentinel_policies (target_type, pattern, action, risk_level, description)
         VALUES (?, ?, ?, ?, ?)`,
        [policy.targetType, policy.pattern, policy.action, policy.riskLevel, policy.description],
    );
    return result.insertId;
}

async function deletePolicy(id) {
    const [result] = await pool.execute('DELETE FROM sentinel_policies WHERE id = ?', [id]);
    return result.affectedRows > 0;
}

async function evaluateResource(accountId, resource) {
    const normalizedResource = resource.toLowerCase();
    const [policies] = await pool.execute(
        'SELECT id, target_type, pattern, action, risk_level, description FROM sentinel_policies ORDER BY risk_level DESC, id',
    );
    const matchedPolicy = policies.find((policy) => {
        const pattern = policy.pattern.toLowerCase();
        if (policy.target_type === 'EXTENSION') return normalizedResource.endsWith(pattern);
        return normalizedResource.includes(pattern);
    });

    const action = matchedPolicy ? matchedPolicy.action : 'SIN_REGLA';
    const riskLevel = matchedPolicy ? matchedPolicy.risk_level : 10;
    const reason = matchedPolicy
        ? `[Política #${matchedPolicy.id} - ${matchedPolicy.target_type}] ${matchedPolicy.description}`
        : 'El recurso no coincide con ninguna política local. Se sugiere un escaneo externo.';

    await pool.execute(
        'INSERT INTO sentinel_audit_log (account_id, operation, evaluated_resource, result) VALUES (?, ?, ?, ?)',
        [accountId, 'EvaluarRecurso', resource.slice(0, 2048), action],
    );

    return { action, riskLevel, reason };
}

module.exports = {
    addPolicy,
    deletePolicy,
    evaluateResource,
    getChatHistory,
    getPolicies,
    saveChatExchange,
};
