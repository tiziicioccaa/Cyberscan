'use strict';

const crypto = require('crypto');
const { promisify } = require('util');
const express = require('express');
const multer = require('multer');
const pool = require('../database/db');

const router = express.Router();
const scrypt = promisify(crypto.scrypt);
const SESSION_DURATION_MS = 7 * 24 * 60 * 60 * 1000;
const SESSION_TOKEN_BYTES = 32;
const avatarUpload = multer({
    storage: multer.memoryStorage(),
    limits: { fileSize: 2 * 1024 * 1024 },
    fileFilter: (req, file, callback) => {
        const supportedTypes = new Set(['image/jpeg', 'image/png', 'image/gif', 'image/webp']);
        if (!supportedTypes.has(file.mimetype)) {
            return callback(new Error('La foto debe ser JPG, PNG, GIF o WebP.'));
        }
        return callback(null, true);
    },
});

router.use(express.json({ limit: '16kb' }));

function asyncRoute(handler) {
    return (req, res, next) => Promise.resolve(handler(req, res, next)).catch(next);
}

function publicAccount(row) {
    return {
        id: row.id,
        user: row.username,
        email: row.email,
        avatar: row.avatar || null,
    };
}

async function hashPassword(password) {
    const salt = crypto.randomBytes(16);
    const derivedKey = await scrypt(password, salt, 64);
    return `scrypt$${salt.toString('hex')}$${derivedKey.toString('hex')}`;
}

async function verifyPassword(password, storedHash) {
    const [algorithm, saltHex, keyHex] = String(storedHash || '').split('$');
    if (algorithm !== 'scrypt' || !saltHex || !keyHex) return false;

    const salt = Buffer.from(saltHex, 'hex');
    const expectedKey = Buffer.from(keyHex, 'hex');
    if (salt.length !== 16 || expectedKey.length !== 64) return false;

    const actualKey = await scrypt(password, salt, expectedKey.length);
    return crypto.timingSafeEqual(actualKey, expectedKey);
}

function hashSessionToken(token) {
    return crypto.createHash('sha256').update(token).digest('hex');
}

async function createSession(accountId, connection = pool) {
    const token = crypto.randomBytes(SESSION_TOKEN_BYTES).toString('hex');
    const tokenHash = hashSessionToken(token);
    const expiresAt = new Date(Date.now() + SESSION_DURATION_MS);

    await connection.execute('DELETE FROM auth_sessions WHERE expires_at <= CURRENT_TIMESTAMP');
    await connection.execute(
        'INSERT INTO auth_sessions (account_id, token_hash, expires_at) VALUES (?, ?, ?)',
        [accountId, tokenHash, expiresAt],
    );

    return token;
}

const authenticate = asyncRoute(async (req, res, next) => {
    const authorization = req.get('authorization') || '';
    const match = authorization.match(/^Bearer ([a-f0-9]{64})$/i);
    if (!match) return res.status(401).json({ error: 'Inicia sesión para continuar.' });

    const tokenHash = hashSessionToken(match[1]);
    const [rows] = await pool.execute(
        `SELECT a.id, a.username, a.email, a.avatar
         FROM auth_sessions s
         JOIN user_accounts a ON a.id = s.account_id
         WHERE s.token_hash = ? AND s.expires_at > CURRENT_TIMESTAMP
         LIMIT 1`,
        [tokenHash],
    );
    if (!rows.length) return res.status(401).json({ error: 'La sesión venció. Inicia sesión nuevamente.' });

    req.account = publicAccount(rows[0]);
    req.sessionTokenHash = tokenHash;
    return next();
});

router.post('/register', asyncRoute(async (req, res) => {
    const body = req.body || {};
    const username = typeof body.username === 'string' ? body.username.trim() : '';
    const email = typeof body.email === 'string' ? body.email.trim().toLowerCase() : '';
    const password = typeof body.password === 'string' ? body.password : '';

    if (username.length < 2 || username.length > 80) {
        return res.status(400).json({ error: 'El nombre de usuario debe tener entre 2 y 80 caracteres.' });
    }
    if (email.length > 254 || !/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email)) {
        return res.status(400).json({ error: 'Ingresa una dirección de correo con formato válido.' });
    }
    if (password.length < 8 || password.length > 128) {
        return res.status(400).json({ error: 'La contraseña debe tener entre 8 y 128 caracteres.' });
    }

    const passwordHash = await hashPassword(password);
    const connection = await pool.getConnection();
    try {
        await connection.beginTransaction();
        const [result] = await connection.execute(
            'INSERT INTO user_accounts (username, email, password_hash) VALUES (?, ?, ?)',
            [username, email, passwordHash],
        );
        const token = await createSession(result.insertId, connection);
        await connection.commit();
        return res.status(201).json({
            token,
            user: { id: result.insertId, user: username, email, avatar: null },
        });
    } catch (error) {
        try {
            await connection.rollback();
        } catch (rollbackError) {
            console.error(`[Cyberscan Auth] No se pudo revertir el registro: ${rollbackError.message}`);
        }
        if (error.code === 'ER_DUP_ENTRY') {
            return res.status(409).json({ error: 'Ya existe una cuenta registrada con ese correo.' });
        }
        throw error;
    } finally {
        connection.release();
    }
}));

router.post('/login', asyncRoute(async (req, res) => {
    const body = req.body || {};
    const email = typeof body.email === 'string' ? body.email.trim().toLowerCase() : '';
    const password = typeof body.password === 'string' ? body.password : '';
    if (!email || !password) {
        return res.status(400).json({ error: 'Ingresa tu correo y contraseña.' });
    }

    const [rows] = await pool.execute(
        'SELECT id, username, email, password_hash, avatar FROM user_accounts WHERE email = ? LIMIT 1',
        [email],
    );
    if (!rows.length || !(await verifyPassword(password, rows[0].password_hash))) {
        return res.status(401).json({ error: 'Correo o contraseña incorrectos.' });
    }

    const token = await createSession(rows[0].id);
    return res.json({ token, user: publicAccount(rows[0]) });
}));

router.get('/me', authenticate, (req, res) => res.json({ user: req.account }));

router.delete('/session', authenticate, asyncRoute(async (req, res) => {
    await pool.execute('DELETE FROM auth_sessions WHERE token_hash = ?', [req.sessionTokenHash]);
    return res.status(204).end();
}));

router.put('/profile/avatar', authenticate, avatarUpload.single('avatar'), asyncRoute(async (req, res) => {
    if (!req.file) return res.status(400).json({ error: 'Selecciona una imagen de perfil.' });

    const avatar = `data:${req.file.mimetype};base64,${req.file.buffer.toString('base64')}`;
    await pool.execute('UPDATE user_accounts SET avatar = ? WHERE id = ?', [avatar, req.account.id]);
    return res.json({ user: { ...req.account, avatar } });
}));

router.use((error, req, res, next) => {
    if (error instanceof multer.MulterError && error.code === 'LIMIT_FILE_SIZE') {
        return res.status(413).json({ error: 'La imagen de perfil no puede superar los 2 MB.' });
    }
    if (error.message === 'La foto debe ser JPG, PNG, GIF o WebP.') {
        return res.status(400).json({ error: error.message });
    }
    console.error(`[Cyberscan Auth] Error en la API de cuentas: ${error.message}`);
    return res.status(503).json({ error: 'No se pudo completar la operación de cuenta. Verifica MySQL e inténtalo nuevamente.' });
});

module.exports = router;
module.exports.authenticate = authenticate;
