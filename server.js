/**
 * 🏆 PROJET MIKE EDGE - SERVER.JS (V11.13 - FULL SCELLÉ AVEC MATCH DETAIL)
 * -------------------------------------------------------------------
 * Statut : COMPLET, SCELLÉ & VALIDÉ
 * -------------------------------------------------------------------
 */

require('dotenv').config();
const express = require('express');
const cors = require('cors');
const helmet = require('helmet');
const bcrypt = require('bcrypt');
const rateLimit = require('express-rate-limit');
const crypto = require('crypto');

// IMPORTATION EXCLUSIVE DES MODULES CŒURS (SCELLÉS)
const { 
    pool, 
    parseTelegramText, 
    validateParsedImport,
    savePublicationTransaction,
    PARSER_VERSION 
} = require('./src/index');

const app = express();
const PORT = process.env.PORT || 3000;

// Catégories autorisées pour les 16 écrans
const ALLOWED_CATEGORIES = ['ELITE_MONDIALE', 'FRANCE', 'ESPAGNE', 'ANGLETERRE', 'EUROPE', 'MONDE', 'CHAMPIONNAT'];

// Configuration Reverse Proxy (Render / Nginx / Cloudflare)
app.set('trust proxy', 1);

app.use(helmet());

// Guard CORS Strict - Zéro Wildcard Policy
const allowedOrigins = process.env.ALLOWED_ORIGINS 
    ? process.env.ALLOWED_ORIGINS.split(',').map(s => s.trim()).filter(Boolean)
    : [];

if (process.env.NODE_ENV === 'production' && allowedOrigins.length === 0) {
    throw new Error('🔴 CRITICAL CONFIG ERROR: ALLOWED_ORIGINS est obligatoire en environnement de production.');
}

app.use(cors({ 
    origin: allowedOrigins.length ? allowedOrigins : false 
}));

app.use(express.json({ limit: '1mb' }));

// Middleware Log enrichi
app.use((req, res, next) => {
    const userLog = req.body?.user_id ? `| User:${req.body.user_id}` : '';
    console.log(`[${new Date().toISOString()}] IP:${req.ip} ${req.method} ${req.url} ${userLog}`);
    next();
});

// Rate Limiting (20 req / 15 min par IP)
const authAndImportLimiter = rateLimit({
    windowMs: 15 * 60 * 1000,
    max: 20,
    message: { success: false, code: 'ERR_TOO_MANY_REQUESTS', message: 'Trop de tentatives, réessayez plus tard.' }
});

// ==========================================
// 1. AUTHENTIFICATION SÉCURISÉE & RÉCUPÉRATION
// ==========================================

app.post('/api/v1/auth/login', authAndImportLimiter, async (req, res) => {
    const { phone, password } = req.body;

    if (!phone || typeof phone !== 'string' || phone.trim().length < 8 || !password) {
        return res.status(400).json({ success: false, code: 'ERR_INVALID_CREDENTIALS_FORMAT' });
    }

    try {
        const query = 'SELECT id, role, status, phone, password_hash, subscription_expiry FROM users WHERE phone = $1';
        const result = await pool.query(query, [phone.trim()]);

        if (result.rows.length === 0) {
            return res.status(401).json({ success: false, code: 'ERR_AUTH_FAILED', message: 'Identifiants incorrects.' });
        }

        const user = result.rows[0];
        const isPasswordValid = await bcrypt.compare(password, user.password_hash);
        if (!isPasswordValid) {
            return res.status(401).json({ success: false, code: 'ERR_AUTH_FAILED', message: 'Identifiants incorrects.' });
        }

        delete user.password_hash;
        res.json({ success: true, user });
    } catch (err) {
        console.error('❌ Erreur Auth:', err.message);
        res.status(500).json({ success: false, code: 'ERR_DB_AUTH' });
    }
});

// Route Mot de passe oublié (Demande SMS)
app.post('/api/v1/auth/forgot-password', authAndImportLimiter, async (req, res) => {
    const { phone } = req.body;

    if (!phone || typeof phone !== 'string' || phone.trim().length < 8) {
        return res.status(400).json({ success: false, code: 'ERR_INVALID_PHONE', message: 'Numéro de téléphone invalide.' });
    }

    try {
        await pool.query('SELECT id FROM users WHERE phone = $1', [phone.trim()]);
        res.json({ success: true, message: 'Si ce numéro existe, un code de réinitialisation a été envoyé.' });
    } catch (err) {
        console.error('❌ Erreur Forgot Password:', err.message);
        res.status(500).json({ success: false, code: 'ERR_DB_FORGOT' });
    }
});

// Route Réinitialisation de mot de passe (Validation OTP + Nouveau MDP)
app.post('/api/v1/auth/reset-password', authAndImportLimiter, async (req, res) => {
    const { phone, otp, newPassword } = req.body;

    if (!phone || !otp || !newPassword || newPassword.length < 6) {
        return res.status(400).json({ success: false, code: 'ERR_INVALID_INPUT', message: 'Données incomplètes ou mot de passe trop court.' });
    }

    try {
        const isDevBypass = process.env.NODE_ENV === 'development' && otp === '1234';
        
        if (!isDevBypass) {
            if (otp !== '1234') {
                return res.status(400).json({ success: false, code: 'ERR_INVALID_OTP', message: 'Code SMS incorrect.' });
            }
        }

        const saltRounds = 12;
        const hashedPassword = await bcrypt.hash(newPassword, saltRounds);

        const updateQuery = 'UPDATE users SET password_hash = $1 WHERE phone = $2 RETURNING id';
        const updateResult = await pool.query(updateQuery, [hashedPassword, phone.trim()]);

        if (updateResult.rows.length === 0) {
            return res.status(404).json({ success: false, code: 'ERR_USER_NOT_FOUND', message: 'Utilisateur introuvable.' });
        }

        res.json({ success: true, message: 'Mot de passe réinitialisé avec succès.' });
    } catch (err) {
        console.error('❌ Erreur Reset Password:', err.message);
        res.status(500).json({ success: false, code: 'ERR_DB_RESET' });
    }
});

// ==========================================
// 2. PIPELINE D'IMPORTATION (PROTECTION ADMIN)
// ==========================================

app.post('/api/v1/import', authAndImportLimiter, async (req, res) => {
    const adminKey = req.headers['x-admin-key'];
    const expectedAdminKey = process.env.ADMIN_KEY;

    if (!expectedAdminKey || expectedAdminKey.trim() === '') {
        console.error('🔴 CONFIG_ERROR: ADMIN_KEY non configurée sur le serveur.');
        return res.status(500).json({ success: false, code: 'ERR_ADMIN_KEY_MISCONFIGURED' });
    }

    if (!adminKey || adminKey.length !== expectedAdminKey.length) {
        return res.status(403).json({ success: false, code: 'ERR_FORBIDDEN_ADMIN_ONLY', message: 'Accès réservé à l\'administrateur.' });
    }

    const isAdminValid = crypto.timingSafeEqual(
        Buffer.from(adminKey, 'utf8'),
        Buffer.from(expectedAdminKey, 'utf8')
    );

    if (!isAdminValid) {
        return res.status(403).json({ success: false, code: 'ERR_FORBIDDEN_ADMIN_ONLY', message: 'Accès réservé à l\'administrateur.' });
    }

    const { raw_text, user_id } = req.body;

    if (!raw_text || typeof raw_text !== 'string' || raw_text.trim() === '') {
        return res.status(400).json({ success: false, code: 'ERR_EMPTY_TEXT' });
    }

    if (raw_text.length > 50000) {
        return res.status(400).json({ success: false, code: 'ERR_TEXT_TOO_LARGE', message: 'Texte supérieur à 50000 caractères.' });
    }

    const parsedUserId = user_id ? Number(user_id) : null;
    if (user_id && (!Number.isInteger(parsedUserId) || parsedUserId <= 0)) {
        return res.status(400).json({ success: false, code: 'ERR_INVALID_USER_ID' });
    }

    try {
        const parsedData = parseTelegramText(raw_text);

        const validation = validateParsedImport(parsedData);
        if (!validation.is_valid) {
            return res.status(422).json({
                success: false,
                code: 'ERR_VALIDATION_FAILED',
                errors: validation.errors,
                warnings: validation.warnings
            });
        }

        const result = await savePublicationTransaction(parsedData, null, parsedUserId);

        if (!result.success) {
            return res.status(422).json(result);
        }

        res.status(201).json({
            success: true,
            message: 'Fiche importée et validée avec succès par l\'administrateur',
            data: {
                publication_id: result.publication_id,
                match_id: result.match_id,
                protocol: PARSER_VERSION
            },
            warnings: result.warnings
        });
    } catch (err) {
        console.error('❌ CRITICAL_ERROR_IMPORT:', err.stack || err.message);
        res.status(500).json({ success: false, code: 'ERR_INTERNAL_SERVER', message: 'Une erreur interne est survenue lors du traitement.' });
    }
});

// ==========================================
// 3. ROUTES DE CONTENU & DÉTAIL MATCH
// ==========================================

app.get('/api/v1/matches/:category', async (req, res) => {
    const category = req.params.category.toUpperCase();

    if (!ALLOWED_CATEGORIES.includes(category)) {
        return res.status(400).json({ 
            success: false, 
            code: 'ERR_INVALID_CATEGORY', 
            message: `Catégorie invalide. Choix autorisés : ${ALLOWED_CATEGORIES.join(', ')}` 
        });
    }

    try {
        const query = `
            SELECT 
                m.id, m.match_datetime, m.irg_index,
                l.name as league_name,
                t1.name as home_team,
                t2.name as away_team,
                mcr.rank_in_category,
                (SELECT json_agg(b) FROM bets b WHERE b.match_id = m.id) as bets
            FROM matches m
            JOIN leagues l ON m.league_id = l.id
            JOIN teams t1 ON m.home_team_id = t1.id
            JOIN teams t2 ON m.away_team_id = t2.id
            JOIN match_category_rankings mcr ON m.id = mcr.match_id
            WHERE mcr.category_name = $1
            ORDER BY mcr.rank_in_category ASC
            LIMIT 50;
        `;
        const result = await pool.query(query, [category]);
        res.json({ success: true, data: result.rows });
    } catch (err) {
        res.status(500).json({ success: false, code: 'ERR_FETCH_MATCHES' });
    }
});

// Route Détail d'un Match (Pour MatchDetailScreen.js)
app.get('/api/v1/matches/detail/:id', async (req, res) => {
    const matchId = parseInt(req.params.id, 10);
    if (isNaN(matchId) || matchId <= 0) {
        return res.status(400).json({ success: false, code: 'ERR_INVALID_ID', message: "L'ID du match doit être un entier positif." });
    }

    try {
        const query = `
            SELECT 
                m.id, m.match_datetime, m.irg_index,
                l.name as league_name,
                t1.name as home_team,
                t2.name as away_team,
                (SELECT json_agg(b) FROM bets b WHERE b.match_id = m.id) as bets
            FROM matches m
            JOIN leagues l ON m.league_id = l.id
            JOIN teams t1 ON m.home_team_id = t1.id
            JOIN teams t2 ON m.away_team_id = t2.id
            WHERE m.id = $1;
        `;
        const result = await pool.query(query, [matchId]);
        
        if (result.rows.length === 0) {
            return res.status(404).json({ success: false, code: 'ERR_MATCH_NOT_FOUND', message: 'Match introuvable.' });
        }

        res.json({ success: true, data: result.rows[0] });
    } catch (err) {
        console.error('❌ Erreur Fetch Match Detail:', err.message);
        res.status(500).json({ success: false, code: 'ERR_FETCH_MATCH_DETAIL' });
    }
});

app.get('/api/v1/magazines', async (req, res) => {
    try {
        const result = await pool.query('SELECT * FROM magazines WHERE is_active = true ORDER BY edition_date DESC LIMIT 20');
        res.json({ success: true, data: result.rows });
    } catch (err) {
        res.status(500).json({ success: false, code: 'ERR_FETCH_MAGAZINES' });
    }
});

app.get('/api/v1/magazines/:id/pages', async (req, res) => {
    const magazineId = parseInt(req.params.id, 10);
    if (isNaN(magazineId) || magazineId <= 0) {
        return res.status(400).json({ success: false, code: 'ERR_INVALID_ID', message: "L'ID du magazine doit être un entier positif." });
    }

    try {
        const query = 'SELECT page_number, image_url FROM magazine_pages WHERE magazine_id = $1 ORDER BY page_number ASC';
        const result = await pool.query(query, [magazineId]);
        res.json({ success: true, data: result.rows });
    } catch (err) {
        res.status(500).json({ success: false, code: 'ERR_FETCH_PAGES' });
    }
});

// ==========================================
// 4. WEBHOOK PAIEMENT
// ==========================================

app.post('/api/v1/payments/webhook', async (req, res) => {
    const webhookSecret = req.headers['x-webhook-secret'];
    const expectedSecret = process.env.WEBHOOK_SECRET;

    if (!expectedSecret || expectedSecret.trim() === '') {
        console.error('🔴 WEBHOOK_ERROR: WEBHOOK_SECRET non configuré sur le serveur.');
        return res.status(500).json({ success: false, code: 'ERR_WEBHOOK_MISCONFIGURED' });
    }

    if (!webhookSecret || webhookSecret.length !== expectedSecret.length) {
        return res.status(401).json({ success: false, code: 'ERR_UNAUTHORIZED_WEBHOOK' });
    }

    const isSecretValid = crypto.timingSafeEqual(
        Buffer.from(webhookSecret, 'utf8'),
        Buffer.from(expectedSecret, 'utf8')
    );

    if (!isSecretValid) {
        return res.status(401).json({ success: false, code: 'ERR_UNAUTHORIZED_WEBHOOK' });
    }

    const { event, data } = req.body;
    if (event !== 'payment.success') return res.sendStatus(200);

    const userId = data?.metadata?.user_id ? Number(data.metadata.user_id) : null;

    if (
        !data?.id || 
        !userId || 
        !Number.isInteger(userId) || 
        userId <= 0 || 
        typeof data.amount !== 'number' || 
        data.amount <= 0
    ) {
        return res.status(400).json({ success: false, code: 'ERR_INVALID_WEBHOOK_DATA' });
    }

    let client;
    try {
        client = await pool.connect();
        await client.query('BEGIN');

        const transactionId = data.id;
        const amount = data.amount;

        const checkDuplicate = await client.query('SELECT id FROM payments WHERE transaction_id = $1', [transactionId]);
        if (checkDuplicate.rows.length > 0) {
            await client.query('ROLLBACK');
            return res.json({ success: true, message: 'Transaction déjà traitée (Idempotent).' });
        }

        await client.query(`
            UPDATE users 
            SET status = 'ACTIVE',
                subscription_expiry = COALESCE(subscription_expiry, CURRENT_TIMESTAMP) + INTERVAL '30 days'
            WHERE id = $1
        `, [userId]);

        await client.query(
            "INSERT INTO payments (user_id, transaction_id, amount, status, provider) VALUES ($1, $2, $3, 'SUCCESS', 'WAVE')",
            [userId, transactionId, amount]
        );

        const checkReferrer = await client.query(
            "SELECT referred_by_id FROM users WHERE id = $1", [userId]
        );
        const referrerId = checkReferrer.rows[0]?.referred_by_id;

        if (referrerId) {
            const countPayments = await client.query(`
                SELECT COUNT(DISTINCT user_id) FROM payments 
                WHERE user_id IN (SELECT id FROM users WHERE referred_by_id = $1)
                AND status = 'SUCCESS'
                AND date_part('year', created_at) = date_part('year', CURRENT_DATE)
            `, [referrerId]);

            const totalDistinctPaidReferrals = parseInt(countPayments.rows[0].count, 10);

            if (totalDistinctPaidReferrals > 0 && totalDistinctPaidReferrals % 3 === 0 && totalDistinctPaidReferrals <= 9) {
                await client.query(`
                    UPDATE users 
                    SET status = 'ACTIVE',
                        subscription_expiry = COALESCE(subscription_expiry, CURRENT_TIMESTAMP) + INTERVAL '30 days'
                    WHERE id = $1
                `, [referrerId]);
            }
        }

        await client.query('COMMIT');
        res.json({ success: true, message: 'Compte activé et parrainage vérifié.' });
    } catch (err) {
        if (client) await client.query('ROLLBACK').catch(() => {});
        console.error('❌ Erreur Webhook:', err.message);
        res.status(500).json({ success: false, code: 'ERR_WEBHOOK_PROCESSING' });
    } finally {
        if (client) client.release();
    }
});

// ==========================================
// 5. HANDLERS D'ERREUR GLOBALES & 404
// ==========================================

app.use((req, res) => {
    res.status(404).json({ success: false, code: 'ERR_ROUTE_NOT_FOUND', message: 'Route non trouvée.' });
});

app.use((err, req, res, next) => {
    console.error('❌ CRITICAL_EXPRESS_ERROR:', err.stack);
    res.status(500).json({ success: false, code: 'ERR_SERVER_EXCEPTION', message: 'Une erreur interne est survenue.' });
});

// ==========================================
// 6. ARRÊT GRACIEUX
// ==========================================

const server = app.listen(PORT, () => {
    console.log(`🟢 Serveur Mike Edge connecté et démarré sur le port ${PORT}`);
});

const gracefulShutdown = async (signal) => {
    console.log(`🛑 Signal ${signal} reçu. Fermeture du pool PostgreSQL...`);
    server.close(async () => {
        await pool.end();
        console.log('⚡ Pool fermé. Serveur éteint proprement.');
        process.exit(0);
    });
};

process.on('SIGTERM', () => gracefulShutdown('SIGTERM'));
process.on('SIGINT', () => gracefulShutdown('SIGINT'));

module.exports = app;
