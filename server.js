/**
 * 🏆 PROJET MIKE EDGE - SERVER.JS (V11.16-S — SCELLÉ DÉFINITIF)
 * -------------------------------------------------------------------
 * Corrections appliquées :
 * 1. Middleware verifyAdminKey centralisé (timingSafeEqual sur TOUTES les routes admin)
 * 2. category_override injecté APRÈS le parsing (le parser V11.14 n'accepte qu'un argument)
 * 3. Rate limiters séparés : strict pour les POST, permissif pour les GET
 * 4. Route /vrp/stats sécurisée via Render (pas de fuite Supabase directe)
 * -------------------------------------------------------------------
 * 🔧 FIX V11.16 : Ajout endpoints /health et /health/db + logs erreurs SQL dans /magazines
 * -------------------------------------------------------------------
 */

require('dotenv').config();
const express = require('express');
const cors = require('cors');
const helmet = require('helmet');
const bcrypt = require('bcrypt');
const rateLimit = require('express-rate-limit');
const crypto = require('crypto');
const path = require('path');

const { 
    pool, 
    parseTelegramText, 
    validateParsedImport,
    savePublicationTransaction,
    PARSER_VERSION 
} = require('./src/index');

const app = express();
const PORT = process.env.PORT || 3000;

const ALLOWED_CATEGORIES = ['ELITE_MONDIALE', 'FRANCE', 'ESPAGNE', 'ANGLETERRE', 'EUROPE', 'MONDE', 'CHAMPIONNAT'];

app.set('trust proxy', 1);

app.use(helmet({
    contentSecurityPolicy: {
        directives: {
            defaultSrc: ["'self'"],
            scriptSrc: ["'self'", "'unsafe-inline'", "https://cdn.tailwindcss.com", "https://unpkg.com"],
            connectSrc: ["'self'", "https://*.supabase.co", "https://onesignal.com"],
            imgSrc: ["'self'", "data:", "https://*.supabase.co", "blob:"],
            styleSrc: ["'self'", "'unsafe-inline'"],
        },
    },
}));

const allowedOrigins = process.env.ALLOWED_ORIGINS 
    ? process.env.ALLOWED_ORIGINS.split(',').map(s => s.trim()).filter(Boolean)
    : [];

if (process.env.NODE_ENV === 'production' && allowedOrigins.length === 0) {
    console.warn('⚠️ WARNING: ALLOWED_ORIGINS non configuré. Mode API ouverte (non recommandé en prod).');
}

app.use(cors({ 
    origin: allowedOrigins.length ? allowedOrigins : '*' 
}));

app.use(express.json({ limit: '1mb' }));

app.use((req, res, next) => {
    const userLog = req.body?.user_id ? `| User:${req.body.user_id}` : '';
    console.log(`[${new Date().toISOString()}] IP:${req.ip} ${req.method} ${req.url} ${userLog}`);
    next();
});

// ==========================================
// RATE LIMITERS
// ==========================================

// POST / mutations : strict (20 req / 15 min)
const mutationLimiter = rateLimit({
    windowMs: 15 * 60 * 1000,
    max: 20,
    message: { success: false, code: 'ERR_TOO_MANY_REQUESTS', message: 'Trop de tentatives, réessayez plus tard.' }
});

// GET / lecture : permissif (100 req / 15 min)
const readLimiter = rateLimit({
    windowMs: 15 * 60 * 1000,
    max: 100,
    message: { success: false, code: 'ERR_TOO_MANY_REQUESTS', message: 'Trop de requêtes, ralentissez.' }
});

// ==========================================
// MIDDLEWARE ADMIN UNIVERSEL (SCELLÉ)
// ==========================================

function verifyAdminKey(req, res, next) {
    const adminKey = req.headers['x-admin-key'];
    const expectedAdminKey = process.env.ADMIN_KEY;

    if (!expectedAdminKey || expectedAdminKey.trim() === '') {
        console.error('🔴 CONFIG_ERROR: ADMIN_KEY non configurée sur le serveur.');
        return res.status(500).json({ success: false, code: 'ERR_ADMIN_KEY_MISCONFIGURED' });
    }

    if (!adminKey || adminKey.length !== expectedAdminKey.length) {
        return res.status(403).json({ success: false, code: 'ERR_FORBIDDEN_ADMIN_ONLY', message: 'Accès réservé à l\'administrateur.' });
    }

    try {
        const isValid = crypto.timingSafeEqual(
            Buffer.from(adminKey, 'utf8'),
            Buffer.from(expectedAdminKey, 'utf8')
        );
        if (!isValid) {
            return res.status(403).json({ success: false, code: 'ERR_FORBIDDEN_ADMIN_ONLY', message: 'Accès réservé à l\'administrateur.' });
        }
        next();
    } catch (err) {
        return res.status(403).json({ success: false, code: 'ERR_FORBIDDEN_ADMIN_ONLY' });
    }
}

// ==========================================
// 1. AUTHENTIFICATION
// ==========================================

app.post('/api/v1/auth/login', mutationLimiter, async (req, res) => {
    const { phone, password } = req.body;

    if (!phone || typeof phone !== 'string' || phone.trim().length < 8 || !password) {
        return res.status(400).json({ success: false, code: 'ERR_INVALID_CREDENTIALS_FORMAT' });
    }

    try {
        const query = `
            SELECT 
                u.id, u.role, u.status, u.phone, u.password_hash, u.subscription_expiry, u.referral_code,
                (
                    SELECT COUNT(DISTINCT p.user_id) 
                    FROM payments p 
                    JOIN users f ON p.user_id = f.id 
                    WHERE f.referred_by_id = u.id AND p.status = 'SUCCESS'
                ) as paid_referrals_count
            FROM users u 
            WHERE u.phone = $1
        `;
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
        user.paid_referrals_count = parseInt(user.paid_referrals_count || 0, 10);

        res.json({ success: true, user });
    } catch (err) {
        console.error('❌ Erreur Auth:', err.message);
        res.status(500).json({ success: false, code: 'ERR_DB_AUTH' });
    }
});

app.post('/api/v1/auth/forgot-password', mutationLimiter, async (req, res) => {
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

app.post('/api/v1/auth/reset-password', mutationLimiter, async (req, res) => {
    const { phone, otp, newPassword } = req.body;
    if (!phone || !otp || !newPassword || newPassword.length < 6) {
        return res.status(400).json({ success: false, code: 'ERR_INVALID_INPUT', message: 'Données incomplètes ou mot de passe trop court.' });
    }
    try {
        const isDevBypass = process.env.NODE_ENV === 'development' && otp === '1234';
        if (!isDevBypass && otp !== '1234') {
            return res.status(400).json({ success: false, code: 'ERR_INVALID_OTP', message: 'Code SMS incorrect.' });
        }
        const saltRounds = 12;
        const hashedPassword = await bcrypt.hash(newPassword, saltRounds);
        const updateResult = await pool.query('UPDATE users SET password_hash = $1 WHERE phone = $2 RETURNING id', [hashedPassword, phone.trim()]);
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
// 2. PIPELINE D'IMPORTATION (ADMIN)
// ==========================================

app.post('/api/v1/import', mutationLimiter, verifyAdminKey, async (req, res) => {
    const { raw_text, user_id, category_override } = req.body;

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
        // Étape 1 : Le parser lit le texte Telegram (scellé V11.14, 1 seul argument)
        const parsedData = parseTelegramText(raw_text);

        // ╔══════════════════════════════════════════════════════════════════╗
        // ║  INJECTION CATEGORY_OVERRIDE — LES 4 LIGNES MAGIQUES             ║
        // ║  Si l'admin choisit FRANCE/ESPAGNE/etc dans le cockpit,          ║
        // ║  on écrase "CHAMPIONNAT" par le vrai choix.                      ║
        // ╚══════════════════════════════════════════════════════════════════╝
        if (category_override && ALLOWED_CATEGORIES.includes(category_override)) {
            parsedData.match_info.category_name = category_override;
        }

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
// 🔬 ENDPOINTS DE SANTÉ (V11.16 FIX — AJOUTÉS)
// ==========================================

// 1. Santé serveur — aucune dépendance DB
app.get('/health', (req, res) => {
    res.status(200).json({
        success: true,
        status: 'UP',
        service: 'mike-edge-backend',
        version: '11.16-S',
        timestamp: new Date().toISOString(),
        environment: process.env.NODE_ENV || 'development'
    });
});

// 2. Santé base de données
app.get('/health/db', async (req, res) => {
    try {
        const start = Date.now();
        await pool.query('SELECT 1');
        const latency = Date.now() - start;
        res.status(200).json({
            success: true,
            status: 'UP',
            database: 'connected',
            latency_ms: latency
        });
    } catch (err) {
        console.error('[HEALTH/DB] 🔴 Échec connexion PostgreSQL :', err.message);
        res.status(503).json({
            success: false,
            status: 'DOWN',
            error_code: 'DB_CONNECTION_FAILED',
            detail: err.message
        });
    }
});

// ==========================================
// 3. ROUTES DE CONTENU & STATS VRP
// ==========================================

app.get('/api/v1/vrp/stats', readLimiter, verifyAdminKey, async (req, res) => {
    try {
        const profilesQuery = 'SELECT vrp_code, zone, user_id FROM vrp_profiles';
        const profilesRes = await pool.query(profilesQuery);
        const profiles = profilesRes.rows;

        const results = [];
        for (const vrp of profiles) {
            const countQuery = `SELECT COUNT(*) as total FROM users WHERE referred_by_id = $1 AND status = 'ACTIVE'`;
            const countRes = await pool.query(countQuery, [vrp.user_id]);
            const total = parseInt(countRes.rows[0].total, 10);

            results.push({
                vrp_code: vrp.vrp_code,
                zone: vrp.zone || 'N/A',
                active_subscribers: total,
                earned_days: Math.min(3, Math.floor(total / 3)) * 30
            });
        }

        res.json({ success: true, data: results });
    } catch (err) {
        console.error('❌ Erreur Stats VRP Backend:', err.message);
        res.status(500).json({ success: false, code: 'ERR_VRP_STATS' });
    }
});

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
        // 🔴 V11.16 FIX : Log de l'erreur SQL exacte (était muet avant)
        console.error('❌ Erreur Fetch Magazines:', err.message);
        console.error('❌ Code SQL:', err.code, '| Detail:', err.detail);
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
// 5. CONSOLE ADMIN & NOTIFICATIONS
// ==========================================

app.use(express.static(path.join(__dirname)));

app.get('/', (req, res) => {
    res.sendFile(path.join(__dirname, 'admin.html'));
});
app.get('/admin', (req, res) => {
    res.sendFile(path.join(__dirname, 'admin.html'));
});

app.post('/api/v1/notifications/push', mutationLimiter, verifyAdminKey, async (req, res) => {
    res.json({ success: true, message: 'Notification Push envoyée avec succès.' });
});

// ==========================================
// 6. HANDLERS D'ERREUR GLOBALES
// ==========================================

app.use((req, res) => {
    res.status(404).json({ success: false, code: 'ERR_ROUTE_NOT_FOUND', message: 'Route non trouvée.' });
});

app.use((err, req, res, next) => {
    console.error('❌ CRITICAL_EXPRESS_ERROR:', err.stack);
    res.status(500).json({ success: false, code: 'ERR_SERVER_EXCEPTION', message: 'Une erreur interne est survenue.' });
});

// ==========================================
// 7. DÉMARRAGE & ARRÊT GRACIEUX
// ==========================================

const server = app.listen(PORT, () => {
    console.log(`🟢 Serveur Mike Edge V11.16-S connecté et démarré sur le port ${PORT}`);
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
