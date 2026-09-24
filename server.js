/**
 * 🏆 PROJET MIKE EDGE - SERVER.JS (V11.18.8 — F-4.3 RESEND OTP)
 * -------------------------------------------------------------------
 * (Historique V11.18.7 conservé — non reproduit intégralement)
 *
 * F-4.2 : Introduction du système OTP de production.
 *   - AUTH_MODE=TEST : comportement 1234 conservé (aucun accès à otp_codes)
 *   - AUTH_MODE=PRODUCTION : OTP 6 chiffres + bcrypt + 10 min + 5 tentatives
 *
 * F-4.3 : Ajout de la route POST /auth/resend-otp
 *   - Permet à un utilisateur existant de redemander un code OTP
 *   - Aucun impact sur /register, /verify-otp, /login, /forgot-password, /reset-password
 *   - Mode TEST : vérifie l'utilisateur, ne touche pas otp_codes
 *   - Mode PRODUCTION : advisory lock + invalidation ancien OTP + nouveau OTP + SMS
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
const multer = require('multer');
const { createClient } = require('@supabase/supabase-js');

const {
    pool,
    parseTelegramText,
    validateParsedImport,
    savePublicationTransaction,
    PARSER_VERSION
} = require('./src/index');

// 🆕 F-4.2 : modules OTP
const config = require('./src/config');
const { StubSmsProvider } = require('./src/smsProvider');

const app = express();
const PORT = process.env.PORT || 3000;

// 🆕 F-4.2 : provider SMS (STUB uniquement en phase actuelle)
const smsProvider = new StubSmsProvider();

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
// SUPABASE ADMIN (service_role) — KIOSQUE HD / FLASH HD / TICKET HD
// ==========================================
const supabaseAdmin = createClient(
    process.env.SUPABASE_URL,
    process.env.SUPABASE_SERVICE_ROLE_KEY
);

const upload = multer({
    storage: multer.memoryStorage(),
    limits: { fileSize: 10 * 1024 * 1024 },
    fileFilter: (req, file, cb) => {
        if (file.mimetype.startsWith('image/')) {
            cb(null, true);
        } else {
            cb(new Error('Seules les images sont acceptées.'), false);
        }
    }
});

// ==========================================
// RATE LIMITERS
// ==========================================

const mutationLimiter = rateLimit({
    windowMs: 15 * 60 * 1000,
    max: 20,
    message: { success: false, code: 'ERR_TOO_MANY_REQUESTS', message: 'Trop de tentatives, réessayez plus tard.' }
});

const readLimiter = rateLimit({
    windowMs: 15 * 60 * 1000,
    max: 100,
    message: { success: false, code: 'ERR_TOO_MANY_REQUESTS', message: 'Trop de requêtes, ralentissez.' }
});

// ==========================================
// MIDDLEWARE ADMIN UNIVERSEL
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
// 🆕 F-4.2 — HELPERS OTP
// ==========================================

/**
 * Génère un OTP numérique de longueur fixe, à zéro initial conservé.
 * Utilise crypto.randomInt (source cryptographiquement sûre).
 * Ex : generateOtp(6) peut retourner "007421".
 */
function generateOtp(length) {
    const max = Math.pow(10, length);
    const n = crypto.randomInt(0, max);
    return String(n).padStart(length, '0');
}

/**
 * Tronque un numéro de téléphone pour les logs.
 * Ex : "771234567" → "77****567"
 */
function maskPhone(phone) {
    const s = String(phone || '');
    if (s.length < 5) return '****';
    return `${s.slice(0, 2)}****${s.slice(-3)}`;
}

// ==========================================
// 1. AUTHENTIFICATION
// ==========================================

// --- REGISTER (F-4.2 : bifurcation TEST / PRODUCTION) ---
app.post('/api/v1/auth/register', mutationLimiter, async (req, res) => {
    const { phone, password, vrp_code, referral_code } = req.body;

    if (!phone || typeof phone !== 'string' || phone.trim().length < 8 || !password) {
        return res.status(400).json({ success: false, code: 'ERR_INVALID_CREDENTIALS_FORMAT' });
    }

    if (password.length < 6) {
        return res.status(400).json({ success: false, code: 'ERR_PASSWORD_TOO_SHORT', message: 'Mot de passe trop court (minimum 6 caractères).' });
    }

    const cleanPhone = phone.trim();

    try {
        // Vérifier si l'utilisateur existe déjà
        const existingUser = await pool.query('SELECT id FROM users WHERE phone = $1', [cleanPhone]);
        if (existingUser.rows.length > 0) {
            return res.status(409).json({ success: false, code: 'ERR_USER_EXISTS', message: 'Ce numéro est déjà enregistré.' });
        }

        // Résolution du code VRP
        const codeToUse = vrp_code || referral_code || null;
        let referredById = null;

        if (codeToUse) {
            const vrpResult = await pool.query(
                'SELECT id FROM users WHERE referral_code = $1 AND role = $2',
                [codeToUse, 'VRP']
            );
            if (vrpResult.rows.length > 0) {
                referredById = vrpResult.rows[0].id;
                console.log('[REGISTER] VRP rattaché avec le code:', codeToUse);
            } else {
                console.warn('[REGISTER] Code VRP invalide:', codeToUse);
            }
        }

        const hashedPassword = await bcrypt.hash(password, config.OTP_BCRYPT_ROUNDS);
        const newReferralCode = 'ME' + Date.now().toString(36).toUpperCase() + Math.random().toString(36).substring(2, 6).toUpperCase();

        // =====================================================
        // MODE TEST : comportement historique conservé (1234)
        // =====================================================
        if (config.AUTH_MODE === 'TEST') {
            const insertResult = await pool.query(
                `INSERT INTO users (phone, password_hash, role, status, referral_code, referred_by_id, subscription_expiry)
                 VALUES ($1, $2, $3, $4, $5, $6, $7)
                 RETURNING id, phone, role, status, referral_code, subscription_expiry`,
                [cleanPhone, hashedPassword, 'SUBSCRIBER', 'ACTIVE', newReferralCode, referredById, new Date(Date.now() + 30 * 24 * 60 * 60 * 1000)]
            );
            const newUser = insertResult.rows[0];
            delete newUser.password_hash;

            return res.status(201).json({
                success: true,
                user: newUser,
                otp_length: config.OTP_TEST_LENGTH
            });
        }

        // =====================================================
        // MODE PRODUCTION
        // =====================================================
        let otp = generateOtp(config.OTP_PRODUCTION_LENGTH);
        const otpHash = await bcrypt.hash(otp, config.OTP_BCRYPT_ROUNDS);

        const client = await pool.connect();
        let newUser;

        try {
            await client.query('BEGIN');

            const insertResult = await client.query(
                `INSERT INTO users (phone, password_hash, role, status, referral_code, referred_by_id, subscription_expiry)
                 VALUES ($1, $2, $3, $4, $5, $6, $7)
                 RETURNING id, phone, role, status, referral_code, subscription_expiry`,
                [cleanPhone, hashedPassword, 'SUBSCRIBER', 'ACTIVE', newReferralCode, referredById, new Date(Date.now() + 30 * 24 * 60 * 60 * 1000)]
            );
            newUser = insertResult.rows[0];
            delete newUser.password_hash;

            await client.query(
                `UPDATE otp_codes
                 SET used = true, consumed_at = NOW()
                 WHERE phone = $1
                   AND used = false
                   AND consumed_at IS NULL
                   AND expires_at > NOW()`,
                [cleanPhone]
            );

            await client.query(
                `INSERT INTO otp_codes (phone, code_hash, expires_at, used, created_at, attempts, consumed_at)
                 VALUES ($1, $2, NOW() + ($3 * INTERVAL '1 minute'), false, NOW(), 0, NULL)`,
                [cleanPhone, otpHash, config.OTP_EXPIRATION_MINUTES]
            );

            await client.query('COMMIT');
        } catch (txErr) {
            await client.query('ROLLBACK').catch(() => {});

            if (txErr && txErr.code === '23505') {
                return res.status(409).json({ success: false, code: 'ERR_USER_EXISTS', message: 'Ce numéro est déjà enregistré.' });
            }

            console.error('❌ Erreur Register (transaction PRODUCTION):', txErr.message);
            return res.status(500).json({ success: false, code: 'ERR_DB_REGISTER' });
        } finally {
            client.release();
        }

        let sms_sent = false;
        try {
            const smsResult = await smsProvider.sendOtp(cleanPhone, otp);
            sms_sent = Boolean(smsResult && smsResult.success);
        } catch (smsErr) {
            console.error('❌ Erreur envoi SMS:', smsErr.message);
            sms_sent = false;
        }

        otp = null;

        return res.status(201).json({
            success: true,
            user: newUser,
            otp_length: config.OTP_PRODUCTION_LENGTH,
            sms_sent
        });

    } catch (err) {
        console.error('❌ Erreur Register:', err.message);
        res.status(500).json({ success: false, code: 'ERR_DB_REGISTER' });
    }
});

// --- VERIFY OTP (F-4.2 : bifurcation TEST / PRODUCTION) ---
app.post('/api/v1/auth/verify-otp', mutationLimiter, async (req, res) => {
    const { phone, otp_code } = req.body;

    if (!phone || !otp_code) {
        return res.status(400).json({ success: false, code: 'ERR_INVALID_INPUT', message: 'Numéro et code requis.' });
    }

    const cleanPhone = String(phone).trim();

    // =====================================================
    // MODE TEST : comportement historique conservé (1234)
    // =====================================================
    if (config.AUTH_MODE === 'TEST') {
        try {
            if (otp_code !== '1234') {
                return res.status(400).json({ success: false, code: 'ERR_INVALID_OTP', message: 'Code SMS incorrect.' });
            }

            const result = await pool.query(
                'SELECT id, phone, role, status, referral_code, subscription_expiry FROM users WHERE phone = $1',
                [cleanPhone]
            );

            if (result.rows.length === 0) {
                return res.status(404).json({ success: false, code: 'ERR_USER_NOT_FOUND', message: 'Utilisateur introuvable.' });
            }

            return res.json({ success: true, user: result.rows[0] });
        } catch (err) {
            console.error('❌ Erreur Verify OTP (TEST):', err.message);
            return res.status(500).json({ success: false, code: 'ERR_DB_VERIFY_OTP' });
        }
    }

    // =====================================================
    // MODE PRODUCTION
    // =====================================================

    if (!/^\d{6}$/.test(String(otp_code))) {
        return res.status(400).json({ success: false, code: 'ERR_INVALID_OTP', message: 'Code OTP invalide.' });
    }

    const client = await pool.connect();

    try {
        await client.query('BEGIN');

        const otpRes = await client.query(
            `SELECT id, phone, code_hash, expires_at, used, attempts, consumed_at
             FROM otp_codes
             WHERE phone = $1
             ORDER BY created_at DESC
             LIMIT 1
             FOR UPDATE`,
            [cleanPhone]
        );

        if (otpRes.rows.length === 0) {
            await client.query('ROLLBACK');
            return res.status(400).json({ success: false, code: 'ERR_INVALID_OTP', message: 'Code OTP invalide.' });
        }

        const otpRow = otpRes.rows[0];

        if (otpRow.used === true || otpRow.consumed_at !== null) {
            await client.query('ROLLBACK');
            return res.status(400).json({ success: false, code: 'ERR_OTP_ALREADY_USED', message: 'Ce code a déjà été utilisé.' });
        }

        if (new Date(otpRow.expires_at) <= new Date()) {
            await client.query(
                `UPDATE otp_codes SET used = true, consumed_at = NOW() WHERE id = $1`,
                [otpRow.id]
            );
            await client.query('COMMIT');
            return res.status(400).json({ success: false, code: 'ERR_OTP_EXPIRED', message: 'Code OTP expiré.' });
        }

        if (otpRow.attempts >= config.OTP_MAX_ATTEMPTS) {
            await client.query(
                `UPDATE otp_codes SET used = true, consumed_at = NOW() WHERE id = $1`,
                [otpRow.id]
            );
            await client.query('COMMIT');
            return res.status(429).json({ success: false, code: 'ERR_OTP_MAX_ATTEMPTS', message: 'Trop de tentatives.' });
        }

        if (!otpRow.code_hash) {
            await client.query('ROLLBACK');
            return res.status(400).json({ success: false, code: 'ERR_INVALID_OTP', message: 'Code OTP invalide.' });
        }

        const valid = await bcrypt.compare(String(otp_code), otpRow.code_hash);

        if (!valid) {
            const newAttempts = otpRow.attempts + 1;

            if (newAttempts >= config.OTP_MAX_ATTEMPTS) {
                await client.query(
                    `UPDATE otp_codes SET attempts = $1, used = true, consumed_at = NOW() WHERE id = $2`,
                    [newAttempts, otpRow.id]
                );
                await client.query('COMMIT');
                return res.status(429).json({ success: false, code: 'ERR_OTP_MAX_ATTEMPTS', message: 'Trop de tentatives.' });
            }

            await client.query(
                `UPDATE otp_codes SET attempts = $1 WHERE id = $2`,
                [newAttempts, otpRow.id]
            );
            await client.query('COMMIT');
            return res.status(400).json({ success: false, code: 'ERR_INVALID_OTP', message: 'Code OTP invalide.' });
        }

        await client.query(
            `UPDATE otp_codes SET used = true, consumed_at = NOW() WHERE id = $1`,
            [otpRow.id]
        );
        await client.query('COMMIT');

        const userRes = await pool.query(
            'SELECT id, phone, role, status, referral_code, subscription_expiry FROM users WHERE phone = $1',
            [cleanPhone]
        );

        if (userRes.rows.length === 0) {
            return res.status(404).json({ success: false, code: 'ERR_USER_NOT_FOUND', message: 'Utilisateur introuvable.' });
        }

        return res.json({ success: true, user: userRes.rows[0] });

    } catch (err) {
        await client.query('ROLLBACK').catch(() => {});
        console.error('❌ Erreur Verify OTP (PRODUCTION):', err.message);
        return res.status(500).json({ success: false, code: 'ERR_OTP_INTERNAL' });
    } finally {
        client.release();
    }
});

app.post('/api/v1/auth/login', mutationLimiter, async (req, res) => {
    const { phone, password } = req.body;

    if (!phone || typeof phone !== 'string' || phone.trim().length < 8 || !password) {
        return res.status(400).json({ success: false, code: 'ERR_INVALID_CREDENTIALS_FORMAT' });
    }

    try {
        const query = `
            SELECT 
                u.id, u.role, u.status, u.phone, u.password_hash, u.subscription_expiry, u.referral_code
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
        const hashedPassword = await bcrypt.hash(newPassword, 12);
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

// --- RESEND OTP (F-4.3) ---
app.post('/api/v1/auth/resend-otp', mutationLimiter, async (req, res) => {
    const { phone } = req.body;

    if (!phone || typeof phone !== 'string' || phone.trim().length < 8) {
        return res.status(400).json({ success: false, code: 'ERR_INVALID_PHONE', message: 'Numéro invalide.' });
    }

    const cleanPhone = phone.trim();

    // =====================================================
    // MODE TEST : vérifier l'utilisateur, ne pas toucher otp_codes
    // =====================================================
    if (config.AUTH_MODE === 'TEST') {
        try {
            const userCheck = await pool.query('SELECT id FROM users WHERE phone = $1', [cleanPhone]);
            if (userCheck.rows.length === 0) {
                return res.status(404).json({ success: false, code: 'ERR_USER_NOT_FOUND', message: 'Utilisateur introuvable.' });
            }

            return res.json({
                success: true,
                message: 'En mode TEST, utilisez le code 1234.',
                otp_length: config.OTP_TEST_LENGTH,
                sms_sent: false
            });
        } catch (err) {
            console.error('❌ Erreur Resend OTP (TEST):', err.message);
            return res.status(500).json({ success: false, code: 'ERR_DB_RESEND_OTP' });
        }
    }

    // =====================================================
    // MODE PRODUCTION
    // =====================================================
    const client = await pool.connect();

    try {
        await client.query('BEGIN');

        const userRes = await client.query('SELECT id FROM users WHERE phone = $1', [cleanPhone]);
        if (userRes.rows.length === 0) {
            await client.query('ROLLBACK');
            return res.status(404).json({ success: false, code: 'ERR_USER_NOT_FOUND', message: 'Utilisateur introuvable.' });
        }

        // Verrou advisory pour empêcher les resends concurrents
        await client.query('SELECT pg_advisory_xact_lock(hashtext($1))', [`otp:${cleanPhone}`]);

        // Invalider les anciens OTP actifs
        await client.query(
            `UPDATE otp_codes
             SET used = true, consumed_at = NOW()
             WHERE phone = $1
               AND used = false
               AND consumed_at IS NULL
               AND expires_at > NOW()`,
            [cleanPhone]
        );

        // Générer un nouveau code
        let otp = generateOtp(config.OTP_PRODUCTION_LENGTH);
        const otpHash = await bcrypt.hash(otp, config.OTP_BCRYPT_ROUNDS);

        // Insérer le nouvel OTP
        await client.query(
            `INSERT INTO otp_codes (phone, code_hash, expires_at, used, created_at, attempts, consumed_at)
             VALUES ($1, $2, NOW() + ($3 * INTERVAL '1 minute'), false, NOW(), 0, NULL)`,
            [cleanPhone, otpHash, config.OTP_EXPIRATION_MINUTES]
        );

        await client.query('COMMIT');

        // Envoi SMS hors transaction
        let sms_sent = false;
        try {
            const smsResult = await smsProvider.sendOtp(cleanPhone, otp);
            sms_sent = Boolean(smsResult && smsResult.success);
        } catch (smsErr) {
            console.error('❌ Erreur envoi SMS (resend-otp):', smsErr.message);
            sms_sent = false;
        }

        otp = null;

        return res.json({
            success: true,
            otp_length: config.OTP_PRODUCTION_LENGTH,
            sms_sent
        });

    } catch (err) {
        await client.query('ROLLBACK').catch(() => {});
        console.error('❌ Erreur Resend OTP (PRODUCTION):', err.message);
        return res.status(500).json({ success: false, code: 'ERR_OTP_INTERNAL' });
    } finally {
        client.release();
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
        const parsedData = parseTelegramText(raw_text);

        if (category_override && ALLOWED_CATEGORIES.includes(category_override)) {
            parsedData.match_info.category_name = category_override;
            console.log('[IMPORT] category_override injecté:', category_override);
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

        const result = await savePublicationTransaction(parsedData, null, parsedUserId, category_override);

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
// 🔬 ENDPOINTS DE SANTÉ
// ==========================================

app.get('/health', (req, res) => {
    res.status(200).json({
        success: true,
        status: 'UP',
        service: 'mike-edge-backend',
        version: '11.18.8',
        timestamp: new Date().toISOString(),
        environment: process.env.NODE_ENV || 'development'
    });
});

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
                active_subscribers: total
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
    console.log('[API] GET /matches/' + category);

    if (!ALLOWED_CATEGORIES.includes(category)) {
        console.log('[API] Catégorie invalide:', category);
        return res.status(400).json({
            success: false,
            code: 'ERR_INVALID_CATEGORY',
            message: `Catégorie invalide. Choix autorisés : ${ALLOWED_CATEGORIES.join(', ')}`
        });
    }

    try {
        const sessionQuery = `
            SELECT 
                id, 
                session_number,
                status
            FROM category_sessions
            WHERE category_name = $1
              AND status = 'ACTIVE'
            ORDER BY session_number DESC
            LIMIT 1
        `;
        const sessionResult = await pool.query(sessionQuery, [category]);

        let session = null;
        let activeCount = 0;
        const maxQuota = category === 'ELITE_MONDIALE' ? 10 : 5;

        if (sessionResult.rows.length > 0) {
            const sessionRow = sessionResult.rows[0];

            const countQuery = `
                SELECT COUNT(*) as cnt
                FROM match_category_rankings
                WHERE session_id = $1
            `;
            const countResult = await pool.query(countQuery, [sessionRow.id]);
            activeCount = parseInt(countResult.rows[0].cnt, 10);

            session = {
                id: sessionRow.id,
                number: sessionRow.session_number,
                status: sessionRow.status,
                current_count: activeCount,
                max_quota: maxQuota,
                remaining_slots: Math.max(0, maxQuota - activeCount),
                can_import: activeCount < maxQuota
            };
        } else {
            console.log('[API] Aucune session active pour', category);
            return res.json({
                success: true,
                data: [],
                session: {
                    id: null,
                    number: null,
                    status: 'NONE',
                    current_count: 0,
                    max_quota: maxQuota,
                    remaining_slots: maxQuota,
                    can_import: true
                }
            });
        }

        console.log('[API] Session active pour', category, ':', session);

        const query = `
            SELECT 
                m.id, m.match_datetime, m.irg_index,
                l.name as league_name,
                t1.name as home_team,
                t2.name as away_team,
                mcr.rank_in_category,
                COALESCE((SELECT json_agg(b) FROM bets b WHERE b.match_id = m.id), '[]'::json) as bets
            FROM match_category_rankings mcr
            LEFT JOIN matches m ON mcr.match_id::integer = m.id
            LEFT JOIN leagues l ON m.league_id = l.id
            LEFT JOIN teams t1 ON m.home_team_id = t1.id
            LEFT JOIN teams t2 ON m.away_team_id = t2.id
            WHERE mcr.category_name = $1
              AND mcr.session_id = $2
            ORDER BY m.irg_index DESC NULLS LAST
            LIMIT 50;
        `;
        const result = await pool.query(query, [category, session.id]);

        console.log('[API] Résultats pour', category, ':', result.rows.length, 'matchs (session active uniquement)');

        res.json({
            success: true,
            data: result.rows,
            session: session
        });

    } catch (err) {
        console.error('[API] 🔴 ERREUR /matches/' + category + ':', err.message);
        console.error('[API] Code SQL:', err.code, '| Detail:', err.detail);
        res.status(500).json({
            success: false,
            code: 'ERR_FETCH_MATCHES',
            message: err.message
        });
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
                COALESCE((SELECT json_agg(b) FROM bets b WHERE b.match_id = m.id), '[]'::json) as bets
            FROM matches m
            LEFT JOIN leagues l ON m.league_id = l.id
            LEFT JOIN teams t1 ON m.home_team_id = t1.id
            LEFT JOIN teams t2 ON m.away_team_id = t2.id
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
        const query = 'SELECT id, page_number, image_url FROM magazine_pages WHERE magazine_id = $1 ORDER BY page_number ASC';
        const result = await pool.query(query, [magazineId]);
        res.json({ success: true, data: result.rows });
    } catch (err) {
        res.status(500).json({ success: false, code: 'ERR_FETCH_PAGES' });
    }
});

// ==========================================
// KIOSQUE MAGAZINE HD — GESTION ADMIN (V11.18)
// ==========================================

app.get('/api/v1/admin/magazines', readLimiter, verifyAdminKey, async (req, res) => {
    try {
        const query = `
            SELECT m.id, m.title, m.edition_date, m.cover_url, m.is_active,
                   COUNT(mp.id)::int as page_count
            FROM magazines m
            LEFT JOIN magazine_pages mp ON mp.magazine_id = m.id
            WHERE m.is_active = true
            GROUP BY m.id
            ORDER BY m.edition_date DESC
        `;
        const result = await pool.query(query);
        res.json({ success: true, data: result.rows });
    } catch (err) {
        console.error('❌ Erreur admin magazines:', err.message);
        res.status(500).json({ success: false, code: 'ERR_FETCH_ADMIN_MAGAZINES' });
    }
});

app.post('/api/v1/admin/magazines', mutationLimiter, verifyAdminKey, upload.single('cover'), async (req, res) => {
    try {
        const { title, edition_date } = req.body;
        if (!title || !edition_date || !req.file) {
            return res.status(400).json({ success: false, code: 'ERR_MISSING_FIELDS', message: 'Titre, date et couverture requis.' });
        }

        const countRes = await pool.query('SELECT COUNT(*) as cnt FROM magazines WHERE is_active = true');
        if (parseInt(countRes.rows[0].cnt, 10) >= 6) {
            return res.status(403).json({ success: false, code: 'ERR_ALBUM_LIMIT_REACHED', message: 'Limite de 6 albums atteinte.' });
        }

        const file = req.file;
        const storagePath = `covers/${Date.now()}_${file.originalname}`;
        const { error: upError } = await supabaseAdmin.storage.from('magazines').upload(storagePath, file.buffer, {
            contentType: file.mimetype,
            upsert: false
        });
        if (upError) {
            console.error('❌ Erreur upload cover Storage:', upError.message);
            throw new Error('Échec upload couverture');
        }

        const { data: urlData } = supabaseAdmin.storage.from('magazines').getPublicUrl(storagePath);
        const coverUrl = urlData.publicUrl;

        const insertRes = await pool.query(
            'INSERT INTO magazines (title, edition_date, cover_url, is_active) VALUES ($1, $2, $3, true) RETURNING id, title, edition_date, cover_url, is_active',
            [title.trim(), edition_date, coverUrl]
        );

        res.status(201).json({ success: true, data: insertRes.rows[0] });
    } catch (err) {
        console.error('❌ Erreur création album:', err.message);
        res.status(500).json({ success: false, code: 'ERR_CREATE_ALBUM', message: err.message });
    }
});

app.post('/api/v1/admin/magazines/:id/pages', mutationLimiter, verifyAdminKey, upload.array('pages', 10), async (req, res) => {
    try {
        const magazineId = parseInt(req.params.id, 10);
        if (isNaN(magazineId) || magazineId <= 0) {
            return res.status(400).json({ success: false, code: 'ERR_INVALID_ID' });
        }
        if (!req.files || req.files.length === 0) {
            return res.status(400).json({ success: false, code: 'ERR_NO_FILES', message: 'Aucun fichier fourni.' });
        }

        const magCheck = await pool.query('SELECT id FROM magazines WHERE id = $1', [magazineId]);
        if (magCheck.rows.length === 0) {
            return res.status(404).json({ success: false, code: 'ERR_MAGAZINE_NOT_FOUND' });
        }

        const countRes = await pool.query('SELECT COUNT(*) as cnt FROM magazine_pages WHERE magazine_id = $1', [magazineId]);
        const currentCount = parseInt(countRes.rows[0].cnt, 10);
        if (currentCount + req.files.length > 10) {
            return res.status(403).json({ success: false, code: 'ERR_PAGE_LIMIT_REACHED', message: `Dépassement : ${currentCount + req.files.length}/10 pages max.` });
        }

        const insertedPages = [];
        const client = await pool.connect();
        try {
            await client.query('BEGIN');
            for (let i = 0; i < req.files.length; i++) {
                const file = req.files[i];
                const pageNum = currentCount + i + 1;
                const storagePath = `pages/${magazineId}/${Date.now()}_p${pageNum}_${file.originalname}`;

                const { error: upError } = await supabaseAdmin.storage.from('magazines').upload(storagePath, file.buffer, {
                    contentType: file.mimetype,
                    upsert: false
                });
                if (upError) throw upError;

                const { data: urlData } = supabaseAdmin.storage.from('magazines').getPublicUrl(storagePath);
                const imageUrl = urlData.publicUrl;

                const pageRes = await client.query(
                    'INSERT INTO magazine_pages (magazine_id, page_number, image_url) VALUES ($1, $2, $3) RETURNING id, page_number, image_url',
                    [magazineId, pageNum, imageUrl]
                );
                insertedPages.push(pageRes.rows[0]);
            }
            await client.query('COMMIT');
        } catch (err) {
            await client.query('ROLLBACK').catch(() => {});
            throw err;
        } finally {
            client.release();
        }

        res.status(201).json({ success: true, data: insertedPages });
    } catch (err) {
        console.error('❌ Erreur ajout pages:', err.message);
        res.status(500).json({ success: false, code: 'ERR_ADD_PAGES', message: err.message });
    }
});

app.put('/api/v1/magazines/:id', mutationLimiter, verifyAdminKey, async (req, res) => {
    const magazineId = parseInt(req.params.id, 10);
    const { title, edition_date } = req.body;
    if (isNaN(magazineId) || magazineId <= 0) {
        return res.status(400).json({ success: false, code: 'ERR_INVALID_ID' });
    }
    if (!title || !edition_date) {
        return res.status(400).json({ success: false, code: 'ERR_MISSING_FIELDS' });
    }
    try {
        const result = await pool.query(
            'UPDATE magazines SET title = $1, edition_date = $2 WHERE id = $3 RETURNING id',
            [title.trim(), edition_date, magazineId]
        );
        if (result.rows.length === 0) {
            return res.status(404).json({ success: false, code: 'ERR_MAGAZINE_NOT_FOUND' });
        }
        res.json({ success: true });
    } catch (err) {
        console.error('❌ Erreur update magazine:', err.message);
        res.status(500).json({ success: false, code: 'ERR_UPDATE_MAGAZINE' });
    }
});

app.delete('/api/v1/magazines/:id', mutationLimiter, verifyAdminKey, async (req, res) => {
    const magazineId = parseInt(req.params.id, 10);
    if (isNaN(magazineId) || magazineId <= 0) {
        return res.status(400).json({ success: false, code: 'ERR_INVALID_ID' });
    }
    const client = await pool.connect();
    try {
        await client.query('BEGIN');
        const magResult = await client.query('SELECT cover_url FROM magazines WHERE id = $1', [magazineId]);
        if (magResult.rows.length === 0) {
            await client.query('ROLLBACK');
            return res.status(404).json({ success: false, code: 'ERR_MAGAZINE_NOT_FOUND' });
        }
        const pagesResult = await client.query('SELECT image_url FROM magazine_pages WHERE magazine_id = $1', [magazineId]);
        const urlsToClean = [magResult.rows[0].cover_url, ...pagesResult.rows.map(r => r.image_url)].filter(Boolean);

        await client.query('DELETE FROM magazine_pages WHERE magazine_id = $1', [magazineId]);
        await client.query('DELETE FROM magazines WHERE id = $1', [magazineId]);
        await client.query('COMMIT');

        const pathsToRemove = urlsToClean.map(url => {
            const m = url.match(/\/magazines\/(.+)$/);
            return m ? m[1] : null;
        }).filter(Boolean);
        if (pathsToRemove.length > 0) {
            const { error: delError } = await supabaseAdmin.storage.from('magazines').remove(pathsToRemove);
            if (delError) console.error('❌ Erreur suppression Storage album:', delError.message);
        }

        res.json({ success: true });
    } catch (err) {
        await client.query('ROLLBACK');
        console.error('❌ Erreur suppression album:', err.message);
        res.status(500).json({ success: false, code: 'ERR_DELETE_MAGAZINE' });
    } finally {
        client.release();
    }
});

app.delete('/api/v1/magazines/pages/:pageId', mutationLimiter, verifyAdminKey, async (req, res) => {
    const pageId = parseInt(req.params.pageId, 10);
    if (isNaN(pageId) || pageId <= 0) {
        return res.status(400).json({ success: false, code: 'ERR_INVALID_ID' });
    }
    const client = await pool.connect();
    try {
        await client.query('BEGIN');
        const pageResult = await client.query(
            'SELECT image_url, magazine_id, page_number FROM magazine_pages WHERE id = $1',
            [pageId]
        );
        if (pageResult.rows.length === 0) {
            await client.query('ROLLBACK');
            return res.status(404).json({ success: false, code: 'ERR_PAGE_NOT_FOUND' });
        }
        const { image_url, magazine_id, page_number } = pageResult.rows[0];

        await client.query('DELETE FROM magazine_pages WHERE id = $1', [pageId]);
        await client.query(
            'UPDATE magazine_pages SET page_number = page_number - 1 WHERE magazine_id = $1 AND page_number > $2',
            [magazine_id, page_number]
        );
        await client.query('COMMIT');

        const pathMatch = image_url.match(/\/magazines\/(.+)$/);
        if (pathMatch) {
            const { error: delError } = await supabaseAdmin.storage.from('magazines').remove([pathMatch[1]]);
            if (delError) console.error('❌ Erreur suppression Storage page:', delError.message);
        }

        res.json({ success: true, deleted_url: image_url });
    } catch (err) {
        await client.query('ROLLBACK');
        console.error('❌ Erreur suppression page:', err.message);
        res.status(500).json({ success: false, code: 'ERR_DELETE_PAGE' });
    } finally {
        client.release();
    }
});

// ==========================================
// INFO FLASH HD — GESTION ADMIN (V11.18.2)
// ==========================================

app.get('/api/v1/admin/flash-info/status', async (req, res) => {
    try {
        const result = await pool.query('SELECT is_active, image_url FROM flash_infos LIMIT 1');
        if (result.rows.length === 0) {
            return res.json({ success: true, data: { is_active: false, image_url: null } });
        }
        res.json({ success: true, data: { is_active: result.rows[0].is_active, image_url: result.rows[0].image_url } });
    } catch (err) {
        console.error('❌ Erreur lecture statut flash:', err.message);
        res.status(500).json({ success: false, code: 'ERR_READ_FLASH_STATUS' });
    }
});

app.post('/api/v1/admin/flash-info', mutationLimiter, verifyAdminKey, upload.single('photo'), async (req, res) => {
    try {
        if (!req.file) {
            return res.status(400).json({ success: false, code: 'ERR_NO_FILE', message: 'Photo requise.' });
        }

        const file = req.file;
        const storagePath = `flash/${Date.now()}_${file.originalname}`;

        const oldRes = await pool.query('SELECT image_url FROM flash_infos LIMIT 1');
        const oldImageUrl = oldRes.rows.length > 0 ? oldRes.rows[0].image_url : null;

        const { error: upError } = await supabaseAdmin.storage.from('magazines').upload(storagePath, file.buffer, {
            contentType: file.mimetype,
            upsert: false
        });
        if (upError) {
            console.error('❌ Erreur upload flash Storage:', upError.message);
            throw new Error('Échec upload photo flash');
        }

        const { data: urlData } = supabaseAdmin.storage.from('magazines').getPublicUrl(storagePath);
        const imageUrl = urlData.publicUrl;

        if (oldRes.rows.length > 0) {
            await pool.query(
                'UPDATE flash_infos SET title = $1, message = $2, image_url = $3, is_active = $4',
                ['Info Flash', 'Flash direct', imageUrl, true]
            );
        } else {
            await pool.query(
                'INSERT INTO flash_infos (title, message, image_url, is_active) VALUES ($1, $2, $3, $4)',
                ['Info Flash', 'Flash direct', imageUrl, true]
            );
        }

        if (oldImageUrl) {
            const pathMatch = oldImageUrl.match(/\/magazines\/(.+)$/);
            if (pathMatch) {
                const { error: delError } = await supabaseAdmin.storage.from('magazines').remove([pathMatch[1]]);
                if (delError) console.error('❌ Erreur suppression ancienne photo flash:', delError.message);
            }
        }

        res.status(200).json({ success: true, data: { image_url: imageUrl, is_active: true } });
    } catch (err) {
        console.error('❌ Erreur publication flash:', err.message);
        res.status(500).json({ success: false, code: 'ERR_PUBLISH_FLASH', message: err.message });
    }
});

app.put('/api/v1/admin/flash-info/status', mutationLimiter, verifyAdminKey, async (req, res) => {
    try {
        const { is_active } = req.body;
        if (typeof is_active !== 'boolean') {
            return res.status(400).json({ success: false, code: 'ERR_INVALID_STATUS', message: 'is_active doit être un booléen.' });
        }

        const oldRes = await pool.query('SELECT id FROM flash_infos LIMIT 1');
        if (oldRes.rows.length === 0) {
            return res.status(404).json({ success: false, code: 'ERR_NO_FLASH', message: 'Aucun flash info existant. Publiez une photo d\'abord.' });
        }

        await pool.query('UPDATE flash_infos SET is_active = $1', [is_active]);

        res.json({ success: true, data: { is_active: is_active } });
    } catch (err) {
        console.error('❌ Erreur toggle flash status:', err.message);
        res.status(500).json({ success: false, code: 'ERR_TOGGLE_FLASH', message: err.message });
    }
});

// ============================================
// MODULE 4 — TICKET DE SESSION HD (V11.18.4)
// ============================================

app.get('/api/v1/admin/session-ticket', async (req, res) => {
    try {
        const result = await pool.query(
            "SELECT value FROM system_configs WHERE key = 'session_ticket_url'"
        );
        if (result.rows.length === 0) {
            return res.json({ success: true, data: null });
        }
        res.json({ success: true, data: { image_url: result.rows[0].value } });
    } catch (err) {
        console.error('[ADMIN SESSION TICKET GET]', err);
        res.status(500).json({ success: false, message: err.message });
    }
});

app.post('/api/v1/admin/session-ticket', mutationLimiter, verifyAdminKey, upload.single('photo'), async (req, res) => {
    try {
        if (!req.file) {
            return res.status(400).json({ success: false, message: 'Aucune image fournie.' });
        }

        const client = await pool.connect();
        let oldUrl = null;
        let newPublicUrl = null;

        try {
            await client.query('BEGIN');

            const oldResult = await client.query(
                "SELECT value FROM system_configs WHERE key = 'session_ticket_url'"
            );
            oldUrl = oldResult.rows[0]?.value || null;

            const fileExt = req.file.originalname.split('.').pop() || 'jpg';
            const fileName = `session_tickets/${Date.now()}_${Math.random().toString(36).substring(2, 10)}.${fileExt}`;

            const { error: uploadError } = await supabaseAdmin.storage
                .from('tickets')
                .upload(fileName, req.file.buffer, {
                    contentType: req.file.mimetype,
                    upsert: false
                });

            if (uploadError) throw new Error('Upload échoué: ' + uploadError.message);

            const { data: publicUrlData } = supabaseAdmin.storage
                .from('tickets')
                .getPublicUrl(fileName);
            newPublicUrl = publicUrlData.publicUrl;

            await client.query(
                `INSERT INTO system_configs (key, value) VALUES ('session_ticket_url', $1)
                 ON CONFLICT (key) DO UPDATE SET value = EXCLUDED.value`,
                [newPublicUrl]
            );

            await client.query('COMMIT');
        } catch (err) {
            await client.query('ROLLBACK');
            throw err;
        } finally {
            client.release();
        }

        if (oldUrl) {
            try {
                const pathMatch = oldUrl.split('/tickets/');
                if (pathMatch.length > 1) {
                    const oldPath = pathMatch.slice(1).join('/tickets/');
                    await supabaseAdmin.storage.from('tickets').remove([oldPath]);
                    console.log('[TICKET] Ancienne photo supprimée:', oldPath);
                }
            } catch (delErr) {
                console.warn('[TICKET] Échec suppression ancienne photo (non bloquant):', delErr.message);
            }
        }

        res.json({ success: true, data: { image_url: newPublicUrl, is_active: true } });
    } catch (err) {
        console.error('[ADMIN SESSION TICKET POST]', err);
        res.status(500).json({ success: false, message: err.message });
    }
});

// ==========================================
// 4. WEBHOOK PAIEMENT (V11.18.5)
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

        await client.query('COMMIT');
        res.json({ success: true, message: 'Compte activé.' });
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

app.use((err, req, res, next) => {
    if (err instanceof multer.MulterError) {
        if (err.code === 'LIMIT_FILE_SIZE') {
            return res.status(400).json({ success: false, code: 'ERR_FILE_TOO_LARGE', message: 'Fichier trop lourd (max 10Mo).' });
        }
        return res.status(400).json({ success: false, code: 'ERR_UPLOAD', message: err.message });
    }
    if (err && err.message === 'Seules les images sont acceptées.') {
        return res.status(400).json({ success: false, code: 'ERR_INVALID_FILE_TYPE', message: err.message });
    }
    next(err);
});

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
    console.log(`🟢 Serveur Mike Edge V11.18.8 connecté et démarré sur le port ${PORT}`);
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
