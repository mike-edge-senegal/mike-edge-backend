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
    contentSecurityPolicy: false,
}));

const allowedOrigins = process.env.ALLOWED_ORIGINS 
    ? process.env.ALLOWED_ORIGINS.split(',').map(s => s.trim()).filter(Boolean)
    : [];

if (process.env.NODE_ENV === 'production' && allowedOrigins.length === 0) {
    throw new Error('🔴 CRITICAL CONFIG ERROR: ALLOWED_ORIGINS obligatoire en production.');
}

app.use(cors({ origin: allowedOrigins.length ? allowedOrigins : false }));

app.use(express.json({ limit: '1mb' }));

app.use((req, res, next) => {
    const userLog = req.body?.user_id ? `| User:${req.body.user_id}` : '';
    console.log(`[${new Date().toISOString()}] IP:${req.ip} ${req.method} ${req.url} ${userLog}`);
    next();
});

const authLimiter = rateLimit({
    windowMs: 15 * 60 * 1000,
    max: 20,
    message: { success: false, code: 'ERR_TOO_MANY_REQUESTS', message: 'Trop de tentatives.' }
});

const adminLimiter = rateLimit({
    windowMs: 1 * 60 * 1000,
    max: 60,
    message: { success: false, code: 'ERR_TOO_MANY_REQUESTS', message: 'Limite d\'import atteinte.' }
});

// ==========================================
// 1. SERVIR LA CONSOLE ADMIN
// ==========================================
app.get('/admin.html', (req, res) => {
    res.sendFile(path.join(__dirname, 'admin.html'), (err) => {
        if (err) {
            console.error('Erreur chargement admin.html:', err.message);
            res.status(404).json({ success: false, code: 'ERR_ADMIN_PAGE_NOT_FOUND' });
        }
    });
});

// ==========================================
// 2. AUTHENTIFICATION SÉCURISÉE
// ==========================================
app.post('/api/v1/auth/login', authLimiter, async (req, res) => {
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
        console.error('Erreur Auth:', err.message);
        res.status(500).json({ success: false, code: 'ERR_DB_AUTH' });
    }
});

app.post('/api/v1/auth/register', authLimiter, async (req, res) => {
    const { phone, password, vrp_code } = req.body;

    if (!phone || typeof phone !== 'string' || phone.trim().length < 8 || !password || password.length < 6) {
        return res.status(400).json({ success: false, code: 'ERR_INVALID_REGISTER_DATA' });
    }

    const cleanPhone = phone.trim();

    try {
        const checkPhone = await pool.query('SELECT id FROM users WHERE phone = $1', [cleanPhone]);
        if (checkPhone.rows.length > 0) {
            return res.status(409).json({ success: false, code: 'ERR_PHONE_ALREADY_EXISTS', message: 'Ce numero est deja inscrit.' });
        }

        let referredById = null;
        if (vrp_code && typeof vrp_code === 'string' && vrp_code.trim() !== '') {
            const cleanVrpCode = vrp_code.trim().toUpperCase();
            const vrpRes = await pool.query('SELECT user_id FROM vrp_profiles WHERE vrp_code = $1', [cleanVrpCode]);
            if (vrpRes.rows.length > 0) {
                referredById = vrpRes.rows[0].user_id;
            } else {
                const userVrpRes = await pool.query('SELECT id FROM users WHERE phone = $1', [cleanVrpCode]);
                if (userVrpRes.rows.length > 0) {
                    referredById = userVrpRes.rows[0].id;
                }
            }
        }

        const saltRounds = 10;
        const passwordHash = await bcrypt.hash(password, saltRounds);

        const insertQuery = `
            INSERT INTO users (phone, password_hash, referred_by_id, vrp_code_used, status, role)
            VALUES ($1, $2, $3, $4, 'INACTIVE', 'SUBSCRIBER')
            RETURNING id, phone, status;
        `;
        const newUser = await pool.query(insertQuery, [cleanPhone, passwordHash, referredById, vrp_code || null]);

        res.status(201).json({
            success: true,
            message: 'Compte cree. Un code OTP a ete envoye.',
            user_id: newUser.rows[0].id,
            phone: newUser.rows[0].phone
        });
    } catch (err) {
        console.error('Erreur Register:', err.message);
        res.status(500).json({ success: false, code: 'ERR_REGISTER_FAILED' });
    }
});

app.post('/api/v1/auth/verify-otp', authLimiter, async (req, res) => {
    const { phone, otp_code } = req.body;

    if (!phone || !otp_code || otp_code.trim().length < 4) {
        return res.status(400).json({ success: false, code: 'ERR_INVALID_OTP_FORMAT' });
    }

    try {
        let isOtpValid = false;

        if (process.env.NODE_ENV !== 'production' && (otp_code.trim() === '1234' || otp_code.trim() === '123456')) {
            isOtpValid = true;
        } else {
            const otpResult = await pool.query(`
                SELECT id FROM otp_codes 
                WHERE phone = $1 AND code = $2 AND expires_at > NOW() AND used = false
            `, [phone.trim(), otp_code.trim()]);

            if (otpResult.rows.length > 0) {
                isOtpValid = true;
                await pool.query('UPDATE otp_codes SET used = true WHERE id = $1', [otpResult.rows[0].id]);
            }
        }

        if (isOtpValid) {
            const updateResult = await pool.query(`
                UPDATE users 
                SET status = 'ACTIVE',
                    subscription_expiry = GREATEST(COALESCE(subscription_expiry, CURRENT_TIMESTAMP), CURRENT_TIMESTAMP) + INTERVAL '30 days'
                WHERE phone = $1
                RETURNING id, phone, role, status, subscription_expiry;
            `, [phone.trim()]);

            if (updateResult.rows.length === 0) {
                return res.status(404).json({ success: false, code: 'ERR_USER_NOT_FOUND' });
            }

            return res.json({
                success: true,
                message: 'OTP Valide ! Votre mois de decouverte gratuit est actif.',
                user: updateResult.rows[0]
            });
        }

        res.status(401).json({ success: false, code: 'ERR_WRONG_OTP', message: 'Code OTP incorrect ou expiré.' });
    } catch (err) {
        console.error('Erreur Verify OTP:', err.message);
        res.status(500).json({ success: false, code: 'ERR_OTP_VERIFICATION_FAILED' });
    }
});

// ==========================================
// 3. PIPELINE D'IMPORTATION
// ==========================================
app.post('/api/v1/import', adminLimiter, async (req, res) => {
    const adminKey = req.headers['x-admin-key'];
    const expectedAdminKey = process.env.ADMIN_KEY;

    if (!expectedAdminKey || expectedAdminKey.trim() === '') {
        console.error('CONFIG_ERROR: ADMIN_KEY non configuree.');
        return res.status(500).json({ success: false, code: 'ERR_ADMIN_KEY_MISCONFIGURED' });
    }

    if (!adminKey || adminKey.length !== expectedAdminKey.length) {
        return res.status(403).json({ success: false, code: 'ERR_FORBIDDEN_ADMIN_ONLY' });
    }

    const isAdminValid = crypto.timingSafeEqual(
        Buffer.from(adminKey, 'utf8'),
        Buffer.from(expectedAdminKey, 'utf8')
    );

    if (!isAdminValid) {
        return res.status(403).json({ success: false, code: 'ERR_FORBIDDEN_ADMIN_ONLY' });
    }

    const { raw_text, user_id, category_override } = req.body;

    if (!raw_text || typeof raw_text !== 'string' || raw_text.trim() === '') {
        return res.status(400).json({ success: false, code: 'ERR_EMPTY_TEXT' });
    }

    if (raw_text.length > 50000) {
        return res.status(400).json({ success: false, code: 'ERR_TEXT_TOO_LARGE' });
    }

    const parsedUserId = user_id ? Number(user_id) : null;
    if (user_id && (!Number.isInteger(parsedUserId) || parsedUserId <= 0)) {
        return res.status(400).json({ success: false, code: 'ERR_INVALID_USER_ID' });
    }

    try {
        const parsedData = parseTelegramText(raw_text);

        if (category_override && ALLOWED_CATEGORIES.includes(category_override)) {
            parsedData.match_info.category_name = category_override;
        }

        const validation = validateParsedImport(parsedData);
        if (!validation.is_valid) {
            return res.status(422).json({
                success: false,
                code: 'ERR_VALIDATION_FAILED',
                errors: validation.errors
            });
        }

        const result = await savePublicationTransaction(parsedData, null, parsedUserId);

        if (!result.success) {
            return res.status(422).json(result);
        }

        res.status(201).json({
            success: true,
            message: 'Fiche importee avec succes',
            data: {
                publication_id: result.publication_id,
                match_id: result.match_id,
                protocol: PARSER_VERSION
            }
        });
    } catch (err) {
        console.error('CRITICAL_ERROR_IMPORT:', err.stack || err.message);
        res.status(500).json({ success: false, code: 'ERR_INTERNAL_SERVER' });
    }
});

// ==========================================
// 4. ROUTES DE CONTENU
// ==========================================
app.get('/api/v1/matches/:category', async (req, res) => {
    const category = req.params.category.toUpperCase();

    if (!ALLOWED_CATEGORIES.includes(category)) {
        return res.status(400).json({ 
            success: false, 
            code: 'ERR_INVALID_CATEGORY', 
            message: `Categorie invalide. Choix : ${ALLOWED_CATEGORIES.join(', ')}` 
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
        return res.status(400).json({ success: false, code: 'ERR_INVALID_ID' });
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
// 5. WEBHOOK PAIEMENT
// ==========================================
app.post('/api/v1/payments/webhook', async (req, res) => {
    const webhookSecret = req.headers['x-webhook-secret'];
    const expectedSecret = process.env.WEBHOOK_SECRET;

    if (!expectedSecret || expectedSecret.trim() === '') {
        console.error('WEBHOOK_ERROR: WEBHOOK_SECRET non configure.');
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

    if (!data?.id || !userId || !Number.isInteger(userId) || userId <= 0 || typeof data.amount !== 'number' || data.amount <= 0) {
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
            return res.json({ success: true, message: 'Transaction deja traitee.' });
        }

        await client.query(`
            UPDATE users 
            SET status = 'ACTIVE',
                subscription_expiry = GREATEST(COALESCE(subscription_expiry, CURRENT_TIMESTAMP), CURRENT_TIMESTAMP) + INTERVAL '30 days'
            WHERE id = $1
        `, [userId]);

        await client.query(
            "INSERT INTO payments (user_id, transaction_id, amount, status, provider) VALUES ($1, $2, $3, 'SUCCESS', 'WAVE')",
            [userId, transactionId, amount]
        );

        const checkReferrer = await client.query("SELECT referred_by_id FROM users WHERE id = $1", [userId]);
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
                    SET subscription_expiry = GREATEST(COALESCE(subscription_expiry, CURRENT_TIMESTAMP), CURRENT_TIMESTAMP) + INTERVAL '30 days'
                    WHERE id = $1
                `, [referrerId]);
                console.log(`Recompense parrainage : +30 jours pour le parrain ID ${referrerId}`);
            }
        }

        await client.query('COMMIT');
        res.json({ success: true, message: 'Compte active et parrainage verifie.' });
    } catch (err) {
        if (client) await client.query('ROLLBACK').catch(() => {});
        console.error('Erreur Webhook:', err.message);
        res.status(500).json({ success: false, code: 'ERR_WEBHOOK_PROCESSING' });
    } finally {
        if (client) client.release();
    }
});

// ==========================================
// 6. ERREURS & LANCEMENT
// ==========================================
app.use((req, res) => {
    res.status(404).json({ success: false, code: 'ERR_ROUTE_NOT_FOUND', message: 'Route non trouvee.' });
});

app.use((err, req, res, next) => {
    console.error('CRITICAL_EXPRESS_ERROR:', err.stack);
    res.status(500).json({ success: false, code: 'ERR_SERVER_EXCEPTION' });
});

const server = app.listen(PORT, () => {
    console.log(`SERVEUR MIKE EDGE V12.2 ACTIF | PORT: ${PORT}`);
});

const gracefulShutdown = async (signal) => {
    console.log(`Signal ${signal} recu. Fermeture du pool...`);
    server.close(async () => {
        await pool.end();
        console.log('Pool ferme. Serveur eteint.');
        process.exit(0);
    });
};

process.on('SIGTERM', () => gracefulShutdown('SIGTERM'));
process.on('SIGINT', () => gracefulShutdown('SIGINT'));

module.exports = app;
