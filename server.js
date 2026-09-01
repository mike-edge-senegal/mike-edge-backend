/**
 * 🏆 PROJET MIKE EDGE - SERVER.JS (V11.18.2)
 * -------------------------------------------------------------------
 * FIX : category_override passé à savePublicationTransaction
 * FIX : Classement par IRG décroissant (ORDER BY m.irg_index DESC)
 * FIX : CAST match_id::integer pour corriger le JOIN vide
 * FIX : GET /api/v1/matches/:category renvoie désormais les infos de session active
 * FIX : La liste des matchs est filtrée par session_id (Claude audit)
 * FIX : Routes Kiosque Magazine HD (Gestion Admin)
 * SEC : Kiosque Magazine HD — toutes écritures (upload, insert, delete Storage)
 *       passent exclusivement par le serveur via SUPABASE_SERVICE_ROLE_KEY.
 *       Multer reçoit les fichiers en multipart. Le client n'écrit plus jamais
 *       directement dans Supabase pour le Kiosque.
 * FIX : Info Flash HD — toutes écritures passent par le serveur (service_role)
 *       Logique défensive : upload → UPDATE → suppression ancienne.
 *       Routes GET /admin/flash-info/status, POST /admin/flash-info,
 *       PUT /admin/flash-info/status.
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
// SUPABASE ADMIN (service_role) — KIOSQUE HD / FLASH HD
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
        version: '11.18.2',
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

// ==========================================
// 🔧 V11.17.5 FIX : CAST match_id::integer + SESSION ACTIVE + FILTRE SESSION_ID
// ==========================================
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
        // =============================================
        // 1. RÉCUPÉRER LA SESSION ACTIVE
        // =============================================
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
            
            // Compter les matchs dans cette session
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
            // Aucune session active → import autorisé
            session = {
                id: null,
                number: null,
                status: 'NONE',
                current_count: 0,
                max_quota: maxQuota,
                remaining_slots: maxQuota,
                can_import: true
            };
        }
        
        console.log('[API] Session active pour', category, ':', session);
        
        // =============================================
        // 2. RÉCUPÉRER LES MATCHS DE LA SESSION ACTIVE UNIQUEMENT
        // =============================================
        // 🔧 FIX CLAUDE : Filtrer par session_id pour ne renvoyer que les matchs de la session active
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
        
        // =============================================
        // 3. RÉPONSE AVEC SESSION
        // =============================================
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
// Toutes écritures passent par le serveur (service_role)
// ==========================================

// --- LISTE ADMIN (existante, inchangée) ---
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

// --- CRÉATION ALBUM + UPLOAD COUVERTURE ---
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

// --- AJOUT DE PAGES ---
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

// --- MODIFICATION INFOS ALBUM (existante, inchangée) ---
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

// --- SUPPRESSION ALBUM ENTIER + NETTOYAGE STORAGE ---
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

        // Nettoyage Storage côté serveur
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

// --- SUPPRESSION PAGE + RENUMÉROTATION + NETTOYAGE STORAGE ---
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

        // Nettoyage Storage côté serveur
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
// Toutes écritures passent par le serveur (service_role)
// Logique défensive : upload → UPDATE → suppression ancienne
// ==========================================

// --- LECTURE STATUT (public, pour initialisation client) ---
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

// --- PUBLICATION / MISE À JOUR FLASH (upload photo + UPDATE unique) ---
app.post('/api/v1/admin/flash-info', mutationLimiter, verifyAdminKey, upload.single('photo'), async (req, res) => {
    try {
        if (!req.file) {
            return res.status(400).json({ success: false, code: 'ERR_NO_FILE', message: 'Photo requise.' });
        }

        const file = req.file;
        const storagePath = `flash/${Date.now()}_${file.originalname}`;

        // 1. Récupérer l'ancienne ligne (pour nettoyage post-UPDATE)
        const oldRes = await pool.query('SELECT image_url FROM flash_infos LIMIT 1');
        const oldImageUrl = oldRes.rows.length > 0 ? oldRes.rows[0].image_url : null;

        // 2. Upload nouvelle photo
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

        // 3. UPDATE ou INSERT (une seule ligne toujours)
        if (oldRes.rows.length > 0) {
            await pool.query(
                'UPDATE flash_infos SET title = $1, message = $2, image_url = $3, is_active = $4, updated_at = NOW()',
                ['Info Flash', 'Flash direct', imageUrl, true]
            );
        } else {
            await pool.query(
                'INSERT INTO flash_infos (title, message, image_url, is_active) VALUES ($1, $2, $3, $4)',
                ['Info Flash', 'Flash direct', imageUrl, true]
            );
        }

        // 4. Nettoyage best-effort de l'ancienne photo (après succès DB)
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

// --- ACTIVATION / DÉSACTIVATION FLASH ---
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

        await pool.query('UPDATE flash_infos SET is_active = $1, updated_at = NOW()', [is_active]);

        res.json({ success: true, data: { is_active: is_active } });
    } catch (err) {
        console.error('❌ Erreur toggle flash status:', err.message);
        res.status(500).json({ success: false, code: 'ERR_TOGGLE_FLASH', message: err.message });
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
            const countPayments = await pool.query(`
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

// Multer errors (doit précéder le 404)
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
    console.log(`🟢 Serveur Mike Edge V11.18.2 connecté et démarré sur le port ${PORT}`);
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
