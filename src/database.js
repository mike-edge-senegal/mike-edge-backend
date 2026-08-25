// ============================================
// MODULE 3 : database.js — MIKE EDGE V11.17.4
// FIX : Date fallback + rank_in_category = 1 (classement par IRG côté API)
// ============================================
const { Pool } = require('pg');
const { validateParsedImport } = require('./validator');
const { PARSER_VERSION, normalizeFrenchText, REGEX_NON_DB_CHARS } = require('./parser');

// 🔒 V11.16 FIX : Support DATABASE_URL (Render/Supabase) + SSL conditionnel
const poolConfig = process.env.DATABASE_URL
  ? {
      connectionString: process.env.DATABASE_URL,
      max: 20,
      ssl: process.env.NODE_ENV === 'production'
        ? { rejectUnauthorized: false }
        : false,
      idleTimeoutMillis: 30000,
      connectionTimeoutMillis: 5000,
    }
  : {
      user: process.env.DB_USER,
      host: process.env.DB_HOST || 'localhost',
      database: process.env.DB_NAME || 'mike_edge_db',
      password: process.env.DB_PASSWORD,
      port: process.env.DB_PORT || 5432,
      max: 20,
      ssl: process.env.NODE_ENV === 'production'
        ? { rejectUnauthorized: false }
        : false,
      idleTimeoutMillis: 30000,
      connectionTimeoutMillis: 5000,
    };

const pool = new Pool(poolConfig);

// 🩺 V11.16 FIX : Test de connexion au boot (log Render immédiat)
pool.query('SELECT 1')
  .then(() => console.log('[DATABASE] ✅ Connexion PostgreSQL établie — Module 3 actif'))
  .catch((err) => {
    console.error('[DATABASE] 🔴 ÉCHEC CONNEXION PostgreSQL :', err.message);
    console.error('[DATABASE] Code :', err.code, '| Detail :', err.detail);
  });

function normalizeDatabaseName(value) {
    return normalizeFrenchText(value).replace(REGEX_NON_DB_CHARS, '');
}

// 🔧 V11.17 FIX : Auto-création de la ligue si inconnue
async function getLeagueIdStrict(client, leagueName) {
    if (!leagueName) throw new Error('ERR_UNKNOWN_LEAGUE');
    const normalized = normalizeDatabaseName(leagueName);
    const result = await client.query(
        `SELECT id FROM leagues WHERE LOWER(REGEXP_REPLACE(unaccent(name), '[^a-zA-Z0-9]', '', 'g')) = $1`,
        [normalized]
    );
    if (result.rows.length > 0) return result.rows[0].id;
    
    const insert = await client.query(
        `INSERT INTO leagues (name) VALUES ($1) RETURNING id`,
        [leagueName.trim()]
    );
    console.log('[DB AUTO] Ligue creee : ' + leagueName.trim() + ' (ID:' + insert.rows[0].id + ')');
    return insert.rows[0].id;
}

// 🔧 V11.17 FIX : Auto-création de l'équipe si inconnue
async function getTeamIdStrict(client, teamName, leagueId) {
    if (!teamName) throw new Error('ERR_UNKNOWN_TEAM');
    const normalized = normalizeDatabaseName(teamName);
    let result = await client.query(
        `SELECT id FROM teams WHERE LOWER(REGEXP_REPLACE(unaccent(name), '[^a-zA-Z0-9]', '', 'g')) = $1 AND league_id = $2`,
        [normalized, leagueId]
    );
    if (result.rows.length > 0) return result.rows[0].id;
    
    result = await client.query(
        `SELECT id FROM teams WHERE LOWER(REGEXP_REPLACE(unaccent(name), '[^a-zA-Z0-9]', '', 'g')) = $1 LIMIT 1`,
        [normalized]
    );
    if (result.rows.length > 0) return result.rows[0].id;
    
    const insert = await client.query(
        `INSERT INTO teams (name, league_id) VALUES ($1, $2) RETURNING id`,
        [teamName.trim(), leagueId]
    );
    console.log('[DB AUTO] Equipe creee : ' + teamName.trim() + ' (ID:' + insert.rows[0].id + ')');
    return insert.rows[0].id;
}

// 🔧 V11.17.4 FIX : Fallback date/heure au lieu de crash
function buildRobustIsoDatetime(dateStr, timeStr) {
    if (!dateStr || !timeStr) {
        console.warn('[DB] Date/heure manquante, fallback sur maintenant');
        return new Date();
    }
    const normalizedDate = normalizeFrenchText(dateStr);
    let year, month, day;
    const frenchDateMatch = normalizedDate.match(/(?:[\p{Letter}\p{Mark}]+\s+)?(\d{1,2})\s+(janvier|fevrier|mars|avril|mai|juin|juillet|aout|septembre|octobre|novembre|decembre)(?:\s+(\d{2,4}))?/iu);
    if (frenchDateMatch) {
        const months = { janvier: 1, fevrier: 2, mars: 3, avril: 4, mai: 5, juin: 6, juillet: 7, aout: 8, septembre: 9, octobre: 10, novembre: 11, decembre: 12 };
        day = Number(frenchDateMatch[1]);
        month = months[frenchDateMatch[2]];
        year = frenchDateMatch[3] ? (Number(frenchDateMatch[3]) < 100 ? 2000 + Number(frenchDateMatch[3]) : Number(frenchDateMatch[3])) : new Date().getUTCFullYear();
    } else {
        let numericMatch = normalizedDate.match(/^(\d{4})[-/.](\d{1,2})[-/.](\d{1,2})$/);
        if (numericMatch) {
            year = Number(numericMatch[1]);
            month = Number(numericMatch[2]);
            day = Number(numericMatch[3]);
        } else {
            numericMatch = normalizedDate.match(/^(\d{1,2})[-/.](\d{1,2})[-/.](20\d{2}|\d{2})$/);
            if (numericMatch) {
                day = Number(numericMatch[1]);
                month = Number(numericMatch[2]);
                const rawYear = Number(numericMatch[3]);
                year = rawYear < 100 ? 2000 + rawYear : rawYear;
            }
        }
    }
    if (!Number.isInteger(year) || !Number.isInteger(month) || !Number.isInteger(day) || month < 1 || month > 12 || day < 1 || day > 31) {
        console.warn('[DB] Date invalide ("' + dateStr + '"), fallback sur maintenant');
        return new Date();
    }
    const timeParts = String(timeStr).split(':');
    const hour = Number(timeParts[0]) || 0;
    const minute = Number(timeParts[1]) || 0;
    const date = new Date(Date.UTC(year, month - 1, day, hour, minute, 0, 0));
    if (date.getUTCFullYear() !== year || date.getUTCMonth() !== month - 1 || date.getUTCDate() !== day || date.getUTCHours() !== hour || date.getUTCMinutes() !== minute) {
        console.warn('[DB] Date calendaire invalide, fallback sur maintenant');
        return new Date();
    }
    return date;
}

async function insertBetRow(client, matchId, bet) {
    const isBanned = bet.section_type === 'BANNED';
    await client.query(
        `INSERT INTO bets (match_id, section_type, rank_in_section, market_name, odds, probability_pct, robustness_pct, confidence_stars, comment)
         VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9)`,
        [matchId, bet.section_type, bet.rank_in_section, bet.market_name, isBanned ? null : bet.odds, bet.probability_pct ?? null, bet.robustness_pct ?? null, isBanned ? null : bet.confidence_stars, bet.comment || null]
    );
}

// 🔧 V11.17.1 FIX : Ajout categoryOverride pour forcer la catégorie depuis le dashboard
async function savePublicationTransaction(parsedData, targetPublicationId = null, userId = null, categoryOverride = null) {
    let client;
    const startTime = Date.now();
    const validation = validateParsedImport(parsedData);
    if (!validation.is_valid)
        return { success: false, code: 'ERR_VALIDATION_FAILED', errors: validation.errors, warnings: validation.warnings };

    try {
        client = await pool.connect();
        await client.query('BEGIN');

        const leagueId = await getLeagueIdStrict(client, parsedData.match_info.league_name);
        const homeTeamId = await getTeamIdStrict(client, parsedData.match_info.home_team, leagueId);
        const awayTeamId = await getTeamIdStrict(client, parsedData.match_info.away_team, leagueId);
        const matchDatetime = buildRobustIsoDatetime(parsedData.match_info.date_str, parsedData.match_info.time_str);

        let publicationId = targetPublicationId;
        if (!publicationId) {
            const title = parsedData.publication_title || `${parsedData.match_info.home_team} vs ${parsedData.match_info.away_team} — ${parsedData.match_info.league_name}`;
            const publicationResult = await client.query(
                `INSERT INTO publications (title, start_date, end_date, status, protocol_version)
                 VALUES ($1, $2, $3, 'DRAFT', $4) RETURNING id`,
                [title, matchDatetime, new Date(matchDatetime.getTime() + 3 * 24 * 60 * 60 * 1000), PARSER_VERSION]
            );
            publicationId = publicationResult.rows[0].id;
        }

        const matchResult = await client.query(
            `INSERT INTO matches (publication_id, league_id, home_team_id, away_team_id, match_datetime, irg_index)
             VALUES ($1, $2, $3, $4, $5, $6)
             ON CONFLICT (publication_id, home_team_id, away_team_id, match_datetime) DO NOTHING RETURNING id`,
            [publicationId, leagueId, homeTeamId, awayTeamId, matchDatetime, parsedData.match_info.irg_index]
        );

        if (matchResult.rows.length === 0) {
            await client.query('ROLLBACK');
            return { success: false, code: 'ERR_DUPLICATE_MATCH', message: 'Ce match existe déjà pour cette publication.' };
        }

        const matchId = matchResult.rows[0].id;
        
        // 🔧 V11.17.1 FIX : Utilise categoryOverride si fourni par le dashboard
        const categoryName = categoryOverride || parsedData.match_info?.category_name || 'CHAMPIONNAT';
        console.log('[DB] Category insert:', categoryName, '| match_id:', matchId, '| override:', categoryOverride || 'none');

        // 🔧 V11.17.4 FIX : Classement par IRG côté API — on ignore le rank de la fiche
        await client.query(
            `INSERT INTO match_category_rankings (match_id, publication_id, category_name, rank_in_category)
             VALUES ($1, $2, $3, $4)`,
            [matchId, publicationId, categoryName, 1]
        );

        const bets = [parsedData.pari_du_jour, ...parsedData.top_5_premium, ...parsedData.top_3_opportunites, parsedData.value_bet_premium, parsedData.value_bet_speculatif, parsedData.ticket_combine, ...parsedData.paris_a_bannir].filter(Boolean);
        for (const bet of bets) await insertBetRow(client, matchId, bet);

        try {
            await client.query(
                `INSERT INTO import_logs (user_id, status, raw_text_length, execution_time_ms)
                 VALUES ($1, 'SUCCESS', $2, $3)`,
                [userId, parsedData.raw_text_length || 0, Date.now() - startTime]
            );
        } catch (logErr) {
            console.error('⚠️ Échec log import (non bloquant):', logErr.message);
        }

        await client.query('COMMIT');
        return { success: true, publication_id: publicationId, match_id: matchId, warnings: validation.warnings };

    } catch (error) {
        console.error('[DATABASE] 🔴 ERREUR TRANSACTION :', error.message);
        console.error('[DATABASE] Code SQL :', error.code);
        console.error('[DATABASE] Stack :', error.stack);

        if (client) await client.query('ROLLBACK').catch(rbErr => console.error('❌ Échec du ROLLBACK:', rbErr.message));

        if (error && error.code === '23505')
            return { success: false, code: 'ERR_DUPLICATE_MATCH', message: 'Ce match existe déjà pour cette publication.' };

        const businessCode = error.message ? error.message.match(/^ERR_[A-Z_]+/)?.[0] : null;
        return { success: false, code: businessCode || error.code || 'ERR_DATABASE', message: error.message };

    } finally {
        if (client) client.release();
    }
}

module.exports = { savePublicationTransaction, closePool: async () => await pool.end(), pool };
