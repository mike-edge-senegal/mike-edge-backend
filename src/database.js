// ============================================
// MODULE 3 : database.js — MIKE EDGE V11.17.5
// FIX : Date fallback + rank_in_category = 1 (classement par IRG côté API)
// FIX : import_logs hors transaction pour éviter ABORTED
// FIX : Auto-création ligue + équipe via unaccent + fallback cross-ligue
// SESSION : Gestion des sessions actives par catégorie
// ============================================

// ============================================
// 1. IMPORTS
// ============================================
const { Pool } = require('pg');

// ============================================
// 2. POOL DE CONNEXION
// ============================================
const pool = new Pool({
    connectionString: process.env.DATABASE_URL,
    ssl: process.env.DATABASE_URL?.includes('localhost') ? false : { rejectUnauthorized: false },
});

// ============================================
// 3. FONCTION : normalizeDatabaseName
// ============================================
function normalizeDatabaseName(name) {
    if (!name || typeof name !== 'string') return '';
    return name
        .normalize('NFD')
        .replace(/[\u0300-\u036f]/g, '')
        .replace(/[^a-zA-Z0-9\s]/g, '')
        .trim()
        .toLowerCase();
}

// ============================================
// 4. FONCTION : getLeagueIdStrict
// ============================================
async function getLeagueIdStrict(client, leagueName) {
    if (!leagueName) throw new Error('ERR_UNKNOWN_LEAGUE');

    const normalized = normalizeDatabaseName(leagueName);

    const result = await client.query(
        `SELECT id FROM leagues 
         WHERE LOWER(REGEXP_REPLACE(unaccent(name), '[^a-zA-Z0-9]', '', 'g')) = $1 
         LIMIT 1`,
        [normalized]
    );

    if (result.rows.length > 0) return result.rows[0].id;

    const insert = await client.query(
        `INSERT INTO leagues (name) VALUES ($1) RETURNING id`,
        [leagueName.trim()]
    );
    return insert.rows[0].id;
}

// ============================================
// 5. FONCTION : getTeamIdStrict
// ============================================
async function getTeamIdStrict(client, teamName, leagueId) {
    if (!teamName) throw new Error('ERR_UNKNOWN_TEAM');

    const normalized = normalizeDatabaseName(teamName);

    const result = await client.query(
        `SELECT id FROM teams 
         WHERE LOWER(REGEXP_REPLACE(unaccent(name), '[^a-zA-Z0-9]', '', 'g')) = $1 
         AND league_id = $2 
         LIMIT 1`,
        [normalized, leagueId]
    );

    if (result.rows.length > 0) return result.rows[0].id;

    const fallback = await client.query(
        `SELECT id FROM teams 
         WHERE LOWER(REGEXP_REPLACE(unaccent(name), '[^a-zA-Z0-9]', '', 'g')) = $1 
         LIMIT 1`,
        [normalized]
    );

    if (fallback.rows.length > 0) return fallback.rows[0].id;

    const insert = await client.query(
        `INSERT INTO teams (name, league_id) VALUES ($1, $2) RETURNING id`,
        [teamName.trim(), leagueId]
    );
    return insert.rows[0].id;
}

// ============================================
// 6. FONCTION : buildRobustIsoDatetime
// ============================================
function buildRobustIsoDatetime(dateStr, timeStr) {
    try {
        if (!dateStr) return null;
        const cleanDate = dateStr.toString().trim();
        const cleanTime = timeStr ? timeStr.toString().trim() : '20:00';

        let day, month, year;
        const frMatch = cleanDate.match(/(\d{1,2})[\/\-\.](\d{1,2})[\/\-\.](\d{2,4})/);
        if (frMatch) {
            day = frMatch[1].padStart(2, '0');
            month = frMatch[2].padStart(2, '0');
            year = frMatch[3].length === 2 ? '20' + frMatch[3] : frMatch[3];
        } else {
            const d = new Date(cleanDate);
            if (!isNaN(d.getTime())) return d.toISOString();
            return null;
        }

        const [hours, minutes] = cleanTime.split(':');
        const isoStr = `${year}-${month}-${day}T${hours.padStart(2, '0')}:${minutes.padStart(2, '0')}:00`;
        const d = new Date(isoStr);
        return isNaN(d.getTime()) ? null : d.toISOString();
    } catch (e) {
        console.error('[buildRobustIsoDatetime] Erreur:', e.message, '| input:', dateStr, timeStr);
        return null;
    }
}

// ============================================
// 7. FONCTION : insertBetRow
// ============================================
async function insertBetRow(client, matchId, bet) {
    await client.query(
        `INSERT INTO bets (
            match_id, section_type, rank_in_section, market_name, odds,
            probability_pct, robustness_pct, confidence_stars, comment,
            home_score, away_score, home_team, away_team,
            home_odds, away_odds, draw_odds, over_under_line
        ) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14, $15, $16, $17)`,
        [
            matchId,
            bet.section_type || 'PARI_DU_JOUR',
            bet.rank_in_section || 1,
            bet.market_name || '—',
            bet.odds || 0,
            bet.probability_pct || 0,
            bet.robustness_pct || 0,
            bet.confidence_stars || 0,
            bet.comment || null,
            bet.home_score || null,
            bet.away_score || null,
            bet.home_team || null,
            bet.away_team || null,
            bet.home_odds || null,
            bet.away_odds || null,
            bet.draw_odds || null,
            bet.over_under_line || null
        ]
    );
}

// ============================================
// 8. FONCTION : validateParsedImport
// ============================================
function validateParsedImport(parsedData) {
    if (!parsedData || typeof parsedData !== 'object') {
        throw new Error('ERR_INVALID_IMPORT_DATA');
    }
    if (!parsedData.match_info || typeof parsedData.match_info !== 'object') {
        throw new Error('ERR_MISSING_MATCH_INFO');
    }
    if (!parsedData.match_info.home_team || !parsedData.match_info.away_team) {
        throw new Error('ERR_MISSING_TEAMS');
    }
    return true;
}

// ============================================
// 9. FONCTION : savePublicationTransaction
// ============================================
async function savePublicationTransaction(parsedData, rawText, userId, categoryOverride) {
    const client = await pool.connect();
    try {
        await client.query('BEGIN');

        // 🚨 TRACE 1
        console.log('🚨 TRACE 1 — ENTRÉE savePublicationTransaction');

        const categoryName = categoryOverride || parsedData.match_info?.category_name || 'EUROPE';
        const leagueName = parsedData.match_info?.league_name || 'Ligue inconnue';
        const homeTeamName = parsedData.match_info?.home_team || 'Équipe domicile';
        const awayTeamName = parsedData.match_info?.away_team || 'Équipe extérieure';
        const matchDate = parsedData.match_info?.date_str || '';
        const matchTime = parsedData.match_info?.time_str || '20:00';
        const irgIndex = parsedData.match_info?.irg_index || 0;

        // 🚨 TRACE 2
        console.log('🚨 TRACE 2 — CONNEXION CLIENT OK');

        // 🚨 TRACE 3
        console.log('🚨 TRACE 3 — BEGIN OK');

        // 🚨 TRACE 4 — LEAGUE
        const leagueId = await getLeagueIdStrict(client, leagueName);
        console.log('🚨 TRACE 4 — LEAGUE OK — ID:', leagueId);

        // 🚨 TRACE 5 — HOME TEAM
        const homeTeamId = await getTeamIdStrict(client, homeTeamName, leagueId);
        console.log('🚨 TRACE 5 — HOME TEAM OK — ID:', homeTeamId);

        // 🚨 TRACE 6 — AWAY TEAM
        const awayTeamId = await getTeamIdStrict(client, awayTeamName, leagueId);
        console.log('🚨 TRACE 6 — AWAY TEAM OK — ID:', awayTeamId);

        // 🚨 TRACE 7 — PUBLICATION
        const pubRes = await client.query(
            `INSERT INTO publications (title, start_date, end_date, status, protocol_version)
             VALUES ($1, $2, $3, $4, $5) RETURNING id`,
            [
                `${homeTeamName} vs ${awayTeamName}`,
                matchDate || new Date().toISOString().split('T')[0],
                matchDate || new Date().toISOString().split('T')[0],
                'ACTIVE',
                'V11.14'
            ]
        );
        const publicationId = pubRes.rows[0].id;
        console.log('🚨 TRACE 7 — PUBLICATION OK — ID:', publicationId);

        // 🚨 TRACE 8 — MATCH
        const matchDateTime = buildRobustIsoDatetime(matchDate, matchTime);
        const matchRes = await client.query(
            `INSERT INTO matches (publication_id, league_id, home_team_id, away_team_id, match_datetime, irg_index)
             VALUES ($1, $2, $3, $4, $5, $6) RETURNING id`,
            [publicationId, leagueId, homeTeamId, awayTeamId, matchDateTime, irgIndex]
        );
        const matchId = matchRes.rows[0].id;
        console.log('🚨 TRACE 8 — MATCH INSERT RETOUR — rows:', matchRes.rowCount);
        console.log('🚨 TRACE 9 — MATCH OK — ID:', matchId);

        // 🚨 TRACE 10
        console.log(
            '🚨 TRACE 10 — AVANT INSERT MCR'
        );

        // =====================================================
        // SESSION ACTIVE — récupérer ou créer
        // =====================================================
        const sessionRes = await client.query(
            `SELECT id FROM category_sessions 
             WHERE category_name = $1 AND status = 'ACTIVE' 
             LIMIT 1`,
            [categoryName]
        );

        let sessionId;
        if (sessionRes.rows.length === 0) {
            const newSession = await client.query(
                `INSERT INTO category_sessions (category_name, session_number, status)
                 VALUES ($1, 1, 'ACTIVE')
                 RETURNING id`,
                [categoryName]
            );
            sessionId = newSession.rows[0].id;
            console.log('[SESSION] Création session #1', categoryName, 'id:', sessionId);
        } else {
            sessionId = sessionRes.rows[0].id;
            console.log('[SESSION] Session active trouvée', categoryName, 'id:', sessionId);
        }

        // Vérifier le quota de la session active
        const countRes = await client.query(
            `SELECT COUNT(*) as cnt FROM match_category_rankings 
             WHERE session_id = $1`,
            [sessionId]
        );
        const currentCount = parseInt(countRes.rows[0].cnt, 10);
        const maxQuota = categoryName === 'ELITE_MONDIALE' ? 10 : 5;

        if (currentCount >= maxQuota) {
            await client.query('ROLLBACK');
            return {
                success: false,
                code: 'ERR_SESSION_FULL',
                message: `Session ${categoryName} complète (${currentCount}/${maxQuota}). Clôturez la session pour en créer une nouvelle.`
            };
        }

        await client.query(
            `INSERT INTO match_category_rankings (
                match_id,
                publication_id,
                category_name,
                rank_in_category,
                session_id
            )
            VALUES ($1, $2, $3, $4, $5)`,
            [
                matchId,
                publicationId,
                categoryName,
                1,
                sessionId
            ]
        );

        // 🚨 TRACE 11
        console.log(
            '🚨 TRACE 11 — MCR OK'
        );

        // 🚨 TRACE 12 — BETS
        const bets = parsedData.bets || [];
        console.log('🚨 TRACE 12 — AVANT BETS — count:', bets.length);

        if (bets.length > 0) {
            for (const bet of bets) {
                await insertBetRow(client, matchId, bet);
            }
        } else if (parsedData.pari_du_jour) {
            await insertBetRow(client, matchId, {
                ...parsedData.pari_du_jour,
                section_type: 'PARI_DU_JOUR',
                rank_in_section: 1
            });
        }

        if (parsedData.top_5_premium && Array.isArray(parsedData.top_5_premium)) {
            for (let i = 0; i < parsedData.top_5_premium.length; i++) {
                await insertBetRow(client, matchId, {
                    ...parsedData.top_5_premium[i],
                    section_type: 'TOP_5',
                    rank_in_section: i + 1
                });
            }
        }

        if (parsedData.top_3_opportunites && Array.isArray(parsedData.top_3_opportunites)) {
            for (let i = 0; i < parsedData.top_3_opportunites.length; i++) {
                await insertBetRow(client, matchId, {
                    ...parsedData.top_3_opportunites[i],
                    section_type: 'OPPORTUNITE',
                    rank_in_section: i + 1
                });
            }
        }

        if (parsedData.value_bet_premium) {
            await insertBetRow(client, matchId, {
                ...parsedData.value_bet_premium,
                section_type: 'VALUE_PREMIUM',
                rank_in_section: 1
            });
        }

        if (parsedData.value_bet_speculatif) {
            await insertBetRow(client, matchId, {
                ...parsedData.value_bet_speculatif,
                section_type: 'VALUE_SPECULATIF',
                rank_in_section: 1
            });
        }

        if (parsedData.ticket_combine) {
            await insertBetRow(client, matchId, {
                ...parsedData.ticket_combine,
                section_type: 'COMBINE',
                rank_in_section: 1
            });
        }

        if (parsedData.paris_a_bannir && Array.isArray(parsedData.paris_a_bannir)) {
            for (let i = 0; i < parsedData.paris_a_bannir.length; i++) {
                await insertBetRow(client, matchId, {
                    ...parsedData.paris_a_bannir[i],
                    section_type: 'BANNED',
                    rank_in_section: i + 1
                });
            }
        }

        console.log('🚨 TRACE 13 — BETS OK');

        // 🚨 TRACE 14 — IMPORT_LOG (hors transaction, non bloquant)
        console.log('🚨 TRACE 14 — AVANT IMPORT_LOG');
        try {
            await pool.query(
                `INSERT INTO import_logs (user_id, status, raw_text_length, execution_time_ms)
                 VALUES ($1, $2, $3, $4)`,
                [userId || null, 'SUCCESS', rawText ? rawText.length : 0, 0]
            );
            console.log('🚨 TRACE 15A — IMPORT_LOG OK');
        } catch (logErr) {
            console.log('🚨 TRACE 15B — IMPORT_LOG ÉCHEC MAIS NON BLOQUANT:', logErr.message);
        }

        // 🚨 TRACE 16
        console.log('🚨 TRACE 16 — AVANT COMMIT');

        await client.query('COMMIT');
        console.log('🚨 TRACE 17 — COMMIT OK — publication_id:', publicationId, '| match_id:', matchId);

        return { success: true, publicationId, matchId };

    } catch (err) {
        await client.query('ROLLBACK').catch(() => {});
        console.error('🚨 TRACE ERREUR — ROLLBACK:', err.message);
        throw err;
    } finally {
        client.release();
    }
}

// ============================================
// 10. EXPORTS
// ============================================
module.exports = {
    pool,
    savePublicationTransaction,
    closePool: () => pool.end(),
};
