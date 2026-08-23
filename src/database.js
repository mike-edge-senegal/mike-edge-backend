const { Pool } = require('pg');
const { validateParsedImport } = require('./validator');
const { 
    PARSER_VERSION, 
    normalizeFrenchText, 
    REGEX_NON_DB_CHARS 
} = require('./parser');

const pool = new Pool({ 
    user: process.env.DB_USER, 
    host: process.env.DB_HOST, 
    database: process.env.DB_NAME, 
    password: process.env.DB_PASSWORD, 
    port: process.env.DB_PORT || 5432, 
    max: 20, 
    ssl: { rejectUnauthorized: false }, 
    idleTimeoutMillis: 30000, 
    connectionTimeoutMillis: 5000 
});

function normalizeDatabaseName(value) { 
    return normalizeFrenchText(value).replace(REGEX_NON_DB_CHARS, ''); 
}

async function getLeagueIdStrict(client, leagueName) { 
    if (!leagueName) throw new Error('ERR_UNKNOWN_LEAGUE'); 
    const normalized = normalizeDatabaseName(leagueName); 
    const result = await client.query(
        "SELECT id FROM leagues WHERE LOWER(REGEXP_REPLACE(unaccent(name), '[^a-zA-Z0-9]', '', 'g')) = $1", 
        [normalized]
    ); 
    if (result.rows.length === 0) throw new Error(`ERR_UNKNOWN_LEAGUE: ${leagueName}`); 
    return result.rows[0].id; 
}

async function getTeamIdStrict(client, teamName, leagueId) { 
    if (!teamName) throw new Error('ERR_UNKNOWN_TEAM'); 
    const normalized = normalizeDatabaseName(teamName); 
    let result = await client.query(
        "SELECT id FROM teams WHERE LOWER(REGEXP_REPLACE(unaccent(name), '[^a-zA-Z0-9]', '', 'g')) = $1 AND league_id = $2", 
        [normalized, leagueId]
    ); 
    if (result.rows.length === 0) { 
        result = await client.query(
            "SELECT id FROM teams WHERE LOWER(REGEXP_REPLACE(unaccent(name), '[^a-zA-Z0-9]', '', 'g')) = $1 LIMIT 1", 
            [normalized]
        ); 
    } 
    if (result.rows.length === 0) throw new Error(`ERR_UNKNOWN_TEAM: ${teamName}`); 
    return result.rows[0].id; 
}

function buildRobustIsoDatetime(dateStr, timeStr) { 
    if (!dateStr || !timeStr) throw new Error('ERR_MISSING_DATETIME'); 
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
        } 
    } 
    if (!Number.isInteger(year) || !Number.isInteger(month) || !Number.isInteger(day)) throw new Error('ERR_INVALID_DATE_FORMAT'); 
    const timeParts = String(timeStr).split(':'); 
    const date = new Date(Date.UTC(year, month - 1, day, Number(timeParts[0]), Number(timeParts[1]), 0, 0)); 
    return date; 
}

async function insertBetRow(client, matchId, bet) { 
    const isBanned = bet.section_type === 'BANNED'; 
    await client.query(
        "INSERT INTO bets (match_id, section_type, rank_in_section, market_name, odds, probability_pct, robustness_pct, confidence_stars, comment) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9)", 
        [matchId, bet.section_type, bet.rank_in_section, bet.market_name, isBanned ? null : bet.odds, bet.probability_pct ?? null, bet.robustness_pct ?? null, isBanned ? null : bet.confidence_stars, bet.comment || null]
    ); 
}

async function savePublicationTransaction(parsedData, targetPublicationId = null, userId = null) { 
    let client; 
    try { 
        client = await pool.connect(); 
        await client.query('BEGIN'); 
        const leagueId = await getLeagueIdStrict(client, parsedData.match_info.league_name); 
        const homeTeamId = await getTeamIdStrict(client, parsedData.match_info.home_team, leagueId); 
        const awayTeamId = await getTeamIdStrict(client, parsedData.match_info.away_team, leagueId); 
        const matchDatetime = buildRobustIsoDatetime(parsedData.match_info.date_str, parsedData.match_info.time_str); 
        let publicationId = targetPublicationId; 
        if (!publicationId) { 
            const title = parsedData.publication_title || `${parsedData.match_info.home_team} vs ${parsedData.match_info.away_team}`; 
            const pubRes = await client.query(
                "INSERT INTO publications (title, start_date, end_date, status, protocol_version) VALUES ($1, $2, $3, 'DRAFT', $4) RETURNING id", 
                [title, matchDatetime, new Date(matchDatetime.getTime() + 259200000), PARSER_VERSION]
            ); 
            publicationId = pubRes.rows[0].id; 
        } 
        const matchResult = await client.query(
            "INSERT INTO matches (publication_id, league_id, home_team_id, away_team_id, match_datetime, irg_index) VALUES ($1, $2, $3, $4, $5, $6) RETURNING id", 
            [publicationId, leagueId, homeTeamId, awayTeamId, matchDatetime, parsedData.match_info.irg_index]
        ); 
        const matchId = matchResult.rows[0].id; 
        await client.query(
            "INSERT INTO match_category_rankings (match_id, publication_id, category_name, rank_in_category) VALUES ($1, $2, $3, $4)", 
            [matchId, publicationId, parsedData.match_info.category_name, parsedData.match_info.rank_in_category]
        ); 
        const bets = [parsedData.pari_du_jour, ...parsedData.top_5_premium, ...parsedData.top_3_opportunites, parsedData.value_bet_premium, parsedData.value_bet_speculatif, parsedData.ticket_combine, ...parsedData.paris_a_bannir].filter(Boolean); 
        for (const bet of bets) await insertBetRow(client, matchId, bet); 
        await client.query('COMMIT'); 
        return { success: true, publication_id: publicationId, match_id: matchId }; 
    } catch (error) { 
        if (client) await client.query('ROLLBACK'); 
        return { success: false, code: 'ERR_DATABASE', message: error.message }; 
    } finally { 
        if (client) client.release(); 
    } 
}

module.exports = { 
    savePublicationTransaction, 
    closePool: async () => await pool.end(), 
    pool 
};
