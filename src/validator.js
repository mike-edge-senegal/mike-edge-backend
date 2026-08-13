// MODULE 2 : validator.js
const { normalizeMarket } = require('./parser');

function validateOptionalArray(value, field, errorCode, validation) { 
    if (value == null) return []; 
    if (!Array.isArray(value)) { 
        validation.is_valid = false; 
        validation.errors.push({ code: errorCode, message: `${field} doit être un tableau.` }); 
        return []; 
    } 
    return value; 
}

function getEffectiveRank(bet, index) { 
    return Number.isInteger(bet?.rank_in_section) ? bet.rank_in_section : index + 1; 
}

function validateUniqueAndBoundedRanks(items, label, min, max, validation) { 
    const ranks = new Set(); 
    const sortedRanks = []; 
    items.forEach((bet, index) => { 
        const rank = getEffectiveRank(bet, index); 
        if (rank < min || rank > max) { 
            validation.is_valid = false; 
            validation.errors.push({ code: `ERR_INVALID_${label}_RANK`, message: `Rang ${rank} invalide dans ${label}.` }); 
        } 
        if (ranks.has(rank)) { 
            validation.is_valid = false; 
            validation.errors.push({ code: `ERR_DUPLICATE_${label}_RANK`, message: `Rang ${rank} dupliqué dans ${label}.` }); 
        } 
        ranks.add(rank); 
        sortedRanks.push(rank); 
    }); 
    sortedRanks.sort((a, b) => a - b); 
    for (let i = 0; i < sortedRanks.length; i++) { 
        if (sortedRanks[i] !== i + 1) { 
            validation.warnings.push({ code: `WARN_MISSING_${label}_RANK_SEQUENCE`, message: `Séquence de rang discontinue dans ${label}.` }); 
            break; 
        } 
    } 
}

function validateBet(bet, label, validation, requireOdds = true, requireStars = true, requireProbability = false, requireRobustness = false) { 
    if (!bet) { 
        validation.is_valid = false; 
        validation.errors.push({ code: `ERR_MISSING_${label}` }); 
        return; 
    } 
    if (typeof bet.market_name !== 'string' || !bet.market_name.trim()) { 
        validation.is_valid = false; 
        validation.errors.push({ code: `ERR_MISSING_${label}_MARKET` }); 
    } 
    if (requireOdds && (!Number.isFinite(bet.odds) || bet.odds < 1.00)) { 
        validation.is_valid = false; 
        validation.errors.push({ code: `ERR_INVALID_${label}_ODDS` }); 
    } 
    if (requireProbability && (!Number.isFinite(bet.probability_pct) || bet.probability_pct < 0 || bet.probability_pct > 100)) { 
        validation.is_valid = false; 
        validation.errors.push({ code: `ERR_INVALID_${label}_PROBABILITY` }); 
    } 
    if (requireRobustness && (!Number.isFinite(bet.robustness_pct) || bet.robustness_pct < 0 || bet.robustness_pct > 100)) { 
        validation.is_valid = false; 
        validation.errors.push({ code: `ERR_INVALID_${label}_ROBUSTNESS` }); 
    } 
    if (requireStars && (!Number.isInteger(bet.confidence_stars) || bet.confidence_stars < 1 || bet.confidence_stars > 5)) { 
        validation.is_valid = false; 
        validation.errors.push({ code: `ERR_INVALID_${label}_STARS` }); 
    } 
}

function validateParsedImport(parsedData) { 
    const validation = { is_valid: true, errors: [], warnings: [] }; 
    if (!parsedData || typeof parsedData !== 'object') { 
        validation.is_valid = false; 
        validation.errors.push({ code: 'ERR_INVALID_PAYLOAD' }); 
        return validation; 
    } 
    if (parsedData.error_code === 'ERR_TEXT_TOO_LARGE') { 
        validation.is_valid = false; 
        validation.errors.push({ code: 'ERR_TEXT_TOO_LARGE', message: 'Le texte dépasse la taille maximale autorisée.' }); 
        return validation; 
    } 
    const matchInfo = parsedData?.match_info || {}; 
    if (!matchInfo.home_team || !matchInfo.away_team) validation.errors.push({ code: 'ERR_MISSING_TEAMS' }); 
    if (!matchInfo.league_name) validation.errors.push({ code: 'ERR_MISSING_LEAGUE' }); 
    const irg = matchInfo.irg_index; 
    if (!Number.isInteger(irg) || irg < 0 || irg > 100) validation.errors.push({ code: 'ERR_INVALID_IRG' }); 
    if (!matchInfo.date_str) validation.errors.push({ code: 'ERR_MISSING_DATE' }); 
    if (!matchInfo.time_str) validation.errors.push({ code: 'ERR_MISSING_TIME' }); 
    if (!matchInfo.category_name || !Number.isInteger(matchInfo.rank_in_category) || matchInfo.rank_in_category < 1) { 
        validation.errors.push({ code: 'ERR_INVALID_RANKING' }); 
    } 
    if (validation.errors.length > 0) validation.is_valid = false; 

    validateBet(parsedData?.pari_du_jour, 'PARI_DU_JOUR', validation, true, true, true, true); 

    const top5 = validateOptionalArray(parsedData?.top_5_premium, 'top_5_premium', 'ERR_INVALID_TOP5_TYPE', validation); 
    const opps = validateOptionalArray(parsedData?.top_3_opportunites, 'top_3_opportunites', 'ERR_INVALID_OPPORTUNITES_TYPE', validation); 
    const banned = validateOptionalArray(parsedData?.paris_a_bannir, 'paris_a_bannir', 'ERR_INVALID_BANNED_TYPE', validation); 

    if (top5.length > 5) { validation.is_valid = false; validation.errors.push({ code: 'ERR_TOP5_OVERFLOW' }); } 
    if (opps.length > 3) { validation.is_valid = false; validation.errors.push({ code: 'ERR_OPPORTUNITES_OVERFLOW' }); } 
    if (banned.length > 3) { validation.is_valid = false; validation.errors.push({ code: 'ERR_BANNED_OVERFLOW' }); } 

    validateUniqueAndBoundedRanks(top5, 'TOP5', 1, 5, validation); 
    validateUniqueAndBoundedRanks(opps, 'OPPORTUNITES', 1, 3, validation); 
    validateUniqueAndBoundedRanks(banned, 'BANNED', 1, 3, validation); 

    top5.forEach((bet, i) => validateBet(bet, `TOP_5_P${getEffectiveRank(bet, i)}`, validation, true, true, false, false)); 
    opps.forEach((bet, i) => validateBet(bet, `OPP_O${getEffectiveRank(bet, i)}`, validation, true, true, false, false)); 
    banned.forEach((bet, i) => validateBet(bet, `BANNED_${getEffectiveRank(bet, i)}`, validation, false, false, false, false)); 

    if (parsedData?.value_bet_premium) validateBet(parsedData.value_bet_premium, 'VALUE_PREMIUM', validation, true, true, false, false); 
    if (parsedData?.value_bet_speculatif) validateBet(parsedData.value_bet_speculatif, 'VALUE_SPECULATIF', validation, true, true, false, false); 
    if (parsedData?.ticket_combine) validateBet(parsedData.ticket_combine, 'COMBINE', validation, true, true, false, false); 

    const marketSet = new Set(); 
    const activeBets = [parsedData?.pari_du_jour, ...top5, ...opps, parsedData?.value_bet_premium, parsedData?.value_bet_speculatif, parsedData?.ticket_combine].filter(Boolean); 
    for (const bet of activeBets) { 
        const market = normalizeMarket(bet.market_name); 
        if (!market) continue; 
        if (marketSet.has(market)) { 
            validation.is_valid = false; 
            validation.errors.push({ code: 'ERR_DUPLICATE_MARKET', message: `Marché dupliqué: ${bet.market_name}` }); 
        } 
        marketSet.add(market); 
    } 
    return validation; 
}

module.exports = { validateParsedImport };
