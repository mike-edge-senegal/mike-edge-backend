  // MODULE 1 : parser.js (V11.14 GOLD MASTER)
const PARSER_VERSION = 'V11.14 GOLD MASTER';
const MAX_RAW_TEXT_LENGTH = 50000;
const REGEX_UNICODE_SPACES = /\s+/g;
const REGEX_ACCENTS = /[\u0300-\u036f]/g;
const REGEX_NON_ALPHANUMERIC = /[^\p{Letter}\p{Number}]+/gu;
const REGEX_NON_DB_CHARS = /[^a-z0-9]/g;
const REGEX_STARS = /[⭐★]/gu;

const DICTIONARY = { 
    PDJ: ['[PARI_DU_JOUR]', '🎯 PARI DU JOUR', 'PARI DU JOUR', 'PDJ', 'LE PARI DU JOUR'], 
    TOP5: ['[TOP_5_PREMIUM]', '[TOP_5]', '🏆 TOP 5 PREMIUM', 'TOP 5 PREMIUM', 'TOP 5', 'TOP CINQ'], 
    OPP: ['[OPPORTUNITES]', '[TOP_3_OPPORTUNITES]', '💡 TOP 3 OPPORTUNITÉS', 'TOP 3 OPPORTUNITÉS', 'OPPORTUNITÉS'], 
    VALUE_PREMIUM: ['[VALUE_BET_PREMIUM]', '[VALUE_PREMIUM]', '💎 PARI VALUE PREMIUM', 'VALUE BET PREMIUM', 'VALUE PREMIUM'], 
    VALUE_SPECULATIF: ['[VALUE_BET_SPECULATIF]', '[VALUE_SPECULATIF]', '🎰 VALUE BET SPÉCULATIF', 'VALUE BET SPÉCULATIF'], 
    COMBINE: ['[TICKET_COMBINE]', '[TICKET_COMBINE_PREMIUM]', '🎟️ TICKET COMBINÉ PREMIUM', 'TICKET COMBINÉ'], 
    BANNED: ['[PARIS_A_BANNIR]', '[PARIS_A_EVITER]', '🚫 MODULE 3 — PARIS À BANNIR', 'PARIS À BANNIR', 'BANNED'], 
    MARKET_LABELS: ['MARCHE', 'MARCHÉ', 'PARI', 'SÉLECTION', 'SELECTION'] 
};

const MARKET_SYNONYMS = { 
    'over 1 5': 'plus de 1 5 buts', 'plus de 1 5': 'plus de 1 5 buts', 'over 2 5': 'plus de 2 5 buts', 
    'over 2 5 buts': 'plus de 2 5 buts', 'over2 5': 'plus de 2 5 buts', 'o2 5': 'plus de 2 5 buts', 
    'o 2 5': 'plus de 2 5 buts', 'plus de 2 5': 'plus de 2 5 buts', 'plus de 2 5 buts': 'plus de 2 5 buts', 
    '2 5 plus': 'plus de 2 5 buts', '2 5 over': 'plus de 2 5 buts', 'over 3 5': 'plus de 3 5 buts', 
    'plus de 3 5': 'plus de 3 5 buts', 'under 1 5': 'moins de 1 5 buts', 'moins de 1 5': 'moins de 1 5 buts', 
    'under 2 5': 'moins de 2 5 buts', 'under 2 5 buts': 'moins de 2 5 buts', 'under2 5': 'moins de 2 5 buts', 
    'u2 5': 'moins de 2 5 buts', 'u 2 5': 'moins de 2 5 buts', 'moins de 2 5': 'moins de 2 5 buts', 
    'moins de 2 5 buts': 'moins de 2 5 buts', 'under 3 5': 'moins de 3 5 buts', 'moins de 3 5': 'moins de 3 5 buts', 
    'btts oui': 'les deux equipes marquent oui', 'btts yes': 'les deux equipes marquent oui', 'btts': 'les deux equipes marquent oui', 
    'les 2 equipes marquent oui': 'les deux equipes marquent oui', 'les deux equipes marquent oui': 'les deux equipes marquent oui', 
    'equipe marque': 'les deux equipes marquent oui', 'btts non': 'les deux equipes marquent non', 'btts no': 'les deux equipes marquent non', 
    'les 2 equipes marquent non': 'les deux equipes marquent non', 'les deux equipes marquent non': 'les deux equipes marquent non', 
    'equipe ne marque pas': 'les deux equipes marquent non', '1x2 1': 'victoire equipe 1', 'victoire 1': 'victoire equipe 1', 
    '1x2 2': 'victoire equipe 2', 'victoire 2': 'victoire equipe 2', '1x2 x': 'match nul', 'nul': 'match nul', 
    '1x': 'double chance 1x', 'dc 1x': 'double chance 1x', 'double chance 1x': 'double chance 1x', 'x2': 'double chance x2', 
    'dc x2': 'double chance x2', 'double chance x2': 'double chance x2', '12': 'double chance 12', 'dc 12': 'double chance 12', 
    'clean sheet oui': 'cage inviolee oui', 'clean sheet non': 'cage inviolee non', 'cage inviolee oui': 'cage inviolee oui', 
    'qualification': 'qualification equipe' 
};

const SECTION_KEYS = ['PDJ', 'TOP5', 'OPP', 'VALUE_PREMIUM', 'VALUE_SPECULATIF', 'COMBINE', 'BANNED'];
const SECTION_HEADERS = [...SECTION_KEYS.flatMap(key => DICTIONARY[key]), '[META_MATCH]', '=== DEBUT FICHE MATCH ===', '🎯 AUDIT', 'FIN FICHE', '=== FIN FICHE ==='];

function normalizeFrenchText(value) { 
    return String(value || '').replace(/œ/g, 'oe').replace(/æ/g, 'ae').normalize('NFD').replace(REGEX_ACCENTS, '').toLowerCase().trim(); 
}

function normalizeHeader(value) { 
    if (typeof value !== 'string') return ''; 
    return value.normalize('NFKC').replace(/[\uFE0F\u200D]/gu, '').replace(/\p{Extended_Pictographic}/gu, '').replace(REGEX_UNICODE_SPACES, ' ').trim().toLocaleLowerCase('fr-FR'); 
}

function escapeRegExp(value) { 
    return String(value).replace(/[.*+?^${}()|[\]\\]/g, '\\$&'); 
}

function headerMatches(line, tag) { 
    return new RegExp(`^${escapeRegExp(tag)}(?:\\s*[:—\\-⭐★✅✔].*)?$`, 'iu').test(line); 
}

function getNextSectionAliases(currentAliases) { 
    const current = new Set(currentAliases.map(normalizeHeader)); 
    return SECTION_HEADERS.filter(alias => !current.has(normalizeHeader(alias))); 
}

function getSectionByStrictHeader(text, aliasArray, nextSectionAliases) { 
    if (typeof text !== 'string') return null; 
    const lines = text.split(/\r?\n/); 
    let startLine = -1; 
    for (let i = 0; i < lines.length; i++) { 
        if (aliasArray.some(alias => headerMatches(normalizeHeader(lines[i]), normalizeHeader(alias)))) { 
            startLine = i; 
            break; 
        } 
    } 
    if (startLine === -1) return null; 
    let endLine = lines.length; 
    for (let i = startLine + 1; i < lines.length; i++) { 
        if (nextSectionAliases.some(alias => headerMatches(normalizeHeader(lines[i]), normalizeHeader(alias)))) { 
            endLine = i; 
            break; 
        } 
    } 
    return lines.slice(startLine + 1, endLine).join('\n'); 
}

function extractTeams(rawText) { 
    const lines = rawText.split(/\r?\n/); 
    for (const line of lines) { 
        if (/^\s*(?:MATCH|EQUIPES?)\s*:/iu.test(line)) { 
            const cleaned = line.replace(/^\s*(?:MATCH|EQUIPES?)\s*:\s*/iu, '').trim(); 
            const match = cleaned.match(/^(.+?)\s+(?:vs\.?|contre|[-—–\/]|v)\s+(.+)$/iu); 
            if (match) return { home_team: match[1].trim(), away_team: match[2].trim() }; 
        } 
    } 
    for (const line of lines) { 
        if (/^\s*(?:CAT|RANG|DATE|HEURE|LIGUE|COMPETITION|IRG|AUDIT|P\d|BAN\d|\[|===|🏟️)/iu.test(line)) continue; 
        const match = line.trim().match(/^(.+?)\s+(?:vs\.?|contre|[-—–\/]|v)\s+(.+)$/iu); 
        if (match) return { home_team: match[1].trim(), away_team: match[2].trim() }; 
    } 
    return { home_team: null, away_team: null }; 
}

function extractFlexibleMarketName(block, labels) { 
    if (!block) return null; 
    for (const line of block.split(/\r?\n/)) { 
        for (const label of labels) { 
            const match = line.match(new RegExp(`(?:^|\\||\\s)${escapeRegExp(label)}\\s*(?::|—|-)?\\s*([^|\\n]+?)(?=\\s*(?:COTE|Cote|PROBA|PROBABILITE|ROBUSTESSE|ROB|ETOILES|STARS|\\||$))`, 'iu')); 
            if (match && match[1].trim()) return match[1].trim(); 
        } 
    } 
    return null; 
}

function extractProFormaMarket(block, prefix) { 
    if (!block) return null; 
    const prefixPattern = prefix === 'MARCHE' ? '(?:MARCHE|MARCHÉ|PARI|SÉLECTION|SELECTION)' : escapeRegExp(prefix); 
    const match = block.match(new RegExp(`(?:^|\\||\\s)${prefixPattern}\\s*(?::|—|-)?\\s*([^|\\n]+?)(?=\\s*(?:COTE|Cote|PROBA|PROBABILITE|ROBUSTESSE|ROB|ETOILES|STARS|\\||$))`, 'imu')); 
    return match ? match[1].trim() : null; 
}

function extractAnyOdds(block, customTag = null) { 
    if (!block) return null; 
    if (customTag) { 
        const customMatch = block.match(new RegExp(`\\b${escapeRegExp(customTag)}\\s*:\\s*([\\d]+(?:[.,]\\d+)?)`, 'iu')); 
        if (customMatch) return Number(customMatch[1].replace(',', '.')); 
    } 
    const priorityMatch = block.match(/\b(?:COTE_TOTALE|COTE TOTALE)\s*:\s*([\d]+(?:[.,]\d+)?)/iu); 
    if (priorityMatch) return Number(priorityMatch[1].replace(',', '.')); 
    const match = block.match(/\b(?:COTE)\s*:\s*([\d]+(?:[.,]\d+)?)/iu); 
    return match ? Number(match[1].replace(',', '.')) : null; 
}

function extractExplicitRank(block, prefixChar, fallbackIndex) { 
    if (!block) return fallbackIndex; 
    if (/^\s*(?:🥇|①)/.test(block)) return 1; 
    if (/^\s*(?:🥈|②)/.test(block)) return 2; 
    if (/^\s*(?:🥉|③)/.test(block)) return 3; 
    if (/^\s*(?:4️⃣)/.test(block)) return 4; 
    if (/^\s*(?:5️⃣)/.test(block)) return 5; 
    const match = block.match(/(?:RANG|P|O)\s*(\d+)/i); 
    return match ? Number(match[1]) : fallbackIndex; 
}

function extractPercentage(block) { 
    if (!block) return null; 
    for (const line of block.split(/\r?\n/)) { 
        const match = line.match(/(?:Probabilité|PROBABILITE|Proba)[^:]*:\s*([\d.,]+)\s*%/iu); 
        if (match) { 
            const val = Number(match[1].replace(',', '.')); 
            return Number.isFinite(val) ? val : null; 
        } 
    } 
    return null; 
}

function extractScore100(block) { 
    if (!block) return null; 
    for (const line of block.split(/\r?\n/)) { 
        const match = line.match(/(?:Robustesse|ROBUSTESSE|ROB\b|Confiance|Conf\b)[^:]*:\s*(\d+(?:[.,]\d+)?)\s*(?:\/\s*100)?/iu); 
        if (match) { 
            const val = Number(match[1].replace(',', '.')); 
            return Number.isFinite(val) ? val : null; 
        } 
    } 
    return null; 
}

function extractRobustnessScoreOrText(block) { 
    if (!block) return null; 
    const numeric = extractScore100(block); 
    if (numeric !== null) return numeric; 
    const match = block.match(/Robustesse\s*:\s*([^|\n]+)/iu); 
    if (!match) return null; 
    const value = normalizeFrenchText(match[1]).replace(/[\s-]+/g, '_').toUpperCase(); 
    if (/^(TRES_FORTE|EXCELLENTE?)$/.test(value)) return 95; 
    if (/^FORTE?$/.test(value)) return 85; 
    if (/^MOYENNE?$/.test(value)) return 70; 
    if (/^FAIBLE$/.test(value)) return 40; 
    return null; 
}

function extractConfidenceStarsOrText(block) { 
    if (!block) return null; 
    const explicit = block.match(/(?:Étoiles|ETOILES|STARS)\s*:\s*([1-5])/iu); 
    if (explicit) return Number(explicit[1]); 
    const starCount = [...block.matchAll(REGEX_STARS)].length; 
    if (starCount > 0) return Math.min(starCount, 5); 
    const numericMatch = block.match(/(?:CONFIANCE|CONF|Note de Confiance)\s*[:\-]?\s*(\d{1,3})\s*(?:\/\s*100)?/iu); 
    if (numericMatch) { 
        const note = Number(numericMatch[1]); 
        if (note >= 80) return 5; 
        if (note >= 60) return 4; 
        if (note >= 40) return 3; 
        if (note >= 20) return 2; 
        return 1; 
    } 
    const match = block.match(/CONFIANCE\s*:\s*([^|\n]+)/iu); 
    if (!match) return null; 
    const value = normalizeFrenchText(match[1]).replace(REGEX_UNICODE_SPACES, ' ').toUpperCase(); 
    if (/^(TRES ELEVE|TRES ELEVEE|ELEVE|ELEVEE|EXCELLENT)$/.test(value)) return 5; 
    if (/^FORTE?$/.test(value)) return 4; 
    if (/^MOYENNE?$/.test(value)) return 3; 
    if (/^FAIBLE$/.test(value)) return 2; 
    return null; 
}

function extractLine(block, keyword) { 
    if (!block) return null; 
    const normalizedKeyword = normalizeFrenchText(keyword); 
    const line = block.split(/\r?\n/).find(l => normalizeFrenchText(l).includes(normalizedKeyword)); 
    return line ? line.trim() : null; 
}

function normalizeMarket(value) { 
    const rawNormalized = normalizeFrenchText(value).replace(REGEX_NON_ALPHANUMERIC, ' ').replace(REGEX_UNICODE_SPACES, ' '); 
    return MARKET_SYNONYMS[rawNormalized] || rawNormalized; 
}

function parseTelegramText(rawText) { 
    const output = { 
        raw_text_length: typeof rawText === 'string' ? rawText.length : 0, 
        parser_version: PARSER_VERSION, 
        publication_title: null, 
        match_info: { home_team: null, away_team: null, date_str: null, time_str: null, league_name: null, irg_index: null, category_name: null, rank_in_category: null }, 
        pari_du_jour: null, top_5_premium: [], top_3_opportunites: [], value_bet_premium: null, value_bet_speculatif: null, ticket_combine: null, paris_a_bannir: [] 
    }; 
    if (typeof rawText !== 'string' || !rawText.trim() || rawText.length > MAX_RAW_TEXT_LENGTH) return output; 
    
    const teams = extractTeams(rawText); 
    output.match_info.home_team = teams.home_team; 
    output.match_info.away_team = teams.away_team; 

    const categoryMatch = rawText.match(/^\s*CAT(?:E|É)GORIE\s*:\s*([A-Z0-9_]+)\s*$/imu); 
    const rankMatch = rawText.match(/^\s*RANG\s*:\s*(?:MATCH\s*)?(\d+)\s*$/imu) || rawText.match(/^\s*Rang\s+(?:MATCH\s*)?(\d+)\s*$/imu); 
    const dateMatch = rawText.match(/📅\s*([^|\n•]+)/iu) || rawText.match(/^\s*DATE\s*:\s*([^|\n•]+)\s*$/imu); 
    const timeMatch = rawText.match(/(?:HEURE\s*[:—\-]|•\s*HEURE\s*[:—\-]|HEURE\s*)\s*(\d{1,2}:\d{2})/iu) || rawText.match(/^\s*HEURE\s*:\s*(\d{1,2}:\d{2})/imu) || rawText.match(/(?:HEURE\s*:|\bHEURE\b)\s*(\d{1,2}:\d{2})/iu); 
    const leagueMatch = rawText.match(/(?:COMPÉTITION|COMPETITION|LIGUE)\s*:\s*([^|\n]+)/iu) || rawText.match(/^\s*COMPÉTITION\s*[-—]\s*([^\n]+)$/imu); 
    const irgMatch = rawText.match(/(?:SCORE\s+IRG|IRG)\s*:\s*(\d{1,3})\b/iu) || rawText.match(/\bIR\s*:\s*(\d{1,3})\b/iu); 

    output.match_info.category_name = categoryMatch ? categoryMatch[1].toUpperCase().trim() : 'CHAMPIONNAT'; 
    output.match_info.rank_in_category = rankMatch ? Number(rankMatch[1]) : 1; 
    output.match_info.date_str = dateMatch ? dateMatch[1].trim() : null; 
    output.match_info.time_str = timeMatch ? timeMatch[1].trim() : null; 
    output.match_info.league_name = leagueMatch ? leagueMatch[1].trim() : 'Ligue Internationale'; 
    output.match_info.irg_index = irgMatch ? Number(irgMatch[1]) : 80; 

    if (output.match_info.home_team && output.match_info.away_team && output.match_info.league_name) { 
        output.publication_title = `${output.match_info.home_team} vs ${output.match_info.away_team} — ${output.match_info.league_name}`; 
    } 

    const metaSection = getSectionByStrictHeader(rawText, ['[META_MATCH]', '=== DEBUT FICHE MATCH ==='], getNextSectionAliases(['[META_MATCH]', '=== DEBUT FICHE MATCH ==='])) || ''; 
    const globalProb = extractPercentage(metaSection); 
    const globalRob = extractRobustnessScoreOrText(metaSection); 
    const globalStars = extractConfidenceStarsOrText(metaSection); 

    const pdjSection = getSectionByStrictHeader(rawText, DICTIONARY.PDJ, getNextSectionAliases(DICTIONARY.PDJ)); 
    if (pdjSection) { 
        output.pari_du_jour = { 
            section_type: 'PARI_DU_JOUR', 
            rank_in_section: 1, 
            market_name: extractFlexibleMarketName(pdjSection, DICTIONARY.MARKET_LABELS) || extractProFormaMarket(pdjSection, 'MARCHE'), 
            odds: extractAnyOdds(pdjSection), 
            probability_pct: extractPercentage(pdjSection) ?? globalProb, 
            robustness_pct: extractRobustnessScoreOrText(pdjSection) ?? globalRob ?? output.match_info.irg_index, 
            confidence_stars: extractConfidenceStarsOrText(pdjSection) ?? globalStars 
        }; 
    } 

    const top5Section = getSectionByStrictHeader(rawText, DICTIONARY.TOP5, getNextSectionAliases(DICTIONARY.TOP5)); 
    if (top5Section) { 
        top5Section.split(/(?=^\s*(?:🥇|🥈|🥉|4️⃣|5️⃣|P[1-5]\s*:|\d\.\s*(?:SÉCURITÉ|VALEUR|OPPORTUNITÉ)))/gim).filter(b => /^\s*(?:🥇|🥈|🥉|4️⃣|5️⃣|P\d|P\d\s*:|\d\.)/im.test(b)).slice(0, 5).forEach((block, index) => { 
            const rank = extractExplicitRank(block, 'P', index + 1); 
            output.top_5_premium.push({ 
                section_type: 'TOP_5', 
                rank_in_section: rank, 
                market_name: extractFlexibleMarketName(block, DICTIONARY.MARKET_LABELS) || extractProFormaMarket(block, `P${rank}`), 
                odds: extractAnyOdds(block), 
                probability_pct: extractPercentage(block), 
                robustness_pct: extractRobustnessScoreOrText(block), 
                confidence_stars: extractConfidenceStarsOrText(block) 
            }); 
        }); 
    } 

    const oppSection = getSectionByStrictHeader(rawText, DICTIONARY.OPP, getNextSectionAliases(DICTIONARY.OPP)); 
    if (oppSection) { 
        oppSection.split(/(?=^\s*(?:①|②|③|O[1-3]\s*:|Opportunité\s*\d))/gim).filter(b => /^\s*(?:①|②|③|O[1-3]|O[1-3]\s*:|Opportunité\s*\d)/im.test(b)).slice(0, 3).forEach((block, index) => { 
            const rank = extractExplicitRank(block, 'O', index + 1); 
            output.top_3_opportunites.push({ 
                section_type: 'OPPORTUNITE', 
                rank_in_section: rank, 
                market_name: extractFlexibleMarketName(block, DICTIONARY.MARKET_LABELS) || extractProFormaMarket(block, `O${rank}`), 
                odds: extractAnyOdds(block), 
                probability_pct: extractPercentage(block), 
                robustness_pct: extractRobustnessScoreOrText(block), 
                confidence_stars: extractConfidenceStarsOrText(block) 
            }); 
        }); 
    } 

    const valuePremiumSection = getSectionByStrictHeader(rawText, DICTIONARY.VALUE_PREMIUM, getNextSectionAliases(DICTIONARY.VALUE_PREMIUM)); 
    if (valuePremiumSection) { 
        output.value_bet_premium = { 
            section_type: 'VALUE_PREMIUM', 
            rank_in_section: 1, 
            market_name: extractFlexibleMarketName(valuePremiumSection, DICTIONARY.MARKET_LABELS) || extractProFormaMarket(valuePremiumSection, 'MARCHE'), 
            odds: extractAnyOdds(valuePremiumSection), 
            probability_pct: extractPercentage(valuePremiumSection), 
            robustness_pct: extractRobustnessScoreOrText(valuePremiumSection), 
            confidence_stars: extractConfidenceStarsOrText(valuePremiumSection) 
        }; 
    } 

    const valueSpeculativeSection = getSectionByStrictHeader(rawText, DICTIONARY.VALUE_SPECULATIF, getNextSectionAliases(DICTIONARY.VALUE_SPECULATIF)); 
    if (valueSpeculativeSection) { 
        output.value_bet_speculatif = { 
            section_type: 'VALUE_SPECULATIF', 
            rank_in_section: 1, 
            market_name: extractFlexibleMarketName(valueSpeculativeSection, DICTIONARY.MARKET_LABELS) || extractProFormaMarket(valueSpeculativeSection, 'MARCHE'), 
            odds: extractAnyOdds(valueSpeculativeSection), 
            probability_pct: extractPercentage(valueSpeculativeSection), 
            robustness_pct: extractRobustnessScoreOrText(valueSpeculativeSection), 
            confidence_stars: extractConfidenceStarsOrText(valueSpeculativeSource = valueSpeculativeSection) // Fallback protect
        }; 
    } 

    const ticketSection = getSectionByStrictHeader(rawText, DICTIONARY.COMBINE, getNextSectionAliases(DICTIONARY.COMBINE)); 
    if (ticketSection) { 
        const sel1 = extractLine(ticketSection, 'SEL1') || extractLine(ticketSection, 'Sélection 1'); 
        const sel2 = extractLine(ticketSection, 'SEL2') || extractLine(ticketSection, 'Sélection 2'); 
        output.ticket_combine = { 
            section_type: 'COMBINE', 
            rank_in_section: 1, 
            market_name: 'Ticket Combiné Premium', 
            odds: extractAnyOdds(ticketSection, 'COTE_TOTALE') ?? extractAnyOdds(ticketSection, 'Cote'), 
            confidence_stars: extractConfidenceStarsOrText(ticketSection), 
            comment: [sel1, sel2].filter(Boolean).join(' + ') || 'Sélections d’élite combinées' 
        }; 
    } 

    const bannedSection = getSectionByStrictHeader(rawText, DICTIONARY.BANNED, getNextSectionAliases(DICTIONARY.BANNED)); 
    if (bannedSection) { 
        const seenRanks = new Set(); 
        for (const line of bannedSection.split('\n')) { 
            const bannedMatch = line.match(/^\s*BAN(\d+)\s*:\s*([^|\n]+?)(?:\s*\|\s*(?:RAISON\s*:)?\s*(.*))?$/i); 
            if (!bannedMatch) continue; 
            const rank = Number(bannedMatch[1]); 
            if (rank < 1 || rank > 3 || seenRanks.has(rank)) continue; 
            seenRanks.add(rank); 
            output.paris_a_bannir.push({ 
                section_type: 'BANNED', 
                rank_in_section: rank, 
                market_name: bannedMatch[2].trim(), 
                reason: bannedMatch[3] ? bannedMatch[3].trim() : 'Risque élevé de scénario défavorable' 
            }); 
        } 
    } 

    return output; 
}

module.exports = { PARSER_VERSION, parseTelegramText, normalizeMarket, normalizeFrenchText, REGEX_NON_DB_CHARS };
