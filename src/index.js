// MODULE 4 : index.js
process.env.TZ = 'UTC';
const { PARSER_VERSION, parseTelegramText, normalizeMarket, normalizeFrenchText, REGEX_NON_DB_CHARS } = require('./parser');
const { validateParsedImport } = require('./validator');
const { savePublicationTransaction, closePool, pool } = require('./database');

module.exports = { 
    PARSER_VERSION, 
    parseTelegramText, 
    validateParsedImport, 
    savePublicationTransaction, 
    closePool, 
    pool, 
    normalizeMarket, 
    normalizeFrenchText, 
    REGEX_NON_DB_CHARS 
};
