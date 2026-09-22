'use strict';

const AUTH_MODE = process.env.AUTH_MODE || 'TEST';
const SMS_PROVIDER = process.env.SMS_PROVIDER || 'STUB';

const VALID_AUTH_MODES = ['TEST', 'PRODUCTION'];
const VALID_SMS_PROVIDERS = ['STUB'];

if (!VALID_AUTH_MODES.includes(AUTH_MODE)) {
    throw new Error(`CONFIG_ERROR: AUTH_MODE invalide (${AUTH_MODE}). Valeurs autorisées: TEST, PRODUCTION.`);
}

if (!VALID_SMS_PROVIDERS.includes(SMS_PROVIDER)) {
    throw new Error(`CONFIG_ERROR: SMS_PROVIDER invalide (${SMS_PROVIDER}). Valeurs actuellement autorisées: STUB.`);
}

const OTP_TEST_LENGTH = 4;
const OTP_PRODUCTION_LENGTH = 6;
const OTP_EXPIRATION_MINUTES = 10;
const OTP_MAX_ATTEMPTS = 5;
const OTP_BCRYPT_ROUNDS = 12;

if (AUTH_MODE === 'TEST') {
    console.log('[CONFIG] AUTH_MODE=TEST — nouveau système OTP désactivé');
} else {
    console.log('[CONFIG] AUTH_MODE=PRODUCTION — système OTP réel actif');
}

module.exports = Object.freeze({
    AUTH_MODE,
    SMS_PROVIDER,
    OTP_TEST_LENGTH,
    OTP_PRODUCTION_LENGTH,
    OTP_EXPIRATION_MINUTES,
    OTP_MAX_ATTEMPTS,
    OTP_BCRYPT_ROUNDS
});
