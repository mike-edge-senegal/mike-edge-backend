'use strict';

const jwt = require('jsonwebtoken');
const crypto = require('crypto');
const { pool } = require('./index');

const JWT_ISSUER = 'mike-edge-backend';
const JWT_AUDIENCE = 'mike-edge-api';
const JWT_ALGORITHM = 'HS256';
const JWT_EXPIRES_IN = '30d';

const JWT_SECRET = process.env.JWT_SECRET;

if (!JWT_SECRET) {
    console.error('[FATAL] JWT_SECRET manquant au demarrage.');
    process.exit(1);
}

if (Buffer.byteLength(JWT_SECRET, 'utf8') < 32) {
    console.error('[FATAL] JWT_SECRET doit contenir au moins 32 octets.');
    process.exit(1);
}

console.log('[CONFIG] JWT_SECRET: configure');

class AuthError extends Error {
    constructor(code, statusCode = 401) {
        super(code);
        this.name = 'AuthError';
        this.code = code;
        this.statusCode = statusCode;
    }
}

function signToken(user) {
    if (!user || user.id === undefined || user.id === null) {
        throw new AuthError('INVALID_USER_ID', 500);
    }

    return jwt.sign(
        {
            sub: String(user.id)
        },
        JWT_SECRET,
        {
            algorithm: JWT_ALGORITHM,
            expiresIn: JWT_EXPIRES_IN,
            issuer: JWT_ISSUER,
            audience: JWT_AUDIENCE,
            jwtid: crypto.randomUUID()
        }
    );
}

function verifyToken(token) {
    let claims;

    try {
        claims = jwt.verify(token, JWT_SECRET, {
            algorithms: [JWT_ALGORITHM],
            issuer: JWT_ISSUER,
            audience: JWT_AUDIENCE
        });
    } catch (err) {
        if (err.name === 'TokenExpiredError') {
            throw new AuthError('TOKEN_EXPIRED', 401);
        }
        throw new AuthError('TOKEN_INVALID', 401);
    }

    if (!claims || typeof claims !== 'object' || Array.isArray(claims)) {
        throw new AuthError('TOKEN_INVALID', 401);
    }

    const expectedClaims = ['aud', 'exp', 'iat', 'iss', 'jti', 'sub'];
    const actualClaims = Object.keys(claims).sort();

    if (
        actualClaims.length !== expectedClaims.length ||
        !expectedClaims.every((key, index) => key === actualClaims[index])
    ) {
        throw new AuthError('TOKEN_INVALID_CLAIMS', 401);
    }

    if (
        typeof claims.sub !== 'string' ||
        claims.sub.length === 0 ||
        !Number.isInteger(claims.iat) ||
        !Number.isInteger(claims.exp) ||
        typeof claims.jti !== 'string' ||
        claims.jti.length === 0 ||
        claims.iss !== JWT_ISSUER ||
        claims.aud !== JWT_AUDIENCE
    ) {
        throw new AuthError('TOKEN_INVALID_CLAIMS', 401);
    }

    return claims;
}

async function loadUserAndCheck(userId, tokenIat) {
    if (
        typeof userId !== 'string' ||
        userId.length === 0 ||
        !Number.isInteger(tokenIat)
    ) {
        throw new AuthError('TOKEN_INVALID_CLAIMS', 401);
    }

    // Validation defensive : users.id est un integer (int4) en base.
    // Rejeter un sub non-numerique en 401 au lieu de laisser PostgreSQL
    // renvoyer une erreur de conversion (qui remonterait en 500).
    const userIdNum = Number(userId);

    if (!Number.isInteger(userIdNum) || userIdNum <= 0) {
        throw new AuthError('TOKEN_INVALID_CLAIMS', 401);
    }

    const result = await pool.query(
        `SELECT
            id,
            role,
            status,
            subscription_expiry,
            password_changed_at
         FROM users
         WHERE id = $1
         LIMIT 1`,
        [userIdNum]
    );

    if (result.rows.length === 0) {
        throw new AuthError('USER_NOT_FOUND', 401);
    }

    const user = result.rows[0];

    if (user.status !== 'ACTIVE') {
        throw new AuthError('ACCOUNT_NOT_ACTIVE', 403);
    }

    const passwordChangedAt = user.password_changed_at;

    if (passwordChangedAt != null) {
        const changedAtMs = new Date(passwordChangedAt).getTime();

        if (!Number.isFinite(changedAtMs)) {
            throw new AuthError('INVALID_ACCOUNT_TIMESTAMP', 500);
        }

        if (tokenIat * 1000 < changedAtMs) {
            throw new AuthError(
                'TOKEN_INVALIDATED_BY_PASSWORD_CHANGE',
                401
            );
        }
    }

    return user;
}

function extractBearerToken(authorization) {
    if (typeof authorization !== 'string') {
        throw new AuthError('AUTH_REQUIRED', 401);
    }
    const match = authorization.match(/^Bearer\s+(\S+)$/i);
    if (!match) {
        throw new AuthError('INVALID_AUTHORIZATION_HEADER', 401);
    }
    return match[1];
}

function sendSafeAuthError(res, error) {
    if (error instanceof AuthError) {
        return res.status(error.statusCode).json({
            success: false,
            code: error.code
        });
    }
    console.error('[AUTH] Erreur interne:', error.message);
    return res.status(500).json({
        success: false,
        code: 'ERR_AUTH_INTERNAL'
    });
}

async function requireAuth(req, res, next) {
    try {
        const token = extractBearerToken(req.headers.authorization);
        const claims = verifyToken(token);
        const user = await loadUserAndCheck(claims.sub, claims.iat);

        req.user = user;
        req.auth = {
            sub: claims.sub,
            iat: claims.iat,
            jti: claims.jti
        };

        return next();
    } catch (error) {
        return sendSafeAuthError(res, error);
    }
}

function requirePremium(req, res, next) {
    if (!req.user) {
        return sendSafeAuthError(
            res,
            new AuthError('AUTH_REQUIRED', 401)
        );
    }
    const expiry = req.user.subscription_expiry;
    const expiryMs = expiry == null
        ? NaN
        : new Date(expiry).getTime();

    if (!Number.isFinite(expiryMs) || expiryMs <= Date.now()) {
        return res.status(403).json({
            success: false,
            code: 'PREMIUM_REQUIRED'
        });
    }
    return next();
}

function requireRole(requiredRole) {
    if (typeof requiredRole !== 'string' || !requiredRole.trim()) {
        throw new TypeError('requiredRole doit etre une chaine non vide.');
    }
    return function roleMiddleware(req, res, next) {
        if (!req.user) {
            return sendSafeAuthError(
                res,
                new AuthError('AUTH_REQUIRED', 401)
            );
        }
        if (req.user.role !== requiredRole) {
            return res.status(403).json({
                success: false,
                code: 'FORBIDDEN'
            });
        }
        return next();
    };
}

module.exports = {
    signToken,
    verifyToken,
    loadUserAndCheck,
    requireAuth,
    requirePremium,
    requireRole,
    AuthError
};
