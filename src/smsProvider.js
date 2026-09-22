'use strict';

const config = require('./config');

class StubSmsProvider {
    async sendOtp(phone, otp) {
        if (config.SMS_PROVIDER !== 'STUB') {
            throw new Error('SMS_PROVIDER_ERROR: StubSmsProvider utilisé alors que SMS_PROVIDER != STUB.');
        }

        const phoneString = String(phone);
        const truncatedPhone =
            phoneString.length > 5
                ? `${phoneString.slice(0, 2)}****${phoneString.slice(-3)}`
                : '****';

        console.log(`[STUB-SMS] phone=${truncatedPhone} otp=${otp}`);

        return {
            success: true,
            provider: 'STUB'
        };
    }
}

module.exports = Object.freeze({
    StubSmsProvider
});
