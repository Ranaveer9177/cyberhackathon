const crypto = require('crypto');

function parseConfig(raw) {
    const parsed = JSON.parse(raw);
    const token = crypto.randomBytes(32).toString('hex');
    return { parsed, token };
}
