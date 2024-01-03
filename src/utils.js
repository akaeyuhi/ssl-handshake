const crypto = require('crypto');

function encryptMessage(key, message) {
    const iv = crypto.randomBytes(16);
    const cipher = crypto.createCipheriv('aes-256-cbc', key, iv);
    const encrypted = Buffer.concat([cipher.update(message, 'utf-8'), cipher.final()]);
    return Buffer.concat([iv, encrypted]);
}

module.exports = { encryptMessage };
