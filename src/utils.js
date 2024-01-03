const crypto = require('crypto');

function encryptMessage(key, message) {
    const iv = crypto.randomBytes(16);
    const cipher = crypto.createCipheriv('aes-256-cbc', key, iv);
    try {
        const encrypted = Buffer.concat([cipher.update(message, 'utf-8'), cipher.final()]);
        return Buffer.concat([iv, encrypted]);
    } catch (e) {
        console.error(e);
        return e;
    }
}

function decryptMessage(key, encryptedMessage) {
    const encryptedString = Buffer.from(encryptedMessage);
    // Розшифрування повідомлення сеансовим ключем
    const iv = encryptedString.subarray(0, 16);
    const encrypted = encryptedString.subarray(16);

    const decipher = crypto.createDecipheriv('aes-256-cbc', key, iv);
    try {
        const decrypted = Buffer.concat([decipher.update(encrypted), decipher.final()]);
        return decrypted.toString('utf-8');
    } catch (e) {
        console.error(e);
        return e;
    }
}

function verifyCertificate(certificate) {
    const knownCertificates = ['server1-cert', 'server2-cert', 'server3-cert'];
    return knownCertificates.includes(certificate);
}

function generateSessionKeys(clientRandom, serverRandom, premaster) {
    // Об'єднання клієнтського та серверного випадкових рядків з секретом premaster
    const combinedSecret = clientRandom + serverRandom + premaster;

    // Генерація ключів сесії на клієнті та сервері на основі комбінованого секрету
    const hashedCombinedSecret = crypto.createHash('sha256').update(combinedSecret).digest('hex');

    const clientKey = hashedCombinedSecret.substring(0, 32);  // перші 32 байти для клієнта
    const serverKey = hashedCombinedSecret.substring(32);    // наступні 32 байти для сервера

    return { clientKey, serverKey };
}

function getMessageFromData(message = '', payload = {}) {
    return JSON.stringify({ message, ...payload});
}

module.exports = { encryptMessage, verifyCertificate, decryptMessage, generateSessionKeys, getMessageFromData };
