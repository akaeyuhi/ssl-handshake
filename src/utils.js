const crypto = require('crypto');

function encryptMessage(key, message) {
    const iv = crypto.randomBytes(16);
    const cipher = crypto.createCipheriv('aes-256-cbc', key, iv);
    const encrypted = Buffer.concat([cipher.update(message, 'utf-8'), cipher.final()]);
    return Buffer.concat([iv, encrypted]);
}

function decryptMessage(key, encryptedMessage) {
    // Розшифрування повідомлення сеансовим ключем
    const iv = encryptedMessage.slice(0, 16);
    const encrypted = encryptedMessage.slice(16);

    const decipher = crypto.createDecipheriv('aes-256-cbc', key, iv);
    const decrypted = Buffer.concat([decipher.update(encrypted), decipher.final()]);
    return decrypted.toString('utf-8');
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

module.exports = { encryptMessage, verifyCertificate, decryptMessage, generateSessionKeys };
