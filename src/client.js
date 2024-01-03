const net = require('net');
const fs = require('fs');
const crypto = require('crypto');
const { encryptMessage, verifyCertificate, decryptMessage, extractSessionKeys, generateSessionKeys} = require('./utils.js');

let sessionKeys;
let clientRandom;
let serverRandom;

const client = net.createConnection({ port: 3000 }, () => {
    console.log('Connected to server');
    clientRandom = crypto.randomBytes(16).toString('hex');
    const helloMessage = 'привіт ' + clientRandom;
    client.write(helloMessage);
});

client.on('data', (data) => {
    const receivedData = data.toString();
    console.log(receivedData);

    if (receivedData.startsWith('привіт сервера')) {
        serverRandom = receivedData.substring('привіт сервера'.length);
    }
    else if (receivedData.startsWith('сертифікат')) {
        const cert = receivedData.substring('сертифікат'.length);

        // Step 3: Автентифікація
        console.log('Server Certificate:', cert);

        // Перевірка сертифікату сервера
        const isCertificateValid = verifyCertificate(cert);

        if (isCertificateValid) {
            console.log('Server certificate verified by client');

            // Step 4: Обмін секретними рядками
            const premasterSecret = 'ThisIsPremasterSecret';
            const encryptedPremaster = crypto.publicEncrypt(
                {
                    key: cert,
                    padding: crypto.constants.RSA_PKCS1_PADDING,
                },
                Buffer.from(premasterSecret)
            );
            client.write('premaster ' + encryptedPremaster);
            sessionKeys = generateSessionKeys(clientRandom, serverRandom, premasterSecret);
        } else {
            console.log('Server certificate verification failed');
            client.end();
        }
    } else {
        const decryptedMessage = decryptMessage(sessionKeys.clientKey, receivedData);
        if (decryptedMessage === 'готовий') {
            const readyMessage = 'готовий';
            const encryptedReadyMessage = encryptMessage(sessionKeys.clientKey, readyMessage);
            client.write(encryptedReadyMessage);

            const handshakeCompletionMessage = 'Отримано ключі сесії. Зв\'язок продовжується за допомогою ключів сеансу.';
            const encryptedCompletionMessage = encryptMessage(sessionKeys.clientKey, handshakeCompletionMessage);
            client.write(encryptedCompletionMessage);
        } else {
            console.log('Server Response:', receivedData);
            console.log('Decrypted Message:', decryptedMessage);
        }
    }
});

client.on('end', () => {
    console.log('Connection closed');
});
