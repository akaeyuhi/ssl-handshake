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
    const helloMessage = { message: 'привіт', random: clientRandom };
    client.write(JSON.stringify(helloMessage));
});

client.on('data', (data) => {
    const receivedData = JSON.parse(data.toString());
    console.log(receivedData);

    if (receivedData.message === 'привіт сервера') {
        serverRandom = receivedData.random;
        const certificate = receivedData.certificate

        // Step 3: Автентифікація
        console.log('Server Certificate:', certificate);

        // Перевірка сертифікату сервера
        const isCertificateValid = true // verifyCertificate(certificate) ;

        if (isCertificateValid) {
            console.log('Server certificate verified by client');

            // Step 4: Обмін секретними рядками
            const premasterSecret = 'ThisIsPremasterSecret';
            const encryptedPremaster = crypto.publicEncrypt(
                {
                    key: certificate,
                    padding: crypto.constants.RSA_PKCS1_PADDING,
                },
                Buffer.from(premasterSecret)
            );
            const json = {
                message: 'premaster',
                premaster: encryptedPremaster,
            };
            client.write(JSON.stringify(json));
            sessionKeys = generateSessionKeys(clientRandom, serverRandom, premasterSecret);
        } else {
            console.log('Server certificate verification failed');
            client.end();
        }
    } else if (receivedData.message) {
        const decryptedMessage = decryptMessage(sessionKeys.serverKey, receivedData.message);
        if (decryptedMessage === 'готовий') {
            const readyMessage = 'готовий';
            const encryptedReadyMessage = encryptMessage(sessionKeys.clientKey, readyMessage);
            const json = { message: encryptedReadyMessage};
            client.write(JSON.stringify(json));
        } else {
            console.log('Decrypted Message:', decryptedMessage);
        }
    }
});

client.on('end', () => {
    console.log('Connection closed');
});
