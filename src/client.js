const net = require('net');
const fs = require('fs');
const crypto = require('crypto');
const { encryptMessage } = require("./utils.js");

const client = net.createConnection({ port: 3000 }, () => {
    console.log('Connected to server');
    const helloMessage = 'привіт ' + crypto.randomBytes(16).toString('hex');
    client.write(helloMessage);
});

client.on('data', (data) => {
    const receivedData = data.toString();

    if (receivedData.startsWith('привіт сервера')) {
        console.log('Server Certificate:', receivedData.substring('привіт сервера'.length));
    } else {
        const premasterSecret = 'ThisIsPremasterSecret';
        const encryptedPremaster = crypto.publicEncrypt(
            {
                key: fs.readFileSync('server-cert.pem'),
                padding: crypto.constants.RSA_PKCS1_PADDING,
            },
            Buffer.from(premasterSecret)
        );

        const sessionKeys = generateSessionKeys(encryptedPremaster);

        const readyMessage = 'готовий';
        const encryptedReadyMessage = encryptMessage(sessionKeys.clientKey, readyMessage);
        client.write(encryptedReadyMessage);
    }
});

client.on('end', () => {
    console.log('Connection closed');
});

function generateSessionKeys(encryptedPremaster) {
    const decryptedPremaster = crypto.privateDecrypt(
        {
            key: fs.readFileSync('client-key.pem'),
            padding: crypto.constants.RSA_PKCS1_PADDING,
        },
        encryptedPremaster
    );

    const clientKey = crypto.randomBytes(32).toString('hex');
    const serverKey = crypto.randomBytes(32).toString('hex');

    return { clientKey, serverKey };
}
