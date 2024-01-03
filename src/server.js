const net = require('net');
const fs = require('fs');
const crypto = require('crypto');
const { encryptMessage, generateSessionKeys, decryptMessage} = require('./utils.js');

const server = net.createServer((socket) => {
    console.log('Client connected');

    let clientRandom;
    let serverRandom;
    let sessionKeys;

    serverRandom = crypto.randomBytes(16).toString('hex');
    serverRandom = crypto.randomBytes(16).toString('hex');
    const serverCertificate = fs.readFileSync('./keys/server-cert.pem');
    const serverHello = { message: 'привіт сервера', random: serverRandom, certificate: serverCertificate.toString() };
    const serverKey = fs.readFileSync('./keys/server-key.pem');

    socket.write(JSON.stringify(serverHello));

    socket.on('data', (data) => {
        const receivedData = JSON.parse(data.toString());
        console.log(receivedData);

        if (receivedData.message === 'привіт') {
            clientRandom = receivedData.random;
        } else if (receivedData.message === 'premaster') {
            const decryptedPremaster = crypto.privateDecrypt(
                {
                    key: serverKey,
                    padding: crypto.constants.RSA_PKCS1_PADDING,
                },
                Buffer.from(receivedData.premaster),
            );

            sessionKeys = generateSessionKeys(clientRandom, serverRandom, decryptedPremaster);

            const readyMessage = 'готовий';
            const encryptedReadyMessage = encryptMessage(sessionKeys.serverKey, readyMessage);
            const json = { message: encryptedReadyMessage };
            socket.write(JSON.stringify(json));
        } else if (receivedData.message) {
            const decryptedMessage = decryptMessage(sessionKeys.clientKey, receivedData.message);
            if (decryptedMessage === 'готовий') {
                const handshakeCompletionMessage = 'Здійснюється безпечне симетричне шифрування. Рукостискання завершено. Зв\'язок продовжується за допомогою ключів сеансу.';
                const encryptedCompletionMessage = encryptMessage(sessionKeys.serverKey, handshakeCompletionMessage);
                const json = { message: encryptedCompletionMessage };
                socket.write(JSON.stringify(json));
            }
            //socket.end();
        }
    });

    socket.on('end', () => {
        console.log('Client disconnected');
    });
});

const serverPort = 3000;
server.listen(serverPort, () => {
    console.log(`Server listening on port ${serverPort}`);
});
