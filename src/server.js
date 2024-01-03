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
    const serverHello = 'привіт сервера ' + serverRandom;
    serverRandom = crypto.randomBytes(16).toString('hex');
    const serverCertificate = fs.readFileSync('./keys/server-cert.pem');

    socket.write(serverHello);
    //socket.write('сертифікат ' + serverCertificate);

    socket.on('data', (data) => {
        const receivedData = data.toString();
        console.log(receivedData);

        if (receivedData.startsWith('привіт')) {
            clientRandom = receivedData.substring('привіт'.length);
        } else if (receivedData.startsWith('premaster')) {
            const decryptedPremaster = crypto.privateDecrypt(
                {
                    key: serverCertificate,
                    padding: crypto.constants.RSA_PKCS1_PADDING,
                },
                data
            );

            sessionKeys = generateSessionKeys(clientRandom, serverRandom, decryptedPremaster);

            const readyMessage = 'готовий';
            const encryptedReadyMessage = encryptMessage(sessionKeys.serverKey, readyMessage);
            socket.write(encryptedReadyMessage);
        } else {
            const decryptedMessage = decryptMessage(sessionKeys.clientKey, receivedData);
            if (decryptedMessage === 'готовий') {
                const handshakeCompletionMessage = 'Здійснюється безпечне симетричне шифрування. Рукостискання завершено. Зв\'язок продовжується за допомогою ключів сеансу.';
                const encryptedCompletionMessage = encryptMessage(sessionKeys.serverKey, handshakeCompletionMessage);
                socket.write(encryptedCompletionMessage);
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
