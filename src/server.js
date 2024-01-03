const net = require('net');
const fs = require('fs');
const crypto = require('crypto');
const { encryptMessage } = require("./utils.js");

const server = net.createServer((socket) => {
    console.log('Client connected');

    const serverHello = 'привіт сервера ' + crypto.randomBytes(16).toString('hex');
    const serverCertificate = fs.readFileSync('server-cert.pem');
w
    socket.write(serverHello);
    socket.write(serverCertificate);

    socket.on('data', (encryptedPremaster) => {
        const decryptedPremaster = crypto.privateDecrypt(
            {
                key: fs.readFileSync('server-key.pem'),
                padding: crypto.constants.RSA_PKCS1_PADDING,
            },
            encryptedPremaster
        );
        const sessionKeys = generateSessionKeys(decryptedPremaster);

        const readyMessage = 'готовий';
        const encryptedReadyMessage = encryptMessage(sessionKeys.serverKey, readyMessage);
        socket.write(encryptedReadyMessage);

        const handshakeCompletionMessage = 'Здійснюється безпечне симетричне шифрування. Рукостискання завершено. Зв\'язок продовжується за допомогою ключів сеансу.';
        const encryptedCompletionMessage = encryptMessage(sessionKeys.serverKey, handshakeCompletionMessage);
        socket.write(encryptedCompletionMessage);

        socket.end();
    });

    socket.on('end', () => {
        console.log('Client disconnected');
    });
});

const serverPort = 3000;
server.listen(serverPort, () => {
    console.log(`Server listening on port ${serverPort}`);
});

function generateSessionKeys() {
    const clientKey = crypto.randomBytes(32).toString('hex'); // 256 біт
    const serverKey = crypto.randomBytes(32).toString('hex'); // 256 біт

    return { clientKey, serverKey };
}
