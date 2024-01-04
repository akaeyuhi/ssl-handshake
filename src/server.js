'use strict';
const net = require('net');
const fs = require('fs');
const crypto = require('crypto');
const { encryptMessage, generateSessionKeys, decryptMessage } = require('./utils.js');
const { getMessageFromData } = require('./utils');

class Client {
  random = '';
  sessionKeys = null;

  constructor(random) {
    this.random = random;
  }
  set keys(sessionKeys) {
    this.sessionKeys = sessionKeys;
  }
}

const clients = [];
const sockets = new Set();
const server = net.createServer(socket => {
  console.log('Client connected');
  sockets.add(socket);

  const serverRandom = crypto.randomBytes(16).toString('hex');
  const serverCertificate = fs.readFileSync('./keys/server-cert.pem');
  const initPayload = { random: serverRandom, certificate: serverCertificate };
  const serverKey = fs.readFileSync('./keys/server-key.pem');

  const sendMessage = (message, keys, userId = serverRandom, payload = {}) => {
    const encryptedMessage = encryptMessage(keys.serverKey, message);
    socket.write(getMessageFromData(encryptedMessage, { userId, ...payload }));
  };

  socket.write(getMessageFromData('привіт сервера', { ...initPayload }));

  socket.on('data', data => {
    let receivedData = null;
    try {
      receivedData = JSON.parse(data.toString());
    } catch (e) {
      console.error(e);
      socket.end();
    }

    if (receivedData && receivedData.message === 'привіт') {
      clients.push(new Client(receivedData.random));
    } else if (receivedData && receivedData.message === 'premaster') {
      const decryptedPremaster = crypto.privateDecrypt(
        {
          key: serverKey,
          padding: crypto.constants.RSA_PKCS1_PADDING,
        },
        Buffer.from(receivedData.premaster),
      );
      const client = clients.find(item => item.random === receivedData.userId);
      client.keys = generateSessionKeys(client.random, serverRandom, decryptedPremaster);

      console.log(client);

      const readyMessage = 'готовий';
      sendMessage(readyMessage, client.sessionKeys);
    } else if (receivedData && receivedData.message) {
      const keys = clients.find(item => item.random === receivedData.userId).sessionKeys;
      const decryptedMessage = decryptMessage(keys.clientKey, receivedData.message);
      if (decryptedMessage === 'готовий') {
        const handshakeCompletionMessage = 'Здійснюється безпечне симетричне шифрування. ' +
          'Рукостискання завершено. ' +
          'Зв\'язок продовжується за допомогою ключів сеансу.';
        sendMessage(handshakeCompletionMessage, keys);
      } else {
        console.log(`user ${receivedData.userId}: ` + decryptedMessage);
        if (receivedData.userId !== serverRandom) {
          sendMessage(decryptedMessage, keys, receivedData.userId);
        }
      }
    }
  });

  socket.on('end', () => {
    console.log('Client disconnected');
    sockets.delete(socket);
  });
});

const serverPort = 3000;
server.listen(serverPort, () => {
  console.log(`Server listening on port ${serverPort}`);
});
