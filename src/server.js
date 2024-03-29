'use strict';
const net = require('net');
const fs = require('fs');
const crypto = require('crypto');
const {
  Client,
  encryptMessage,
  generateSessionKeys,
  decryptMessage,
  getMessageFromData,
  calculateHash
} = require('./utils.js');
const { isValidBlock } = require('./utils');



let clients = [];
const server = net.createServer(socket => {
  console.log('Client connected');

  const serverRandom = crypto.randomBytes(16).toString('hex');
  const serverCertificate = fs.readFileSync('./keys/server-cert.pem');
  const initPayload = { random: serverRandom, certificate: serverCertificate };
  const serverKey = fs.readFileSync('./keys/server-key.pem');

  socket.write(getMessageFromData('привіт сервера', initPayload));

  const sendMessage = (message, keys, userId = serverRandom, payload = {}) => {
    const client = clients.find(item => item.socket === socket);

    if (client) {
      const hash = calculateHash(client.hashes[client.hashes.length - 1], message);
      client.hashes.push(hash);
      const encryptedMessage = encryptMessage(keys.serverKey, message);
      socket.write(getMessageFromData(encryptedMessage, { userId, hash, ...payload }));
    }
  };

  const sendToAll = (message, userId) => {
    for (const client of clients) {
      if (client.socket !== socket) {
        const encryptedMessage = encryptMessage(client.sessionKeys.serverKey, message);
        client.socket.write(getMessageFromData(encryptedMessage, { userId }));
      }
    }
  };

  socket.on('data', data => {
    let receivedData = null;
    try {
      receivedData = JSON.parse(data.toString());
      console.dir(receivedData);
    } catch (e) {
      console.error(e);
      socket.end();
    }

    if (receivedData && receivedData.message === 'привіт') {
      clients.push(new Client(receivedData.userId, receivedData.random, socket));
    } else if (receivedData && receivedData.message === 'premaster') {
      const decryptedPremaster = crypto.privateDecrypt(
        {
          key: serverKey,
          padding: crypto.constants.RSA_PKCS1_PADDING
        },
        Buffer.from(receivedData.premaster)
      );
      const client = clients.find(item => item.id === receivedData.userId);
      client.keys = generateSessionKeys(client.random, serverRandom, decryptedPremaster);

      const readyMessage = 'готовий';
      sendMessage(readyMessage, client.sessionKeys);

    } else if (receivedData && receivedData.message) {
      const client = clients.find(item => item.socket === socket);
      const keys = client.sessionKeys;
      const decryptedMessage = decryptMessage(keys.clientKey, receivedData.message);

      if (isValidBlock(decryptedMessage, receivedData.hash,
        client.hashes[client.hashes.length - 1]) ||
        !client.hashes.length) {
        client.hashes.push(receivedData.hash);
      } else {
        return console.log('Invalid block received. Discarding message.');
      }

      if (decryptedMessage === 'готовий') {
        const handshakeCompletionMessage = 'Здійснюється безпечне симетричне шифрування. ' +
          'Рукостискання завершено. ' +
          'Зв\'язок продовжується за допомогою ключів сеансу.';
        sendMessage(handshakeCompletionMessage, keys);
      } else {
        console.log(`user ${receivedData.userId}: ` + decryptedMessage);
        console.log(receivedData.userId, client.hashes);
        if (receivedData.userId !== serverRandom) {
          sendToAll(decryptedMessage, receivedData.userId);
        }
      }
    }
  });

  socket.on('end', () => {
    console.log('Client disconnected');
    clients = clients.filter(item => item.socket !== socket);
  });
});

const serverPort = 3000;
server.listen(serverPort, () => {
  console.log(`Server listening on port ${serverPort}`);
});
