'use strict';
const net = require('net');
const crypto = require('crypto');
const {
  encryptMessage,
  decryptMessage,
  generateSessionKeys,
  getMessageFromData,
  verifyCertificate
} = require('./utils.js');
const readline = require('node:readline');

let sessionKeys;
let clientRandom;
let serverRandom;

const client = net.createConnection({ port: 3000 }, () => {
  console.log('Connected to server');
  clientRandom = crypto.randomBytes(16).toString('hex');
  client.write(getMessageFromData('привіт', { random: clientRandom }));
});

const sendMessage = (message, payload = {}) => {
  const encryptedMessage = encryptMessage(sessionKeys.clientKey, message);
  client.write(getMessageFromData(encryptedMessage, { userId: clientRandom, ...payload }));
};

const chat = async () => {
  console.log('Enter your message. Type /end to exit\n');
  for await (const answer of questions('')) {
    if (answer === '/end') break;
    sendMessage(answer);
  }
  sendMessage('Disconnected!\n');
  client.end();
};

async function* questions(query) {
  const rl = readline.createInterface({
    input: process.stdin,
    output: process.stdout,
  });

  try {
    for (;;) {
      yield new Promise(resolve => rl.question(query, resolve));
    }
  } finally {
    rl.close();
  }
}

client.on('data', data => {
  let receivedData = null;
  try {
    receivedData = JSON.parse(data.toString());
  } catch (e) {
    console.error(e);
    client.end();
  }

  if (receivedData && receivedData.message === 'привіт сервера') {
    serverRandom = receivedData.random;
    const certificate = Buffer.from(receivedData.certificate);
    console.log('Server Certificate:', certificate.toString());

    // Перевірка сертифікату сервера
    const isCertificateValid = verifyCertificate(certificate);

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
      client.write(getMessageFromData(
        'premaster',
        { premaster: encryptedPremaster, userId: clientRandom }));
      sessionKeys = generateSessionKeys(clientRandom, serverRandom, premasterSecret);
    } else {
      console.log('Server certificate verification failed');
      client.end();
    }
  } else if (receivedData && receivedData.message) {
    const decryptedMessage = decryptMessage(sessionKeys.serverKey, receivedData.message);
    if (decryptedMessage === 'готовий') {
      const readyMessage = 'готовий';
      sendMessage(readyMessage);
      chat().then();
    } else if (receivedData.userId !== clientRandom && receivedData.userId === serverRandom) {
      console.log(`user server:`, decryptedMessage);
    } else if (receivedData.userId !== clientRandom) {
      console.log(`user ${receivedData.userId}:`, decryptedMessage);
    }
  }
});

client.on('end', () => {
  console.log('Connection closed');
});
