'use strict';
const net = require('net');
const crypto = require('crypto');
const { v4: uuidv4 } = require('uuid');
const {
  encryptMessage,
  decryptMessage,
  generateSessionKeys,
  getMessageFromData,
  verifyCertificate,
  questions
} = require('./utils.js');
const { calculateHash, isValidBlock } = require('./utils');

let sessionKeys;
let clientRandom;
let serverRandom;
let clientId;
const clientHashes = [];

const client = net.createConnection({ port: 3000 }, () => {
  console.log('Connected to server');
  clientRandom = crypto.randomBytes(16).toString('hex');
  clientId = uuidv4();
  client.write(getMessageFromData('привіт', { userId: clientId, random: clientRandom }));
});

const sendMessage = (message, payload = {}) => {
  const prevHash = clientHashes ? clientHashes[clientHashes.length - 1] : '';
  const hash = calculateHash(prevHash, message);
  clientHashes.push(hash);
  const encryptedMessage = encryptMessage(sessionKeys.clientKey, message);
  client.write(getMessageFromData(encryptedMessage, { userId: clientId, hash, ...payload }));
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

      const premasterSecret = crypto.randomBytes(16).toString('hex');
      const encryptedPremaster = crypto.publicEncrypt(
        {
          key: certificate,
          padding: crypto.constants.RSA_PKCS1_PADDING
        },
        Buffer.from(premasterSecret)
      );
      client.write(getMessageFromData(
        'premaster',
        { premaster: encryptedPremaster, userId: clientId }));
      sessionKeys = generateSessionKeys(clientRandom, serverRandom, premasterSecret);
    } else {
      console.log('Server certificate verification failed');
      client.end();
    }
  } else if (receivedData && receivedData.message) {

    const decryptedMessage = decryptMessage(sessionKeys.serverKey, receivedData.message);

    if (isValidBlock(decryptedMessage, receivedData.hash, clientHashes[clientHashes.length - 1]) ||
      !clientHashes[clientHashes.length - 1]) {
      clientHashes.push(receivedData.hash);
    } else {
      return console.log('Invalid block received. Discarding message.');
    }
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
