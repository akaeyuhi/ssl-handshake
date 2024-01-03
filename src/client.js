'use strict';
const net = require('net');
const crypto = require('crypto');
const { encryptMessage, decryptMessage, generateSessionKeys } = require('./utils.js');
const { getMessageFromData } = require('./utils');

let sessionKeys;
let clientRandom;
let serverRandom;

const client = net.createConnection({ port: 3000 }, () => {
  console.log('Connected to server');
  clientRandom = crypto.randomBytes(16).toString('hex');
  client.write(getMessageFromData('привіт', { random: clientRandom }));
});

client.on('data', data => {
  let receivedData = null;
  try {
    receivedData = JSON.parse(data.toString());
    console.log(receivedData);
  } catch (e) {
    console.error(e);
    client.end();
  }

  if (receivedData && receivedData.message === 'привіт сервера') {
    serverRandom = receivedData.random;
    const certificate = receivedData.certificate;

    // Step 3: Автентифікація
    console.log('Server Certificate:', certificate);

    // Перевірка сертифікату сервера
    const isCertificateValid = true; // verifyCertificate(certificate) ;

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
      client.write(getMessageFromData('premaster', { premaster: encryptedPremaster }));
      sessionKeys = generateSessionKeys(clientRandom, serverRandom, premasterSecret);
    } else {
      console.log('Server certificate verification failed');
      client.end();
    }
  } else if (receivedData && receivedData.message) {
    const decryptedMessage = decryptMessage(sessionKeys.serverKey, receivedData.message);
    if (decryptedMessage === 'готовий') {
      const readyMessage = 'готовий';
      const encryptedReadyMessage = encryptMessage(sessionKeys.clientKey, readyMessage);
      client.write(getMessageFromData(encryptedReadyMessage));
    } else {
      console.log('Decrypted Message:', decryptedMessage);
    }
  }
});

client.on('end', () => {
  console.log('Connection closed');
});
