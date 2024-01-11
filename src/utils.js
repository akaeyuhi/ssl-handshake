'use strict';
const crypto = require('crypto');
const readline = require('node:readline');

class Client {
  random = '';
  id = '';
  sessionKeys = null;
  socket = null;
  hashes = [];

  constructor(id, random, socket) {
    this.id = id;
    this.random = random;
    this.socket = socket;
  }

  set keys(sessionKeys) {
    this.sessionKeys = sessionKeys;
  }
}

function encryptMessage(key, message) {
  const iv = crypto.randomBytes(16);
  const cipher = crypto.createCipheriv('aes-256-cbc', key, iv);
  try {
    const encrypted = Buffer.concat([cipher.update(message, 'utf-8'), cipher.final()]);
    return Buffer.concat([iv, encrypted]);
  } catch (e) {
    console.error(e);
    return e;
  }
}

function decryptMessage(key, encryptedMessage) {
  const encryptedString = Buffer.from(encryptedMessage);
  const iv = encryptedString.subarray(0, 16);
  const encrypted = encryptedString.subarray(16);

  const decipher = crypto.createDecipheriv('aes-256-cbc', key, iv);
  try {
    const decrypted = Buffer.concat([decipher.update(encrypted), decipher.final()]);
    return decrypted.toString('utf-8');
  } catch (e) {
    console.error(e);
    return e;
  }
}

const calculateHash = (prevHash, data) => {
  const hash = crypto.createHash('sha256');
  hash.update(prevHash + data);
  return hash.digest('hex');
};

const isValidBlock = (message, hash, prevHash) => {
  const calculatedHash = calculateHash(prevHash, message);
  return calculatedHash === hash;
};

const verifyCertificate = certificate => {
  const knownIssuers = [
    'C=AU\nST=Some-State\nO=Internet Widgits Pty Ltd',
    'C=UA\nST=Zhytomyr-Region\nO=Readme Experts Ltd',
    'C=UA\nST=Zhytomyr-Region\nL=Zhytomyr\nO=Readme Experts\nCN=AkaeYuhi'
  ];
  try {
    const parsedCertificate = new crypto.X509Certificate(certificate);

    const isTrusted = knownIssuers.includes(parsedCertificate.issuer);

    const isNotExpired = new Date(parsedCertificate.validTo) > new Date();

    return isTrusted && isNotExpired;
  } catch (error) {
    console.error('Error verifying certificate:', error);
    return false;
  }
};

function generateSessionKeys(clientRandom, serverRandom, premaster) {
  // Об'єднання клієнтського та серверного випадкових рядків з секретом premaster
  const combinedSecret = clientRandom + serverRandom + premaster;

  // Генерація ключів сесії на клієнті та сервері на основі комбінованого секрету
  const hashedCombinedSecret = crypto.createHash('sha256').update(combinedSecret).digest('hex');

  const clientKey = hashedCombinedSecret.substring(0, 32);  // перші 32 байти для клієнта
  const serverKey = hashedCombinedSecret.substring(32);    // наступні 32 байти для сервера

  return { clientKey, serverKey };
}

function getMessageFromData(message = '', payload = {}) {
  return JSON.stringify({ message, ...payload });
}

async function* questions(query) {
  const rl = readline.createInterface({
    input: process.stdin,
    output: process.stdout
  });

  try {
    for (; ;) {
      yield new Promise(resolve => rl.question(query, resolve));
    }
  } finally {
    rl.close();
  }
}

module.exports = {
  Client,
  encryptMessage,
  verifyCertificate,
  decryptMessage,
  generateSessionKeys,
  getMessageFromData,
  questions,
  calculateHash,
  isValidBlock
};
