const crypto = require('crypto');

// Function to encrypt data using the public key
function encryptAsymmetric(publicKey, plaintext) {
    const buffer = Buffer.from(plaintext, 'utf8');
    const encrypted = crypto.publicEncrypt(publicKey, buffer);
    return encrypted.toString('base64');
}

// Function to decrypt data using the private key
function decryptAsymmetric(privateKey, ciphertext) {
    const buffer = Buffer.from(ciphertext, 'base64');
    const decrypted = crypto.privateDecrypt(privateKey, buffer);
    return decrypted.toString('utf8');
}

// Example Usage
const { generateKeyPairSync } = require('crypto');
const { publicKey, privateKey } = generateKeyPairSync('rsa', {
    modulusLength: 2048,
    publicKeyEncoding: {
        type: 'spki',
        format: 'pem'
    },
    privateKeyEncoding: {
        type: 'pkcs8',
        format: 'pem'
    }
});

const originalText = 'This is a secret message.';

const ciphertext = encryptAsymmetric(publicKey, originalText);
console.log('Ciphertext:', ciphertext);

const decryptedText = decryptAsymmetric(privateKey, ciphertext);
console.log('Decrypted Text:', decryptedText);
