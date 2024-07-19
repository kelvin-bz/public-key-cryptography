const crypto = require('crypto');
const { generateKeyPairSync } = crypto; // Import generateKeyPairSync

// ----- Digital Signature Functions -----

function signData(privateKey, data) {
    const sign = crypto.createSign('RSA-SHA256');
    sign.update(data);
    return sign.sign(privateKey, 'base64');
}

function verifySignature(publicKey, data, signature) {
    const verify = crypto.createVerify('RSA-SHA256');
    verify.update(data);
    return verify.verify(publicKey, signature, 'base64');
}

// ----- Example Usage (Signing Only) -----

const { publicKey, privateKey } = generateKeyPairSync('rsa', {
    modulusLength: 2048,
    publicKeyEncoding: { type: 'spki', format: 'pem' },
    privateKeyEncoding: { type: 'pkcs8', format: 'pem' }
});

const dataToSign = 'This is the important document I want to sign.';

// Sign the data
const signature = signData(privateKey, dataToSign);
console.log('Signature:', signature);

// Verify the signature (just for demonstration)
const isSignatureValid = verifySignature(publicKey, dataToSign, signature);
console.log('Is Signature Valid?', isSignatureValid);
