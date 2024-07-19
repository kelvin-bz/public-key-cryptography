# Public key cryptography
Public key cryptography is a method of encrypting or signing data with two different keys and making one of the keys, the public key, available for anyone to use. The other key is known as the private key. Data encrypted with the public key can only be decrypted with the private key.

Full article at https://kelvin-bz.github.io/posts/public-key-cryptography/
## PEM Format for Keys


```mermaid
graph TD
    pemFile["fa:fa-file-code PEM File for Public Key"] --> header["fa:fa-header Header"]
    pemFile --> base64Content["fa:fa-file-code Base64 Encoded Content"]
    pemFile --> footer["fa:fa-footer Footer"]

    base64Content --> originalBinaryData["fa:fa-binary Original Binary Data"]
    originalBinaryData --> publicKeyComponents["fa:fa-key Public Key Components"]

    header -->|Public Key| headerContent["fa:fa-key -----BEGIN PUBLIC KEY-----"]
    footer -->|Public Key| footerContent["fa:fa-key -----END PUBLIC KEY-----"]

    classDef header fill:#ffcc00,stroke:#333,stroke-width:2px;
    classDef footer fill:#ff6600,stroke:#333,stroke-width:2px;
    classDef data fill:#66ccff,stroke:#333,stroke-width:2px;

    style pemFile fill:#ffffff,stroke:#333,stroke-width:2px;
    style header fill:#ffcc00,stroke:#333,stroke-width:2px;
    style base64Content fill:#66ccff,stroke:#333,stroke-width:2px;
    style footer fill:#ff6600,stroke:#333,stroke-width:2px;
    style originalBinaryData fill:#66ccff,stroke:#333,stroke-width:2px;
    style publicKeyComponents fill:#66ccff,stroke:#333,stroke-width:2px;

    subgraph pemStructure["PEM File Structure"]
        pemFile
        header
        base64Content
        footer
    end
```

The PEM (Privacy-Enhanced Mail) format is a widely used format for encoding cryptographic keys and certificates. It uses Base64 encoding to represent binary data and typically includes header and footer lines that identify the type of encoded data. For example, a PEM-encoded RSA private key might look like this:

```
-----BEGIN RSA PRIVATE KEY-----
MIIEowIBAAKCAQEA7XwH4q2+1T...
-----END RSA PRIVATE KEY-----
```

PEM files can contain various types of data, such as private keys, public keys, and certificates, and are commonly used in SSL/TLS configurations and other cryptographic applications.

## RSA algorithm Overview

The RSA algorithm relies on prime numbers to generate a modulus and exponents that form the public and private keys. These keys are stored in PEM files, which facilitate secure key exchange and storage. RSA key sizes vary, with larger sizes offering better security

Common key sizes include:

- 1024 bits: Considered insecure for most applications today.
- 2048 bits: Provides a good balance between security and performance, widely used.
- 3072 bits: Offers higher security, recommended for more sensitive data.
- 4096 bits: Provides very high security but at the cost of performance, used in highly secure environments.


Even if a hacker can find the public key and ciphertext, it takes an enormous amount of computational effort to determine the secret data. The resources required for such an attack (time, computational power, and energy) are far beyond the reach of any individual or organization, making RSA a robust choice for securing data in transit.


## Encrypt with the recipient's public key (Confidentiality).

```mermaid
graph TD
    subgraph senders["fa:fa-users Many Senders"]
        sender1["fa:fa-user Sender 1"]:::inputNode
        sender2["fa:fa-user Sender 2"]:::inputNode
        sender3["fa:fa-user Sender 3"]:::inputNode
        publicKey["fa:fa-key Public Key"]
    end
    
    recipient["fa:fa-user-shield Recipient"]:::outputNode
    
    subgraph recipient["fa:fa-user-shield Recipient"]
        privateKey["fa:fa-lock Private Key"]
    end


    senders --> encryptionProcess["fa:fa-lock Encryption Process "]:::encryptionNode
    encryptionProcess --> ciphertext["fa:fa-file-code Ciphertext"]:::outputNode
    ciphertext --> recipient

    classDef inputNode fill:#ffcccc,stroke:#333,stroke-width:2px;
    classDef encryptionNode fill:#e6f2ff,stroke:#0066cc,stroke-width:2px;
    classDef outputNode fill:#ccffcc,stroke:#333,stroke-width:2px;

```
This ensures that only the recipient, who holds the corresponding private key, can decrypt the message. This is the most common scenario for secure communication.

- **Secure Messaging Apps (End-to-End Encryption)**:
  Apps like Signal, WhatsApp, and Telegram use public key encryption to ensure that only the intended recipient can read your messages. Your message is encrypted with the recipient's public key, and only their private key can decrypt it.



## Signing with your private key (Authentication and Integrity)

```mermaid
graph TD
    
    subgraph sender["fa:fa-user Sender"]
        privateKey["fa:fa-lock Private Key"]
    end

    signingProcess["fa:fa-lock Signing Process (Sender's Private Key)"]:::encryptionNode
    signature["fa:fa-file-signature Signature"]:::outputNode

    sender --> signingProcess
    signingProcess --> signature

    subgraph recipients["fa:fa-users Recipients"]
        recipient1["fa:fa-user Recipient 1"]:::outputNode
        recipient2["fa:fa-user Recipient 2"]:::outputNode
        recipient3["fa:fa-user Recipient 3"]:::outputNode
          publicKey2["fa:fa-key Public Key"]
    end
    signature --> recipients

    classDef inputNode fill:#ffcccc,stroke:#333,stroke-width:2px;
    classDef encryptionNode fill:#e6f2ff,stroke:#0066cc,stroke-width:2px;
    classDef outputNode fill:#ccffcc,stroke:#333,stroke-width:2px;
```
This creates a digital signature that anyone can verify using your public key. This proves that the message came from you and hasn't been altered.

- **Cryptocurrency Wallets**:
  When you initiate a transaction, your wallet signs it with your private key. This signature proves you own the funds and authorize the transaction.



## Writing the Encryption Code

To implement asymmetric encryption in Node.js, we need to create functions for encrypting and decrypting data using the RSA algorithm. We will use the `crypto` module, which provides cryptographic functionality.



### Encrypting Data

```javascript
const crypto = require('crypto');

function encryptAsymmetric(publicKey, plaintext) {
  const buffer = Buffer.from(plaintext, 'utf8');
  const encrypted = crypto.publicEncrypt(publicKey, buffer);
  return encrypted.toString('base64');
}
```


```mermaid
graph TD
subgraph input["fa:fa-key Input"]
plaintext["fa:fa-file-alt Plaintext"]:::inputNode
publicKey["fa:fa-key Public Key"]:::inputNode
end

input --> encryptAsymmetric["fa:fa-lock Encryption (RSA)"]:::encryptionNode

subgraph encryptAsymmetric["fa:fa-lock Encryption (RSA)"]
plaintextBuffer["fa:fa-file-alt Plaintext Buffer"]:::processNode --> publicEncrypt["fa:fa-lock Public Encrypt"]:::processNode
end

encryptAsymmetric --> ciphertext["fa:fa-file-code Ciphertext"]:::outputNode

subgraph output["fa:fa-file-export Output"]
ciphertext
end

classDef inputNode fill:#ffcccc,stroke:#333,stroke-width:2px;
classDef encryptionNode fill:#e6f2ff,stroke:#0066cc,stroke-width:2px;
classDef processNode fill:#ccffcc,stroke:#333,stroke-width:2px;
classDef outputNode fill:#ccf,stroke:#333,stroke-width:2px;
```

**Encryption Process: A Simplified Explanation**

1. **Input:**
    - **Plaintext:** This is your original data—the information you want to protect. It could be a text message, a document, or any digital data.
    - **Public Key:** This is the public part of the key pair. It can be shared with anyone who needs to encrypt data for you.


2. **Encryption (RSA):**
    - The encryption algorithm (RSA) takes the plaintext and the public key as input.
    - Inside the encryption "machine," the plaintext is converted to a buffer and then encrypted using the public key.

3. **Output:**
    - **Ciphertext:** The result of encryption is the ciphertext. This is the transformed version of your original data. It is unreadable without the private key.

### Decrypting Data

```javascript
function decryptAsymmetric(privateKey, ciphertext) {
  const buffer = Buffer.from(ciphertext, 'base64');
  const decrypted = crypto.privateDecrypt(privateKey, buffer);
  return decrypted.toString('utf8');
}
```

```mermaid
graph TD
subgraph input["fa:fa-key Input"]
ciphertext["fa:fa-file-code Ciphertext"]:::inputNode
privateKey["fa:fa-lock Private Key"]:::inputNode
end

input --> decryptAsymmetric["fa:fa-unlock Decryption (RSA)"]:::decryptionNode

subgraph decryptAsymmetric["fa:fa-unlock Decryption (RSA)"]
ciphertextBuffer["fa:fa-file-code Ciphertext Buffer"]:::processNode --> privateDecrypt["fa:fa-unlock Private Decrypt"]:::processNode
end

decryptAsymmetric --> plaintext["fa:fa-file-alt Plaintext"]:::outputNode

subgraph output["fa:fa-file-import Output"]
plaintext
end

classDef inputNode fill:#ffcccc,stroke:#333,stroke-width:2px;
classDef decryptionNode fill:#e6f2ff,stroke:#0066cc,stroke-width:2px;
classDef processNode fill:#ccffcc,stroke:#333,stroke-width:2px;
classDef outputNode fill:#ccffcc,stroke:#333,stroke-width:2px;
```

**Decryption Process: A Simplified Explanation**

1. **Input:**
    - **Ciphertext:** The encrypted data that needs to be decrypted.
    - **Private Key:** The private part of the key pair. It should be kept secret and only used by the recipient.

2. **Decryption (RSA):**
    - The decryption algorithm (RSA) takes the ciphertext and the private key as input.
    - Inside the decryption "machine," the ciphertext is converted to a buffer and then decrypted using the private key.

3. **Output:**
    - **Plaintext:** The original data after decryption.



Absolutely! Here's the code for creating a digital signature using RSA in Node.js, along with a diagram and explanation:

### Code

```javascript
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
```

**Output**

```
Ciphertext: GxfqW7TB5I7cZZlWKMnjYbBpXMbjYQidHOFrRsECC2ccdXyfSR9hRn52F8pWYs0cBZIkNqiF7+IJW9Lz3mYIicj625vfERxUTwpUfgqQbp4WJ+0qIJNmjv2CZ7gM/W508XxygIpEe4LxRsF+sVGlUjJBhvJMqopyIfF3mVqyUrqUXiAyBMrcf+TouIqFNc7c6rqMV13wsvLghP8XSrtDM7bVE0Szj14hTWwsDA9yz9N9PsvCM3D58nh8fLKA+8SZV6fgxcUyeH6cVQvBct2moLFIjckOns5TIKpVF90nt5XahXdGQndN88R9DXF/MokWoZQTD6T8t6uMitsuW8yk4Q==
Decrypted Text: This is a secret message.
```

## Writing the Signing Code

Absolutely! Let's break down the digital signature process into two distinct subsections: signing data and verifying the signature.

### Signing Data (Creating the Signature)

```javascript
const crypto = require('crypto');

function signData(privateKey, data) {
  // Create a Sign object using RSA-SHA256
  const sign = crypto.createSign('RSA-SHA256');

  // Update the Sign object with the data to be signed
  sign.update(data);

  // Generate the signature using the private key
  const signature = sign.sign(privateKey, 'base64');

  return signature;
}
```

```mermaid
graph TD
subgraph input["fa:fa-key Input"]
data["fa:fa-file-alt Data"]:::inputNode
privateKey["fa:fa-lock Private Key"]:::inputNode
end

input --> signData["fa:fa-signature Sign (RSA-SHA256)"]:::signNode

subgraph signData["fa:fa-signature Sign (RSA-SHA256)"]
updateData["fa:fa-pencil-alt Update Data"]:::processNode --> sign["fa:fa-signature Sign"]:::processNode
end

signData --> signature["fa:fa-signature Signature"]:::outputNode

classDef inputNode fill:#ffcccc,stroke:#333,stroke-width:2px;
classDef signNode fill:#e6f2ff,stroke:#0066cc,stroke-width:2px;
classDef processNode fill:#ccffcc,stroke:#333,stroke-width:2px;
classDef outputNode fill:#ccf,stroke:#333,stroke-width:2px;
```

**Explanation:**

1. **Input:**
    - **`data`:** The data you want to digitally sign (e.g., a document's contents).
    - **`privateKey`:** Your private RSA key, which is kept secret.

2. **Process (`signData` function):**
    - **Create a Sign Object:** A `Sign` object is created using the `crypto.createSign()` method. The 'RSA-SHA256' algorithm is specified, meaning the signature will be generated using RSA and the SHA-256 hash function for data integrity.
    - **Update with Data:** The `sign.update(data)` method feeds the data you want to sign into the `Sign` object.
    - **Generate Signature:** The `sign.sign(privateKey, 'base64')` method uses your private key to generate the signature.  The signature is returned in base64 encoding for easy transmission and storage.

3. **Output:**
    - **`signature`:** A unique string representing the signed data.

### Verifying the Signature (Authentication)

```javascript
function verifySignature(publicKey, data, signature) {
  // Create a Verify object using RSA-SHA256
  const verify = crypto.createVerify('RSA-SHA256');

  // Update the Verify object with the original data
  verify.update(data);

  // Verify the signature using the public key
  return verify.verify(publicKey, signature, 'base64');
}
```

```mermaid
graph TD
subgraph input["fa:fa-key Input"]
data["fa:fa-file-alt Data"]:::inputNode
publicKey["fa:fa-key Public Key"]:::inputNode
signature["fa:fa-signature Signature"]:::inputNode
end

input --> verifySignature["fa:fa-check Verify (RSA-SHA256)"]:::verifyNode

subgraph verifySignature["fa:fa-check Verify (RSA-SHA256)"]
updateData["fa:fa-pencil-alt Update Data"]:::processNode --> verify["fa:fa-check Verify"]:::processNode
end

verifySignature --> result["fa:fa-check-circle Result"]:::outputNode

classDef inputNode fill:#ffcccc,stroke:#333,stroke-width:2px;
classDef verifyNode fill:#e6f2ff,stroke:#0066cc,stroke-width:2px;
classDef processNode fill:#ccffcc,stroke:#333,stroke-width:2px;
classDef outputNode fill:#ccffcc,stroke:#333,stroke-width:2px;
```

**Explanation:**

1. **Input:**
    - **`publicKey`:** The public RSA key associated with the private key that was used to create the signature.
    - **`data`:** The original data that was signed.
    - **`signature`:** The signature to be verified.

2. **Process (`verifySignature` function):**
    - **Create a Verify Object:** A `Verify` object is created using the `crypto.createVerify()` method. The 'RSA-SHA256' algorithm is again specified.
    - **Update with Data:**  The `verify.update(data)` method feeds the original data into the `Verify` object.
    - **Verify Signature:** The `verify.verify(publicKey, signature, 'base64')` method uses the public key to verify the signature. It checks if the signature matches the data and was indeed created with the corresponding private key.

3. **Output:**
    - **`true` or `false`:**  The function returns `true` if the signature is valid (the data is authentic and unaltered), and `false` if the signature is invalid.


### Code

```javascript
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
```
**Output**

```
Signature: VU1dykMNDmXoiiQr+JAxg0ng2cfUyj77gZuJzUD6uk+2f7T7ll1TqEDufRhP37hLuD01ACdfXOnITCI4dpAAZkjzknPnlFfT436p4uSlTgEPCtu75fynnQl5WQeZQPVih6ffkk1gejzonh8fLsEFBKYH+efjNCsjNGlXZOIlqUC5sigFEzq0YbTiPkc4PNf/KUW5kaKNy682OktBOz9dqTc5zR4MTF6kRvgTQMysY3/N2HaZ9/eWf3YMF6bgltFBclVoMZn0z8MfXhnwp3kMeKhmtb26QvLjxJq7q2+G3YMxGV91jf0yxZl8gTMKIbD0lYrGELa4rCK0OS0JaIzWPA==
Is Signature Valid? true
```

## Security Considerations

### Key Protection
- Keep your private key absolutely confidential. Anyone with access to your private key can decrypt messages intended for you.
- Share your public key freely. It's designed to be public and used for encryption.
- Consider using hardware security modules (HSMs) for secure key storage.

### Key Size
- Use a sufficiently large key size (e.g., 2048 or 4096 bits) to ensure the security of your encrypted data.

### Handling Sensitive Data
Ensure that sensitive data, such as keys and plaintext, are securely handled in your application. Avoid logging sensitive information and use secure memory management practices.

