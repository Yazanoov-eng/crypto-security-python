Crypto Security Mechanisms (Python)
==================================

Python implementation of RC4, Message Authentication (RSA + Hash), and Digital Envelope (DES-CTR + RSA).

This project demonstrates three fundamental information security mechanisms using Python:

1) Data confidentiality using symmetric encryption (RC4)
2) Message authentication assurance using hashing and RSA encryption (MAC)
3) Hybrid encryption (Digital Envelope) using DES-CTR with RSA key encryption

Project Structure
-----------------

crypto-security-python/
  src/
    security.py
  docs/
    SECURITY-REPORT.pdf
  README.md
  LICENSE

How It Works
------------

A) RC4 Symmetric Encryption
- Implements RC4 stream cipher for encryption/decryption.
- Generates a keystream and XORs it with plaintext/ciphertext.

B) Message Authentication Assurance
- Hashes the message to generate a digest.
- Encrypts the digest using RSA-1024 to produce a MAC.
- Supports verification by decrypting the MAC and comparing with a fresh hash.
- Includes replay attack mitigation using a unique parameter (nonce/timestamp).

C) Digital Envelope (Hybrid Encryption)
- Encrypts plaintext using DES in CTR mode with a random symmetric key.
- Encrypts the symmetric key using RSA-1024 public key.
- Decrypts by recovering the symmetric key using RSA private key, then decrypting the message.

Running the Project
-------------------

Run the main script:

python src/security.py

Follow the menu options to test:
- RC4 encryption/decryption
- MAC generation/verification
- Digital envelope encryption/decryption

Author
------

Yazan Aqtash
GitHub: https://github.com/Yazanoov-eng

License
-------

MIT License


