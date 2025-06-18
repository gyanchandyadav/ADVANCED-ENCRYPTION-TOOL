# ADVANCED-ENCRYPTION-TOOL

*COMPANY*: CODTECH IT SOLUTIONS

*NAME*: GYANCHAND YADAV

*INTERN ID*: CT12DA331

*DOMAIN*:  CYBER SECURITY & ETHICAL HACKING

*DURATION*: 12 WEEKS

*MENTOR*: NEELA SANTOSH

##
The AES-256 File Encryptor is a user-friendly desktop application built using Python and the tkinter library for GUI, designed to securely encrypt and decrypt files using the AES-256-GCM encryption standard. This tool allows users to protect sensitive files through strong cryptographic practices, ensuring data confidentiality and integrity with a password-based encryption mechanism. By using AES-GCM (Galois/Counter Mode), the application not only encrypts data but also authenticates it, making it resistant to tampering and unauthorized modifications.

In today's digital landscape, protecting private and sensitive information is more crucial than ever. Whether you're dealing with financial documents, personal notes, or business-related files, encrypting this data provides an essential layer of security against data breaches, theft, or unauthorized access. The AES-256 File Encryptor gives users the power to manage this security directly from a graphical interface without needing in-depth knowledge of cryptographic principles.

Functionality
This application provides two core functionalities:

1. File Encryption
Users can select any file on their system via a file browser.

After selecting the file, they input a password of their choice.

Upon clicking the "Encrypt" button, the application:

Derives a cryptographic key from the password using PBKDF2HMAC with SHA-256 hashing, a random 16-byte salt, and 390,000 iterations for security against brute-force attacks.

Uses AES-256-GCM for authenticated encryption.

Generates a 12-byte unique nonce to ensure that encrypting the same file twice will yield different ciphertexts.

Produces a final encrypted output that concatenates the salt, nonce, and ciphertext.

Saves the encrypted file with a .enc extension in the same directory as the original file.

2. File Decryption
Users can select an encrypted file (with .enc extension).

They input the password used during encryption.

Upon clicking the "Decrypt" button, the application:

Extracts the salt and nonce from the encrypted file.

Reconstructs the key using the original password and extracted salt.

Attempts decryption using AES-GCM.

If the password is incorrect or the file is corrupted, the process fails gracefully and notifies the user.

On successful decryption, the plaintext is saved with a .dec extension.

##
OUTPUT

