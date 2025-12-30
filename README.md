\# Secure Secrets Vault



Secure Secrets Vault is an educational zero-knowledge password manager designed to demonstrate modern cryptographic practices such as strong key derivation and authenticated encryption.



This project focuses on security concepts, clean architecture, and professional Git workflows rather than production deployment.



\## Security Notice



This project is strictly for educational and learning purposes.  

Do not use this application to store real or sensitive passwords.



\## Features



\- Zero-knowledge architecture (no plaintext data storage)

\- Argon2 for secure master password key derivation

\- AES-GCM for authenticated encryption

\- Isolated Python virtual environment

\- Clean and modular project structure

\- Version-controlled using Git



\## Cryptographic Design Overview



\- \*\*Key Derivation:\*\*  

&nbsp; Argon2 is used to derive a strong encryption key from the master password.



\- \*\*Encryption:\*\*  

&nbsp; AES-GCM ensures both confidentiality and integrity of stored secrets.



\- \*\*Zero-Knowledge Principle:\*\*  

&nbsp; All encryption and decryption operations occur locally.  

&nbsp; No plaintext passwords are ever stored or transmitted.



\## Project Structure



secret-vault/

├── crypto/ # Cryptographic modules

│ └── zero\_knowledge\_test.py

├── .gitignore # Git ignored files (venv, secrets, etc.)

├── requirements.txt # Python dependencies

├── README.md # Project documentation

└── LICENSE # MIT License





\## Setup and Execution



Clone the repository and set up the virtual environment:



```bash

git clone https://github.com/Jyoti678/secret-vault.git

cd secret-vault

python -m venv venv

venv\\Scripts\\activate

pip install -r requirements.txt

python crypto/zero\_knowledge\_test.py

Learning Objectives

Understanding zero-knowledge system design



Applying password-based key derivation securely



Implementing authenticated encryption



Structuring security-focused Python projects



Maintaining professional Git repositories



License

This project is licensed under the MIT License. See the LICENSE file for details.

