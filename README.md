# Secure Secrets Vault

An educational Python project exploring the core cryptographic concepts behind a secure secrets vault.

The current implementation focuses on experimenting with **Argon2-based key derivation** and **AES-GCM authenticated encryption** rather than providing a complete production password manager.

> **Security Notice:** This project is strictly for educational purposes. Do not use it to store real or sensitive passwords.

## What This Project Demonstrates

* Deriving cryptographic key material from a password using **Argon2**
* Encrypting data using **AES-GCM**
* Understanding authenticated encryption and data integrity
* Exploring the basic building blocks of secure local secret storage
* Structuring a small security-focused Python project

## Cryptographic Flow

```text id="1a5r8z"
Password
   │
   ▼
Argon2 Key Derivation
   │
   ▼
Derived Key
   │
   ▼
AES-GCM Encryption
   │
   ▼
Encrypted Data
```

## Current Implementation

The repository currently contains a small Python-based cryptography implementation used to experiment with the concepts above.

```text id="2x8f0s"
secret-vault/
├── crypto/
│   └── zero_knowledge_test.py
├── .gitignore
├── requirements.txt
├── README.md
└── LICENSE
```

## Running Locally

### Prerequisites

* Python 3.x
* Git

### Clone the repository

```bash id="s5pm36"
git clone https://github.com/Jyoti678/secret-vault.git
cd secret-vault
```

### Create a virtual environment

**Windows:**

```bash id="y7efxq"
python -m venv venv
venv\Scripts\activate
```

**macOS/Linux:**

```bash id="p8wq7n"
python3 -m venv venv
source venv/bin/activate
```

### Install dependencies

```bash id="q3b8ko"
pip install -r requirements.txt
```

### Run the implementation

```bash id="2i5j4r"
python crypto/zero_knowledge_test.py
```

## Why I Built This

This project was created to strengthen my understanding of practical cryptography and secure application design, particularly:

* Password-based key derivation
* Authenticated encryption
* AES-GCM
* Argon2
* Secure handling of locally processed data

## Limitations

This repository is **not a complete password manager** and has not undergone independent security auditing.

It currently does not implement the complete functionality expected from a production password-management system, such as a persistent encrypted vault, account recovery, comprehensive key lifecycle management, extensive security testing, or production-grade threat modeling.

## Future Improvements

Planned areas for experimentation include:

* Persistent encrypted vault storage
* Secure vault file format
* Password-strength analysis
* Automated cryptographic tests
* More comprehensive threat modeling
* Command-line or web interface
* Additional encryption and key-management experiments

## License

This project is licensed under the MIT License. See the `LICENSE` file for details.
