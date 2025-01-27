# RSA Signature Project

Implementation of RSA signature generation and verification system with OAEP padding.

## Features (Part I)
- RSA key generation with 1024-bit primes
- Miller-Rabin primality testing
- OAEP (Optimal Asymmetric Encryption Padding)
- Modular arithmetic operations

## Requirements
- Python 3.8+

## Usage
```python
from src.rsa_core import RSACore, OAEP

# Generate RSA keys
rsa = RSACore()
pub_key, priv_key = rsa.generate_keypair()

# Use OAEP padding
oaep = OAEP(1024)
message = b"Your message here"
padded = oaep.pad(message)
```
Project Structure
```
rsa_signature_project/
├── src/
│   └── rsa_core.py
├── tests/
├── docs/
├── README.md
└── .gitignore
```
Esta implementação inclui:
1. Geração de chaves RSA com primos de 1024 bits
2. Teste de primalidade Miller-Rabin
3. Implementação de OAEP
4. Funções auxiliares para operações modulares
