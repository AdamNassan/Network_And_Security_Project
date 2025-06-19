# Network and Security Lab Project

## Overview
This repository contains the implementation of a secure TCP-based guessing game for the ENCS5121 - Information Security and Computer Network Laboratory (Term 1242) at Circuit University. The project, developed by student ID 1202076, is completed in three phases:
- **Phase 1**: A client-server guessing game using TCP sockets, with a menu-driven interface.
- **Phase 2**: Added AES-256-CBC encryption with a hardcoded 256-bit key and a random 128-bit IV per game round.
- **Phase 3**: Implemented mutual authentication using RSA (620-digit modulus) and Diffie-Hellman (2048-bit MODP group) for session key establishment, ensuring perfect forward secrecy (PFS) and protection against man-in-the-middle (MITM) attacks.

## Project Description
The application is a client-server guessing game where:
- The **server (Bob)** randomly selects a number between 1 and 100.
- The **client (Alice)** guesses the number, receiving encrypted feedback ("Higher," "Lower," or "Correct").
- Communication is secured over TCP for reliability.
- **Phase 2** encrypts guesses and responses using AES-256-CBC.
- **Phase 3** adds RSA-based mutual authentication and Diffie-Hellman key exchange for session key generation.

**Test Environment**:
- **Client (Alice)**: Seed VM, IP: 10.0.2.15
- **Server (Bob)**: Windows, IP: 192.168.56.1
- **Port**: 5566 (TCP)

## Repository Contents
- `client.py`: Client-side code for game logic, AES encryption/decryption, and RSA/DH authentication.
- `server.py`: Server-side code for game logic, AES encryption/decryption, and RSA/DH authentication.
- `utils_crypto.py`: Cryptographic utilities for Diffie-Hellman key exchange, RSA signing/verification, and SHA-256 hashing.
- `generate_primes.py`: Script to generate 310-digit prime numbers for RSA key generation.
- `mod_inverse.py`: Script to compute RSA private keys using the modular inverse algorithm.
- `README.md`: This documentation file.

## Prerequisites
- **Python**: Version 3.8 or higher
- **Required Libraries**:
  ```bash
  pip install cryptography sympy
  ```
  - `cryptography`: For AES-256-CBC encryption/decryption
  - `sympy`: For generating prime numbers
- **Network Configuration**:
  - Client IP: 10.0.2.15 (Seed VM)
  - Server IP: 192.168.56.1 (Windows)
  - Ensure TCP port 5566 is open (adjust firewall settings on both machines).
- **Virtualization**: VirtualBox or VMware for running Seed VM.

## Setup Instructions
1. **Generate RSA Primes**:
   - Run the prime generation script:
     ```bash
     python generate_primes.py
     ```
   - Outputs four unique 310-digit primes for `ALICE_P`, `ALICE_Q`, `BOB_P`, and `BOB_Q`.

2. **Compute RSA Keys**:
   - Update `mod_inverse.py` with the primes from `generate_primes.py`.
   - Run:
     ```bash
     python mod_inverse.py
     ```
   - Copy the generated values (`ALICE_N`, `ALICE_E`, `ALICE_D`, `BOB_N`, `BOB_E`, `BOB_D`) to `client.py` and `server.py`.

3. **Configure IP Addresses**:
   - In `client.py` and `server.py`, verify:
     ```python
     ALICE_ID = "10.0.2.15"  # Client IP
     BOB_ID = "192.168.56.1"  # Server IP
     ```

## Running the Application
1. **Start the Server** (on Windows):
   - Navigate to the project directory and run:
     ```bash
     python server.py
     ```
   - The server listens on port 5566 and waits for client connections.

2. **Start the Client** (on Seed VM):
   - Navigate to the project directory and run:
     ```bash
     python3 client.py
     ```
   - Enter the server IP (`192.168.56.1`) when prompted.

3. **Gameplay**:
   - Select option `1` to start a new game round or `2` to exit.
   - Enter a guess (1-100), which is encrypted using AES-256-CBC.
   - Receive encrypted feedback ("Higher," "Lower," or "Correct").
   - When "Correct" is received, the game round ends, and the menu reappears.
   - Select `2` to close the TCP connection and exit.

## Cryptographic Implementation
- **RSA Authentication (Phase 3)**:
  - **Primes**: Four 310-digit primes generated using `sympy.nextprime()` (as no 310-digit primes were available on https://primes.utm.edu/curios/).
  - **Modulus**: ~620 digits (`ALICE_N = p_A * q_A`, `BOB_N = p_B * q_B`).
  - **Public Exponent**: `e = 65537` (coprime with `(p-1)(q-1)`).
  - **Private Key**: `d` computed via modular inverse (see `mod_inverse.py`).
  - **Signature**: Uses repeated squaring for efficiency (implemented in `utils_crypto.py`).

- **Diffie-Hellman Key Exchange (Phase 3)**:
  - **Parameters**: RFC3526 2048-bit MODP group (`g = 2`, `m = prime`).
  - **Exponents**: `a` (client), `b` (server), 2048-bit, generated using `secrets` module.
  - **Session Key**: `K = SHA256(g^ab mod m)`, used for AES-256-CBC encryption.
  - **PFS**: Exponents `a`, `b`, and key `K` are destroyed after each game round.

- **AES-256-CBC Encryption (Phase 2)**:
  - **Key**: In Phase 2, hardcoded SHA-256 hash of student ID; in Phase 3, derived from Diffie-Hellman.
  - **IV**: 128-bit, randomly generated per message using `secrets.token_bytes(16)`.
  - **Padding**: PKCS7 padding to align with 128-bit block size.

## Test Cases (Phase 3)
To verify mutual authentication and key exchange, three test cases are implemented:
1. **Test Case 1: Normal Operation**
   - Execute two game rounds.
   - **Outputs** (printed by client and server):
     - Exponents: `a` (client), `b` (server)
     - Nonces: `R_A` (client), `R_B` (server)
     - Session key: `K`
     - IVs for each encrypted message
     - Confirmation of mutual authentication ("Bob authenticated successfully," "Alice authenticated successfully")
   - **Verification**: Both sides share the same `K`, and game rounds complete successfully.

2. **Test Case 2: Trudy Posing as Bob**
   - Modify `BOB_D` in `server.py` (e.g., append `1` to the value).
   - Run `client.py` and `server.py`.
   - **Expected Output**: Client prints:
     ```
     Bob authentication failed. Terminating game round.
     ```
   - **Revert**: Restore original `BOB_D` after testing.

3. **Test Case 3: Trudy Posing as Alice**
   - Modify `ALICE_D` in `client.py` (e.g., append `1` to the value).
   - Run `client.py` and `server.py`.
   - **Expected Output**: Server prints:
     ```
     Authentication failed for Alice.
     ```
   - **Revert**: Restore original `ALICE_D` after testing.

## Performance Notes
- **RSA Handshake**: The 620-digit modulus results in a handshake time of ~3-5 seconds (Seed VM: 4GB RAM, Windows: 16GB RAM).
- **AES Encryption**: Minimal overhead due to efficient `cryptography` library implementation.
- **Network**: Tested between Seed VM and Windows using VirtualBox, with stable TCP communication on port 5566.

## Known Considerations
- **Prime Selection**: Used `sympy.nextprime()` due to the unavailability of 310-digit primes on the specified website (pending instructor approval).
- **Hardcoded Keys**: Private keys (`ALICE_D`, `BOB_D`) are hardcoded for simplicity, as permitted, but this is insecure in real-world applications.
- **Online Verification**: Ciphertext may differ in the last block if padding differs from the online tool (e.g., https://cryptii.com/pipes/aes-encryption).

## Acknowledgments
- **ENCS3320 Resources**: Provided initial socket programming code (Google Drive link).
- **References**:
  - RFC3526 for Diffie-Hellman parameters
  - RosettaCode for modular exponentiation
  - StackOverflow for modular inverse algorithm
