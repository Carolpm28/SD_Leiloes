# Secure and Private P2P Auction System

A distributed Peer-to-Peer auction system designed with a strong focus on privacy, anonymity, and cryptographic security. This project implements a hybrid architecture where a Trusted Central Server (TTP) supports a P2P network to ensure advanced security properties such as Blind Signatures, Trusted Timestamping, and Selective Identity Disclosure.

## Security Features

The system is engineered to strictly fulfill six security requirements through robust cryptographic mechanisms:

| Requirement | Implemented Mechanism | Description |
| :--- | :--- | :--- |
| **1. Anonymity** | **RSA Blind Signatures** | The server signs authorization tokens without knowing their content or the identity of the requester, ensuring bids cannot be traced back to the user's identity. |
| **2. Authenticity** | **X.509 & Challenge-Response** | Only users authenticated via Challenge-Response and possessing valid certificates issued by the CA can obtain tokens and participate in the network. |
| **3. Integrity** | **Digital Signatures (RSA-PSS)** | Critical bid content (value, ID) is signed by the Bidder using their private key and timestamped by the Server, making modification within the P2P network impossible. |
| **4. Non-Repudiation** | **RSA-OAEP Encryption (Notary)** | The bidder's real identity is encrypted with the Notary's public key and cryptographically bound to the anonymous Bid ("Identity Blob"), preventing the winner from denying authorship. |
| **5. Timestamping** | **Trusted Timestamp Authority** | The server digitally signs the date and time of every bid, ensuring a fair and immutable ordering for tie-breaking. |
| **6. Selective Disclosure** | **One-Shot Rule + P2P** | Identities are revealed strictly between the Seller and the Winner at the end of the auction, preserving the anonymity of all losing bidders. |

## Architecture

The system utilizes a hybrid architecture to balance security and decentralization:

### Central Server (Trusted Third Party)
* **CA (Certificate Authority):** Handles user registration and certificate issuance.
* **Notary:** Provides custody of encrypted identity envelopes.
* **Timestamping Service:** Issues signed timestamps for bids.
* **Blind Signature Issuer:** Issues blind tokens for anonymity.

### Clients (Peers)
* **Direct P2P Communication:** Used for auction announcements and bid distribution via sockets.
* **Local Database (SQLite):** Manages local auction state and bid history.
* **Web Interface (Flask):** Provides the user interface for interaction.

## How to Run

### Prerequisites
* Python 3.9+
* Required libraries: `flask`, `flask-cors`, `cryptography`, `requests`

```bash
pip install flask flask-cors cryptography requests
```

### Start the Central Server

```bash
python -m crypto.server
```

### Start Clients (Peers)

```bash
cd client
python main.py
```
