# Digital Signature Verifier

A C++ implementation that ensures document authenticity using cryptographic hashes and RSA digital signatures via OpenSSL.

## Features
- Generates RSA key pairs (public & private keys)
- Signs documents using SHA-256 and RSA
- Verifies signatures to ensure document authenticity

## Requirements
- g++ compiler
- OpenSSL library

## Installation & Usage

### 1. Compile the Program
```sh
g++ digital_signature_verifier.cpp -o verifier -lssl -lcrypto
```

### 2. Generate Key Pair
```sh
./verifier
```
Select option `1` to generate a key pair (`private.pem` and `public.pem`).

### 3. Sign a Document
```sh
./verifier
```
Select option `2` and enter the filename to sign. This generates `signature.sig`.

### 4. Verify a Document
```sh
./verifier
```
Select option `3` and enter the filename to verify. If the signature is valid, authentication succeeds.
