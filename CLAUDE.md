# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project Overview

This is a Python decryption tool that extracts and decrypts data from video files. The project uses hybrid RSA+AES encryption where an AES key is encrypted with RSA, and the actual data is encrypted with AES-CBC.

## Commands

```bash
# Install dependencies
cd decryption && pip install -r requirements.txt

# Run the decryption script
cd decryption && python decrypt.py
```

## Architecture

- `decryption/decrypt.py` - Main decryption script
- `decryption/private_key.pem` - RSA private key (2048-bit) for decrypting the AES key
- `decryption/requirements.txt` - Dependencies: cryptography, opencv-python, numpy

### Data Format

The encrypted data is embedded in video frames (1920x1080 grayscale). The structure is:
1. 4 bytes: data length (big-endian uint32)
2. 16 bytes: AES IV
3. 256 bytes: RSA-encrypted AES key
4. Remaining: AES-CBC encrypted file data with PKCS7 padding

### Encryption Details

- RSA-2048 with OAEP padding (SHA-256) for AES key encryption
- AES-256-CBC for data encryption
- Video frames are converted to grayscale and read as raw bytes
