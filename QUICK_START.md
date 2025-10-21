# CipherGenius v1.1.0 - Quick Start Guide

## 🚀 Quick Start (3 Steps)

### Step 1: Install Python (One-time)
- Download Python 3.8+ from https://www.python.org/downloads/
- **Important**: Check "Add Python to PATH" during installation

### Step 2: Launch Application
- Double-click `start.bat`
- First run will auto-install dependencies (takes a few minutes)

### Step 3: Configure API Key (Optional)
- Copy `.env.example` to `.env`
- Edit `.env` and add your API key:
  ```
  ZHIPUAI_API_KEY=your_key_here
  ```

## ✨ Features

### 📊 Dashboard
- **152** cryptographic components
- **20+** post-quantum algorithms (Kyber, Dilithium, SPHINCS+, FALCON, etc.)
- Real-time statistics
- **3** main categories: Primitives (122), Modes (16), Protocols (14)

### 🔮 Component Library (152 Total)

**Block Ciphers (15)**: AES, DES, 3DES, Camellia, ARIA, Twofish, Serpent, Blowfish, CAST5, IDEA, RC6, MARS, SM4

**Stream Ciphers (4)**: ChaCha20, XChaCha20, Salsa20, RC4

**Hash Functions (22)**: SHA-2 family, SHA-3 family, BLAKE2, BLAKE3, Keccak, Whirlpool, SM3, Streebog, Tiger, MD5, RIPEMD-160

**MACs (11)**: HMAC, CMAC, GMAC, Poly1305, KMAC, VMAC, UMAC, BLAKE2-MAC, BLAKE3-MAC, SipHash

**Signatures (23)**: RSA, ECDSA, EdDSA, Schnorr, BLS, DSA, ElGamal, SM2, Dilithium (all levels), FALCON, SPHINCS+, SLH-DSA, ML-DSA, Picnic

**Key Exchange (14)**: ECDH, DH, X25519, X448, Kyber (all levels), NTRU, Classic McEliece, FrodoKEM, BIKE, HQC

**KDF (11)**: HKDF, PBKDF2, Scrypt, Argon2, Bcrypt, Balloon, TLS 1.2/1.3 KDF, KBKDF, X9.63 KDF

**AEAD Modes (10)**: GCM, CCM, ChaCha20-Poly1305, EAX, OCB, GCM-SIV, Ascon, Deoxys-II, AEGIS-128/256

**Traditional Modes (6)**: CTR, CBC, CFB, OFB, XTS, ECB

**Protocols (14)**: zkSNARK, zkSTARK, PLONK, Groth16, Bulletproofs, OPAQUE, SRP, SPAKE2+, CPace, MPC protocols, PSI

**Other (22)**: VRF, IBE, ABE, FHE, Commitment schemes, DRBG variants, Searchable encryption

### 🎨 UI Features
- Purple gradient theme
- 3D hover animations
- Real-time progress tracking
- Color-coded status messages

### 🤖 AI-Powered
- Natural language requirement parsing
- Automatic scheme generation
- Security validation
- Multi-language code output (Python/C/Pseudocode)

## 📝 Usage

### Basic Flow
1. Enter your requirements in natural language
2. Click "Generate Scheme" button
3. Review the generated cryptographic scheme
4. Download implementation code

### Quick Examples
Use the sidebar quick example buttons:
- 🌐 IoT Encryption
- 🔮 Post-Quantum Crypto
- 🔐 Digital Signatures
- 🔑 Key Exchange

## ❓ Common Issues

### Q: Browser doesn't open automatically?
**A**: Manually open http://localhost:8502

### Q: Port 8502 already in use?
**A**: Close the program using that port, or change the port in start.bat

### Q: Missing module errors?
**A**: Run `pip install streamlit zhipuai`

### Q: API call fails?
**A**: Check:
- `.env` file exists and is configured correctly
- API key is valid
- Network connection is working
- API quota is available

## 🛑 Stopping the Application

- Press `Ctrl+C` in the command window
- Or close the command window directly

## 📚 Documentation

- `使用说明.txt` - Detailed guide (Chinese)
- `APP_DEMO_SCRIPT.txt` - Demo script
- `APP_PACKAGING_GUIDE.md` - Packaging guide
- `PACKAGING_QUICK_START.md` - Quick packaging tutorial

## 💡 Tips

1. Use quick example buttons for instant testing
2. Specify security levels clearly (e.g., "128-bit", "256-bit")
3. Check component details to understand algorithm characteristics
4. Download generated code for direct use in your projects
5. Review history to revisit previous schemes

## 🔑 Supported AI Providers

- **ZhipuAI** (Recommended for China): https://open.bigmodel.cn/
- **OpenAI**: https://platform.openai.com/
- **Anthropic**: https://console.anthropic.com/

## 🎉 Enjoy CipherGenius!

For more information, check the detailed documentation files.
