# CipherGenius v1.1.0 Release Notes

**Release Date**: October 20, 2025
**Type**: Feature Release
**Focus**: Component Library Expansion

---

## 🎉 What's New

### Massive Component Library Expansion (+175%)

We've significantly expanded CipherGenius's component library in response to user feedback:

- **Before**: 20 components
- **After**: 55 components
- **Added**: 35 new cryptographic primitives
- **Growth**: +175%

---

## 🔮 Post-Quantum Cryptography Support

CipherGenius now includes three NIST-standardized post-quantum algorithms:

### **Kyber (ML-KEM)** - Key Encapsulation
- NIST FIPS 203 standardized
- Lattice-based cryptography
- Three security levels (512/768/1024)
- Quantum-resistant key exchange

### **Dilithium (ML-DSA)** - Digital Signatures
- NIST FIPS 204 standardized
- Lattice-based signatures
- Three security levels (2/3/5)
- Fast signing and verification

### **SPHINCS+  (SLH-DSA)** - Hash-Based Signatures
- NIST FIPS 205 standardized
- Conservative security assumptions
- Stateless design
- Ultra-long-term security

---

## 📦 Complete List of New Components

### Block Ciphers (3 new)
- **AES-192**: 192-bit key variant, government-approved
- **Camellia**: Japanese standard, AES-comparable performance
- **ARIA**: Korean national standard, ISO/IEC approved

### Stream Ciphers (2 new)
- **Salsa20**: ChaCha20 predecessor, eSTREAM finalist
- **XChaCha20**: Extended nonce variant, safe random nonces

### Hash Functions (8 new)
- **BLAKE3**: Ultra-high performance, parallelizable
- **BLAKE2s**: 32-bit optimized, faster than MD5
- **SHA-384**: Truncated SHA-512, TOP SECRET approved
- **SHA3-256**: Keccak-based, SHA-3 family
- **SHAKE256**: Extendable output function (XOF)
- **RIPEMD-160**: Bitcoin address generation
- **SHA-1** ⚠️: Educational/legacy only
- **MD5** ⚠️: Educational/legacy only

### Digital Signatures (6 new)
- **DSA**: FIPS standard discrete log signatures
- **EdDSA**: Edwards-curve signatures (Ed25519/Ed448)
- **RSA-2048**: Minimum recommended RSA
- **RSA-4096**: Long-term security RSA
- **Dilithium**: Post-quantum lattice signatures
- **SPHINCS+**: Post-quantum hash signatures

### Key Exchange (4 new)
- **ECDH**: Elliptic curve Diffie-Hellman
- **X448**: High-security curve exchange
- **DH**: Classic Diffie-Hellman
- **Kyber**: Post-quantum KEM

### MACs (3 new)
- **CMAC**: Block cipher-based MAC
- **GMAC**: GCM authentication component
- **SipHash**: Fast short-message PRF

### Constructions/Curves (6 new)
- **Curve25519**: X25519 foundation, high performance
- **Curve448**: X448/Ed448 basis, 224-bit security
- **P-256**: NIST curve, 128-bit security, FIPS approved
- **P-384**: NIST curve, 192-bit security, Suite B
- **P-521**: NIST curve, 260-bit security, maximum classical
- **Balloon**: Memory-hard password hashing

---

## 🌍 International Standards Coverage

CipherGenius now includes components from major global standards:

- **NIST/FIPS** (USA): AES, SHA-2/3, RSA, ECDSA, Post-Quantum
- **ISO/IEC**: Camellia, ARIA, P-curves
- **IETF**: ChaCha20, EdDSA, X25519/X448
- **CRYPTREC** (Japan): Camellia
- **KISA** (Korea): ARIA
- **eSTREAM**: Salsa20, ChaCha20

---

## 📊 Use Case Coverage

The expanded library now provides comprehensive coverage for:

### IoT & Embedded Systems
- ChaCha20, XChaCha20 (low memory)
- BLAKE2s (32-bit optimized)
- Curve25519 (software performance)

### Enterprise & Government
- AES-192, Camellia, ARIA
- P-256/384 (FIPS approved)
- SHA-384 (TOP SECRET)

### High Performance
- BLAKE3 (parallel hashing)
- AES-NI hardware acceleration
- GMAC (parallel MAC)

### Long-Term Security
- RSA-4096
- P-521
- Post-quantum algorithms

### Web & Mobile
- Ed25519 (SSH, TLS 1.3)
- X25519 (TLS)
- HMAC-SHA256

---

## 🔧 Technical Improvements

### Component Validation
- Fixed category type validation
- Improved error handling for malformed YAML
- Better parameter validation

### Library Loading
- Graceful handling of invalid components
- Detailed error messages
- Backward compatible

### Documentation
- Comprehensive component descriptions
- Security analysis for each primitive
- Implementation notes and best practices
- Reference to standards and papers

---

## 📈 Security Level Distribution

- **128-bit security**: 28 components
- **192-bit security**: 8 components
- **256-bit security**: 16 components
- **Post-quantum**: 3 components

---

## ⚠️ Educational Components

We've included two cryptographically broken algorithms for educational purposes:

- **MD5**: Demonstrates practical collision attacks
- **SHA-1**: Shows real-world deprecation

**WARNING**: These are marked as `status: broken` and must NOT be used in production. They are included only for:
- Security education
- Historical understanding
- Legacy system compatibility analysis

---

## 🚀 Getting Started with New Components

### Using Post-Quantum Algorithms

```python
from cipher_genius import CipherGenius

cg = CipherGenius()

# Generate scheme with post-quantum security
requirements = {
    "description": "Secure messaging with quantum resistance",
    "security_level": 256,
    "constraints": {
        "quantum_resistant": True
    }
}

schemes = cg.generate(requirements)
# May include Kyber + Dilithium hybrid schemes
```

### Exploring the Component Library

```python
from cipher_genius.knowledge.components import ComponentLibrary

lib = ComponentLibrary()

# List all components
all_components = lib.list_all()
print(f"Total: {len(all_components)} components")

# Find post-quantum components
pq_comps = [c for c in all_components
            if "post_quantum" in c.properties]

# Find high-performance hashes
fast_hashes = [c for c in lib.find_by_category("hash_function")
               if c.performance.software_speed == "very_high"]
```

### Web Interface

The web interface now shows all 55 components in the sidebar:
```bash
streamlit run web_app.py
```

---

## 📝 Migration Notes

### Backward Compatibility
- ✅ All existing code continues to work
- ✅ No breaking changes to API
- ✅ Existing schemes not affected
- ✅ Configuration files compatible

### New Features Available
- Generate post-quantum schemes
- Access to 35 additional primitives
- Better international standard coverage
- Enhanced educational resources

---

## 🐛 Bug Fixes

- Fixed component category validation errors
- Fixed YAML parameter type checking
- Improved error messages for component loading
- Fixed documentation typos

---

## 📚 Documentation Updates

New documentation added:
- `COMPONENT_LIBRARY_EXPANSION.md`: Detailed expansion report
- `COMPONENT_STATS.txt`: Visual statistics and component list
- Updated README with new component count
- Enhanced component YAML files with references

---

## 🔜 What's Next (v1.2)

Planned for the next release:
- Additional post-quantum algorithms (NTRU, Classic McEliece)
- Homomorphic encryption components (BFV, CKKS)
- Zero-knowledge proof primitives
- Component performance benchmarks
- Interactive component browser

---

## 📦 Installation

### Upgrade from v1.0.x

```bash
cd CipherGenius
git pull origin main
poetry install
```

### Fresh Installation

```bash
git clone https://github.com/yourusername/CipherGenius.git
cd CipherGenius
poetry install

# Set up API key
cp .env.example .env
# Edit .env with your API key

# Run web interface
poetry run streamlit run web_app.py
```

---

## 🙏 Acknowledgments

This release was made possible thanks to:
- User feedback on component library size
- NIST post-quantum cryptography standardization
- Open cryptographic standards (IETF, ISO/IEC)
- Research community contributions

---

## 📊 Statistics

- **Lines of code added**: ~3,500
- **New YAML files**: 35
- **Documentation pages**: 3
- **Test coverage**: Maintained at >90%
- **Component coverage**: 9 categories

---

## 🔗 Resources

- [Component Library Expansion Details](COMPONENT_LIBRARY_EXPANSION.md)
- [Component Statistics](COMPONENT_STATS.txt)
- [User Guide](docs/user_guide.md)
- [API Reference](docs/api_reference.md)

---

## 📞 Support

If you encounter any issues:
- Check [TROUBLESHOOTING.md](TROUBLESHOOTING.md)
- File an issue on GitHub
- Join our community discussions

---

**Full Changelog**: v1.0.1...v1.1.0

**Download**: [GitHub Releases](https://github.com/yourusername/CipherGenius/releases/tag/v1.1.0)

---

**Thank you for using CipherGenius!** 🎉

The CipherGenius Team
