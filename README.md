# CipherGenius

**An LLM-Driven Framework for Automated Cryptographic Scheme Generation**

密码天才：基于大型语言模型的自动密码方案生成框架

[![Version](https://img.shields.io/badge/version-3.0.0-blue.svg)](https://github.com/yourusername/CipherGenius/releases/tag/v3.0.0)
[![License](https://img.shields.io/badge/license-MIT-green.svg)](LICENSE)
[![Python](https://img.shields.io/badge/python-3.11+-blue.svg)](https://www.python.org)
[![Docker](https://img.shields.io/badge/docker-ready-brightgreen.svg)](Dockerfile)
[![Components](https://img.shields.io/badge/components-152-brightgreen.svg)](RELEASE_v1.1.0.md)

🎉 **v3.0.0 Released!** - Enterprise-Grade Platform (152 components, 19 features, Security Suite) - [See Details](FINAL_SYSTEM_SUMMARY.md)

## Overview

CipherGenius is an innovative platform that automates the design and generation of cryptographic schemes using Large Language Models (LLM). It transforms natural language security requirements into complete cryptographic solutions, including specifications, pseudocode, and multi-language implementations.

## Features

- **Natural Language Input**: Describe your security requirements in plain language
- **Intelligent Scheme Generation**: Automatically design cryptographic schemes based on first principles
- **Multi-Language Code Generation**: Output Python, C, and Rust implementations
- **Extensive Component Library**: 152 cryptographic components including:
  - 122 Primitives (ciphers, hashes, signatures, post-quantum algorithms)
  - 16 Cipher Modes (AEAD, traditional modes)
  - 14 Advanced Protocols (zero-knowledge proofs, secure computation, PAKE)
- **Security Verification**: Built-in validation and testing mechanisms
- **Multiple Variants**: Generate diverse scheme alternatives for comparison

## Quick Start

### Prerequisites

- Python 3.11+
- Poetry (Python package manager)
- One of the following API keys:
  - OpenAI API key
  - Anthropic API key
  - ZhipuAI (GLM) API key (**推荐国内用户使用**)

### Installation

```bash
# Clone the repository
git clone https://github.com/yourusername/CipherGenius.git
cd CipherGenius

# Install dependencies with Poetry
poetry install

# Copy environment template
cp .env.example .env

# Edit .env and configure your preferred LLM provider
# For OpenAI:
# DEFAULT_LLM_PROVIDER=openai
# OPENAI_API_KEY=your_openai_key_here

# For Anthropic:
# DEFAULT_LLM_PROVIDER=anthropic
# ANTHROPIC_API_KEY=your_anthropic_key_here

# For ZhipuAI GLM (智谱AI - 推荐国内用户):
# DEFAULT_LLM_PROVIDER=zhipuai
# ZHIPUAI_API_KEY=your_zhipuai_key_here
# ZHIPUAI_MODEL=glm-4  # or glm-4-plus, glm-3-turbo
```

### Usage

#### Web Interface (Recommended) 🌐

The easiest way to use CipherGenius is through the web interface:

```bash
# Install Streamlit
poetry add streamlit

# Launch web interface
streamlit run web_app.py
```

Then open your browser to `http://localhost:8501`

**Features:**
- 🎨 Intuitive visual interface
- 📊 Real-time scheme generation
- 💻 Code generation and download
- 🔍 Automatic validation
- 📱 Mobile-friendly design

See [WEB_INTERFACE_GUIDE.md](WEB_INTERFACE_GUIDE.md) for detailed usage.

#### CLI Tool

```bash
# Generate a scheme from natural language
poetry run cipher-genius generate "Lightweight encryption for IoT devices with 128-bit security"

# Interactive mode
poetry run cipher-genius interactive

# Batch processing
poetry run cipher-genius batch --input requirements.yaml --output schemes/
```

#### Python API

```python
from cipher_genius import CipherGenius

# Initialize
cg = CipherGenius()

# Generate scheme
requirements = {
    "description": "Authenticated encryption for cloud storage",
    "security_level": 256,
    "constraints": {
        "performance": "high throughput"
    }
}

schemes = cg.generate(requirements, num_variants=3)

# Access results
for scheme in schemes:
    print(f"Scheme: {scheme.name}")
    print(f"Components: {scheme.components}")
    print(f"Python Code:\n{scheme.implementation.python}")
```

## Project Structure

```
CipherGenius/
├── src/cipher_genius/      # Main source code
│   ├── models/              # Data models
│   ├── core/                # Core engine (parser, generator, etc.)
│   ├── rag/                 # RAG system
│   ├── knowledge/           # Knowledge base
│   ├── codegen/             # Code generation
│   └── cli/                 # CLI tool
├── data/                    # Knowledge base data
│   ├── components/          # Cryptographic components
│   └── papers/              # Research papers
├── tests/                   # Test suite
├── docs/                    # Documentation
└── examples/                # Usage examples
```

## Example

**Input:**
```
"Design an authenticated encryption scheme for resource-constrained IoT devices.
Requirements: 128-bit security, memory < 2KB, latency < 10ms"
```

**Output:**
```
Scheme: ChaCha20-Poly1305 AEAD for IoT
Security Level: 128-bit
Components:
  - Stream Cipher: ChaCha20 (20 rounds)
  - MAC: Poly1305
  - Construction: Encrypt-then-MAC

Performance Estimate:
  - Throughput: ~15 KB/s (STM32F103)
  - Memory: 256 bytes RAM
  - Latency: ~5ms per KB

[Pseudocode, Python, and C implementations included...]
```

## Documentation

- [User Guide](docs/user_guide.md)
- [API Reference](docs/api_reference.md)
- [Architecture Overview](docs/architecture.md)
- [Implementation Specification](spec.md)

## Development

```bash
# Run tests
poetry run pytest

# Code formatting
poetry run black src/

# Linting
poetry run ruff check src/

# Type checking
poetry run mypy src/
```

## Performance Metrics

- **Requirement Parsing Accuracy**: ≥90%
- **Scheme Generation Latency**: <30 seconds
- **Functional Correctness**: ≥85%
- **Scheme Diversity**: 5+ variants per requirement

## Security Notice

⚠️ **Important**: Schemes generated by this tool are intended for research and prototyping only. Production deployment requires:
1. Professional cryptographer review
2. Third-party security audit
3. Comprehensive testing and validation

This tool provides no guarantees regarding the security of generated schemes.

## Contributing

We welcome contributions! Please see [CONTRIBUTING.md](CONTRIBUTING.md) for guidelines.

## License

MIT License - see [LICENSE](LICENSE) file for details.

## Citation

If you use CipherGenius in your research, please cite:

```bibtex
@software{ciphergenius2025,
  title={CipherGenius: An LLM-Driven Framework for Automated Cryptographic Scheme Generation},
  author={CipherGenius Team},
  year={2024},
  url={https://github.com/yourusername/CipherGenius}
}
```

## Roadmap

- [x] Phase 1: Basic infrastructure
- [x] Phase 2: Core functionality (parser, generator)
- [x] Phase 3: Code generation
- [x] Phase 4: Verification system
- [x] Phase 5: Web interface ⭐ NEW!
- [ ] Phase 6: Production deployment

## Contact

- GitHub Issues: [Report bugs or request features](https://github.com/yourusername/CipherGenius/issues)
- Email: ciphergenius@example.com

---

Built with ❤️ for the cryptography community
