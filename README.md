# 🔍 VASA Scanner

> A powerful Web Application Security Assessment (WASA) tool for penetration testers and security researchers.

![PyPI version](https://img.shields.io/pypi/v/vasa-scanner)
![License](https://img.shields.io/badge/license-MIT-blue)
![Python](https://img.shields.io/pypi/pyversions/vasa-scanner)
![Downloads](https://img.shields.io/pypi/dm/vasa-scanner)

---

## ✨ Features

- 🍪 **Cookie Security Scanning** — Detects insecure cookie configurations
- 🌐 **HTTP Method Testing** — Tests for dangerous HTTP methods enabled
- 🔢 **OTP Brute-force Detection** — Checks for OTP rate limiting weaknesses
- 🔄 **Response Manipulation Detection** — Identifies response tampering issues

---

## 📦 Installation
```bash
pip install vasa-scanner
```

---

## 🚀 Usage
```bash
vasa-scan https://example.com
```

---

## 📸 Demo

<!-- Add a screenshot here after running the tool -->
<!-- ![Demo](demo.png) -->

---

## 📋 Requirements

- Python 3.8+
- requests
- openpyxl

---

## 🛠️ How It Works

VASA Scanner automatically tests your target web application for:

1. **Cookie Issues** — Missing Secure, HttpOnly, SameSite flags
2. **HTTP Methods** — Checks if dangerous methods like PUT, DELETE are enabled
3. **OTP Security** — Tests for brute-force protection on OTP endpoints
4. **Response Manipulation** — Detects if responses can be tampered with

---

## 🤝 Contributing

Contributions are welcome!

1. Fork the repo
2. Create your feature branch (`git checkout -b feature/AmazingFeature`)
3. Commit your changes (`git commit -m 'Add AmazingFeature'`)
4. Push to the branch (`git push origin feature/AmazingFeature`)
5. Open a Pull Request

---

## 🐛 Bug Reports

Found a bug? Please open an issue on [GitHub Issues](https://github.com/Jizhin/vasa-scanner/issues)

---

## 📄 License

MIT License — see [LICENSE](LICENSE) for details.

---

## 👤 Author

**Jishin C**
- GitHub: [@Jizhin](https://github.com/Jizhin)
- PyPI: [vasa-scanner](https://pypi.org/project/vasa-scanner)

---

## ⭐ Support

If you find this tool useful, please **star the repo** ⭐ — it helps others discover it!