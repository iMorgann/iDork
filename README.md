# iDork Suite v2.0 - Complete Intelligence Gathering Toolkit

<div align="center">

![iDork Logo](https://img.shields.io/badge/iDork%20Suite-v2.0-blue?style=for-the-badge&logo=search&logoColor=white)
[![Python](https://img.shields.io/badge/Python-3.7+-blue?style=flat-square&logo=python)](https://python.org)
[![License](https://img.shields.io/badge/License-MIT-green?style=flat-square)](LICENSE)
[![Platform](https://img.shields.io/badge/Platform-Windows%20%7C%20Linux%20%7C%20macOS-lightgrey?style=flat-square)](https://github.com/yourusername/idork)

**Complete intelligence gathering toolkit with Google Dorking, vulnerability scanning, and URL extraction capabilities**

[Features](#-features) • [Installation](#-installation) • [Tools Overview](#-tools-overview) • [Usage](#-usage) • [Screenshots](#-screenshots) • [Contributing](#-contributing)

</div>

---

## 🛠️ Tools Overview

The iDork Suite consists of three powerful tools designed for comprehensive web intelligence gathering:

### 🔍 **iDork v2.0** (`iDork.py`)
**Advanced Google Dorking Framework with Risk Analysis**
- Multi-search engine support (Google, Bing, DuckDuckGo, Yahoo, Yandex)
- Real-time vulnerability analysis with risk scoring
- Risk-based file separation (HIGH/MEDIUM/LOW)
- Auto-save with crash protection
- Pre-built dork templates
- Interactive user interface

### 🎯 **IDork Scanner** (`IDork_Scanner.py`)
**Smart Payload Vulnerability Scanner**
- SQL injection, XSS, and SSTI payload testing
- Multi-threading for faster scanning
- Proxy rotation support
- Response analysis and snapshots
- Multiple export formats (TXT, JSON, CSV)
- Authentication token support

### 📎 **URL Extractor** (`UrlExtractor.py`)
**Universal URL Extraction Tool**
- Extract URLs from any file type (TXT, JSON, CSV, logs)
- Advanced encoding detection
- Multiple URL pattern matching
- File picker interface
- Clean and deduplicated output

---

## 🌟 Features

### 🔍 **iDork v2.0 Enhanced Features**
- **Multi-Search Engine Support** - DuckDuckGo, Google, Bing, Yahoo, Yandex
- **Vulnerability Analysis** - Real-time risk assessment of discovered URLs
- **Risk-Based Categorization** - Automatic separation into HIGH/MEDIUM/LOW risk files
- **Advanced Auto-Save** - Never lose progress with crash protection
- **Dork Suggestions** - AI-powered dork generation based on findings
- **Interactive Interface** - No command-line knowledge required
- **Proxy Support** - Single proxy, file import, or manual list entry

### 🎯 **IDork Scanner Features**
- **Smart Payload Testing** - SQLi, XSS, SSTI vulnerability detection
- **Multi-Threading** - Configurable concurrent scanning
- **Proxy Picker** - Automatic proxy rotation from list
- **Response Analysis** - Pattern matching for vulnerability indicators
- **Flexible Methods** - Support for GET and POST requests
- **Export Options** - TXT, JSON, CSV output formats
- **Authentication** - Bearer token support for authenticated scanning

### 📎 **URL Extractor Features**
- **Universal Extraction** - Works with any file format
- **Encoding Detection** - Automatic charset detection and handling
- **Pattern Matching** - Multiple regex patterns for comprehensive extraction
- **File Picker** - Easy file selection with GUI
- **Clean Output** - Deduplicated URLs in clean text format

---

## 📋 Requirements

- **Python 3.7+**
- **Windows 10/11, macOS 10.14+, or Linux**
- **Internet connection** (for search tools)
- **4GB RAM minimum** (8GB recommended for large operations)

## 🚀 Installation

### Method 1: Complete Package Install (Recommended)

```bash
# Clone the complete iDork Suite
git clone https://github.com/iMorgann/iDork-Suite.git
cd iDork-Suite

# Install all dependencies
pip install -r requirements.txt

# Verify installation
python iDork.py --help
python IDork_Scanner.py
python UrlExtractor.py
```

### Method 2: Manual Dependency Installation

```bash
# Core dependencies for all tools
pip install rich requests duckduckgo-search

# Additional dependencies
pip install googlesearch-python chardet  # Optional but recommended
pip install tkinter                      # Usually pre-installed

# Threading and networking (usually included)
pip install urllib3 concurrent.futures
```

### Method 3: Virtual Environment Setup

```bash
# Create isolated environment
python -m venv idork-suite-env

# Activate environment
# Windows:
idork-suite-env\Scripts\activate
# macOS/Linux:
source idork-suite-env/bin/activate

# Install dependencies
pip install rich requests duckduckgo-search googlesearch-python chardet

# Run any tool
python iDork.py
```

---

## 🎮 Usage Guide

## 🔍 **iDork v2.0 Usage**

### Interactive Mode (Recommended)
```bash
# Launch interactive interface
python iDork.py

# Follow the guided setup:
# 1. Choose search engine
# 2. Setup proxy (optional)
# 3. Select dork source (templates/file/manual/target)
# 4. Configure search and auto-save
# 5. Start enhanced search with risk analysis
```

### Dork File Format
Create a text file with dorks (one per line):
```
site:example.com login
site:example.com admin panel
inurl:admin site:example.com
filetype:pdf confidential site:example.com
"index of" password site:example.com
intext:"sql syntax" site:example.com
```

### Risk-Based Output
iDork automatically categorizes findings:
- **HIGH RISK** - Potentially vulnerable URLs
- **MEDIUM RISK** - URLs worth investigating  
- **LOW RISK** - Probably safe URLs

## 🎯 **IDork Scanner Usage**

### File Picker Mode (Easy)
```bash
# Launch with GUI file picker
python IDork_Scanner.py

# The tool will prompt you for:
# 1. URL list file selection
# 2. Thread count configuration
# 3. Proxy file (optional)
# 4. Authentication token (optional)
# 5. POST body template (optional)
```

### URL List Format
Create a text file with URLs containing parameters:
```
https://example.com/page.php?id=1
https://target.com/search.php?query=test
https://site.com/product.asp?pid=123
https://app.com/user.php?user_id=456
```

### Scanning Process
The scanner will:
1. **Parse URLs** - Extract parameters for testing
2. **Inject Payloads** - Test SQL injection, XSS, SSTI
3. **Analyze Responses** - Pattern match for vulnerabilities
4. **Generate Reports** - Export findings in multiple formats

### Output Files
- `vulnerable_urls.txt` - Human-readable results
- `vulnerable_urls.json` - Structured data for tools
- `vulnerable_urls.csv` - Spreadsheet-compatible format

## 📎 **URL Extractor Usage**

### GUI Mode (Recommended)
```bash
# Launch with file picker
python UrlExtractor.py

# Select input file through GUI
# Supports: TXT, JSON, CSV, LOG files
# Output: cleaned URLs in text format
```

### Command Line Mode
```bash
# Extract from specific file
python UrlExtractor.py input_file.txt

# Output will be saved as: input_file_extracted_urls.txt
```

### Supported Input Formats
- **Text Files** - Log files, reports, documentation
- **JSON Files** - API responses, configuration files
- **CSV Files** - Spreadsheets, database exports
- **Log Files** - Server logs, application logs

---

## 📊 Output Examples

### iDork v2.0 Risk-Based Output
```
iDork v2.0 Enhanced - High Risk URLs
============================================
Generated: 2025-05-27 14:30:15
Risk Level: HIGH
Total Results: 23
============================================

1. [DUCKDUCKGO] Admin Login Panel
   URL: https://example.com/admin/login.php?redirect=dashboard
   Query: site:example.com inurl:admin
   Risk: HIGH - Potentially vulnerable parameters: redirect
   Vulnerabilities: Vulnerable parameter: redirect
   Time: 2025-05-27T14:30:22
```

### IDork Scanner Results
```
[+] URL: https://example.com/search.php?q=test
    Parameter: q
    Payload: ' OR '1'='1
    Vulnerability Type: SQLi
    Status Code: 200
    Response Snapshot: MySQL syntax error near '' OR '1'='1' at line 1...
```

### URL Extractor Output
```
# Extracted URLs from: logfile.txt
# Generated: 2025-05-27 14:30:15
# Total URLs: 156

https://example.com/api/users
https://target.com/admin/panel
https://secure.site.com/login
...
```

---

## 🔧 Advanced Configuration

### iDork v2.0 Configuration

#### Search Engine Selection
- **DuckDuckGo** - Most reliable, fewer rate limits
- **Google** - Comprehensive results (requires googlesearch-python)
- **Bing** - Good alternative source
- **Yahoo/Yandex** - Additional coverage

#### Auto-Save Settings
```python
# Customizable settings in interactive mode
auto_save_interval = 50      # Save every N results
output_formats = ["txt", "json", "csv"]  # Multiple formats
risk_separation = True       # Separate files by risk level
```

### IDork Scanner Configuration

#### Payload Customization
```python
# Edit payloads in IDorkScanner class
payloads = {
    "sqli": ["' OR '1'='1", "' UNION SELECT NULL--", "' OR sleep(3)--"],
    "xss": ["<script>alert(1)</script>", "<img src=x onerror=alert(1)>"],
    "ssti": ["{{7*7}}", "{{config.items()}}", "${7*7}"]
}
```

#### Threading and Delays
- **Threads**: 1-20 (default: 5)
- **Delay**: 0.5-10 seconds (default: 1.5)
- **Timeout**: 5-30 seconds (default: 8)

### URL Extractor Configuration

#### Custom Regex Patterns
```python
# Add custom URL patterns in URLExtractor class
custom_patterns = [
    re.compile(r'api_url:\s*(https?://[^\s]+)', re.IGNORECASE),
    re.compile(r'endpoint=(https?://[^&\s]+)', re.IGNORECASE)
]
```

---

## 🎯 Use Cases

### 🔒 **Security Testing Workflow**
1. **Discovery** - Use iDork v2.0 to find potentially vulnerable pages
2. **Analysis** - Review HIGH risk URLs from categorized output
3. **Testing** - Use IDork Scanner to test discovered URLs for vulnerabilities
4. **Reporting** - Compile findings from all tools for comprehensive assessment

### 🕵️ **OSINT Investigation**
1. **Initial Gathering** - Use iDork with target-specific dorks
2. **URL Collection** - Extract additional URLs from discovered documents using URL Extractor
3. **Deep Analysis** - Scan extracted URLs for sensitive information leaks

### 📚 **Research and Documentation**
1. **Data Collection** - Gather URLs related to specific topics
2. **URL Processing** - Extract and clean URLs from research documents
3. **Verification** - Test URL accessibility and categorize by risk level

---

## ⚡ Performance Tips

### For Large-Scale Operations
- **Use proxy rotation** to avoid rate limiting
- **Enable auto-save** to prevent data loss
- **Process in batches** (1000-5000 dorks/URLs)
- **Use threading** appropriately (5-10 threads max)
- **Monitor memory usage** during large scans

### Rate Limiting Mitigation
- **Increase delays** between requests (8-15 seconds)
- **Use multiple search engines** to distribute load
- **Implement proxy rotation** for bulk operations
- **Take breaks** between large scanning sessions

---

## 🐛 Troubleshooting

### Common Issues and Solutions

#### Installation Problems
```bash
# If pip install fails
python -m pip install --upgrade pip
pip install --no-cache-dir rich requests duckduckgo-search

# For encoding issues
pip install chardet

# For GUI issues (Linux)
sudo apt-get install python3-tk
```

#### Runtime Errors
- **"No module named 'rich'"** → `pip install rich`
- **"No results found"** → Check internet connection, try different engine
- **"Rate limited"** → Increase delay, use proxy, switch engines
- **"File encoding error"** → URL Extractor handles this automatically

#### Performance Issues
- **Slow scanning** → Reduce thread count, increase delays
- **Memory usage** → Process smaller batches, enable auto-save
- **Network timeouts** → Increase timeout values, check connection

---

## 📚 Documentation

### Tool-Specific Guides
- **[iDork Guide](docs/idork-guide.md)** - Comprehensive dorking strategies
- **[Scanner Guide](docs/scanner-guide.md)** - Vulnerability testing methodology
- **[Extractor Guide](docs/extractor-guide.md)** - URL extraction techniques

### Reference Materials
- **[Dork Database](docs/dorks.md)** - Collection of useful Google dorks
- **[Vulnerability Patterns](docs/vulns.md)** - Common vulnerability indicators
- **[API Reference](docs/api.md)** - For developers integrating tools

---

## ⚠️ Legal and Ethical Use

**CRITICAL: This toolkit is for authorized testing and educational purposes only.**

### ✅ **Authorized Use**
- Testing systems you own or have explicit written permission to test
- Educational research and learning
- Bug bounty programs with proper scope
- Security assessments with client authorization
- Academic research with proper ethical approval

### ❌ **Prohibited Use**
- Accessing systems without authorization
- Malicious activities or attacks
- Violating terms of service
- Harassment or illegal activities
- Commercial use without proper licensing

### 🛡️ **Best Practices**
- Always obtain proper authorization before testing
- Respect rate limits and terms of service
- Document all testing activities
- Report vulnerabilities responsibly
- Follow applicable laws and regulations

**The developers assume no responsibility for misuse of these tools.**

---

## 🤝 Contributing

We welcome contributions to improve the iDork Suite!

### Ways to Contribute
- 🐛 **Bug Reports** - Report issues via GitHub Issues
- 💡 **Feature Requests** - Suggest new capabilities
- 📝 **Documentation** - Improve guides and examples
- 🔧 **Code Contributions** - Submit pull requests
- 🌟 **Community** - Star the repository and share

### Development Setup
```bash
# Fork and clone
git clone https://github.com/iMorgann/iDork-Suite.git
cd iDork-Suite

# Create feature branch
git checkout -b feature/your-feature

# Install development dependencies
pip install -r requirements-dev.txt

# Test your changes
python -m pytest tests/

# Submit pull request
```

---

## 🎖️ Credits

**Developed by:** [root](https://github.com/iMorgann) ([@rootbck](https://t.me/rootbck))

### Tool Evolution
- **iDork v1.0** - Basic Google dorking functionality
- **iDork v2.0** - Enhanced with risk analysis and multi-engine support
- **IDork Scanner** - Dedicated vulnerability scanning capabilities
- **URL Extractor** - Universal URL extraction from any source

### Special Thanks
- **DuckDuckGo** for their excellent search API
- **Rich library** for beautiful terminal interfaces
- **Security research community** for inspiring these tools
- **Beta testers** who provided valuable feedback

---

## 📄 License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## 📞 Support

- **🐛 Bug Reports**: [GitHub Issues](https://github.com/iMorgann/iDork-Suite/issues)
- **💬 Telegram**: [@rootbck](https://t.me/rootbck)
- **📧 Email**: securedbox247@outlook.com
- **📖 Documentation**: [Wiki](https://github.com/iMorgann/iDork-Suite/wiki)

---

<div align="center">

**⭐ If you find the iDork Suite useful, please consider starring the repository! ⭐**

[![GitHub stars](https://img.shields.io/github/stars/iMorgann/iDork-Suite?style=social)](https://github.com/iMorgann/iDork-Suite/stargazers)

Made with ❤️ by the security community

</div>