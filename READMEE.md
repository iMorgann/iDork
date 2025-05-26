# iDork v2.0 - Intelligent Dorking Framework

<div align="center">

![iDork Logo](https://img.shields.io/badge/iDork-v2.0-blue?style=for-the-badge&logo=search&logoColor=white)
[![Python](https://img.shields.io/badge/Python-3.7+-blue?style=flat-square&logo=python)](https://python.org)
[![License](https://img.shields.io/badge/License-MIT-green?style=flat-square)](LICENSE)
[![Platform](https://img.shields.io/badge/Platform-Windows%20%7C%20Linux%20%7C%20macOS-lightgrey?style=flat-square)](https://github.com/yourusername/idork)

**The most user-friendly Google Dorking tool with multi-search engine support and real-time auto-save**

[Features](#-features) • [Installation](#-installation) • [Usage](#-usage) • [Screenshots](#-screenshots) • [Contributing](#-contributing)

</div>

---

## 🌟 Features

### 🔍 **Multi-Search Engine Support**
- **DuckDuckGo** - Fast and reliable (recommended)
- **Google** - Most comprehensive results
- **Bing** - Microsoft's search engine
- **Yahoo** - Alternative search provider
- **Yandex** - Russian search engine

### 💾 **Advanced Auto-Save System**
- **Real-time saving** every N results (customizable)
- **Multiple formats** - TXT, JSON, CSV
- **Crash protection** - Never lose your progress
- **Live progress tracking** with URL counter

### 🎯 **User-Friendly Interface**
- **No command-line knowledge required**
- **Interactive guided setup**
- **File picker for easy file selection**
- **Beautiful progress bars and statistics**

### 🔒 **Proxy Support**
- **Single proxy** configuration
- **Proxy file import** (bulk loading)
- **Automatic proxy rotation**
- **Failed proxy detection**

### 📝 **Pre-built Dork Templates**
- **Login Pages** - Find admin panels and login forms
- **Config Files** - Locate configuration files
- **Backup Files** - Discover backup and old files
- **Directory Listings** - Find exposed directories
- **Error Pages** - Locate error messages and debug info
- **Sensitive Info** - Find confidential documents
- **Database Files** - Discover database files
- **Log Files** - Locate log files

### ✅ **URL Verification**
- **Accessibility checking** - Test if URLs are live
- **HTTP status codes** - Get response codes
- **Threaded verification** - Fast bulk checking
- **Filter accessible URLs** - Show only working links

## 📋 Requirements

- **Python 3.7+**
- **Windows 10/11, macOS 10.14+, or Linux**
- **Internet connection**
- **4GB RAM minimum** (8GB recommended for large searches)

## 🚀 Installation

### Method 1: Quick Install (Recommended)

```bash
# Clone the repository
git clone https://github.com/yourusername/idork.git
cd idork

# Install dependencies
pip install -r requirements.txt

# Run iDork
python idork.py
```

### Method 2: Manual Setup

```bash
# Install required packages individually
pip install rich duckduckgo-search requests

# Optional dependencies for enhanced features
pip install googlesearch-python  # For Google search support
pip install tkinter              # For file picker (usually pre-installed)

# Download and run
wget https://raw.githubusercontent.com/yourusername/idork/main/idork.py
python idork.py
```

### Method 3: Virtual Environment (Recommended for developers)

```bash
# Create virtual environment
python -m venv idork-env

# Activate virtual environment
# On Windows:
idork-env\Scripts\activate
# On macOS/Linux:
source idork-env/bin/activate

# Install dependencies
pip install -r requirements.txt

# Run iDork
python idork.py
```

## 🎮 Usage

### Basic Usage (Interactive Mode)

Simply run the script and follow the prompts:

```bash
python idork.py
```

### Advanced Usage Examples

#### Using Pre-built Templates
1. Run `python idork.py`
2. Choose **templates** as input method
3. Select a category (e.g., "Login Pages")
4. Enter target domain (e.g., `example.com`)
5. Configure search settings

#### Bulk Dorking from File
1. Create a text file with dorks (one per line):
   ```
   site:example.com login
   site:example.com admin
   inurl:admin site:example.com
   filetype:pdf site:example.com
   ```
2. Run iDork and choose **file** as input method
3. Select your dork file using the file picker

#### Target-Specific Scanning
1. Choose **target** as input method
2. Enter target domain: `example.com`
3. Select categories or choose "all"
4. iDork generates targeted dorks automatically

## 🛠️ Configuration Options

### Search Configuration
- **Max results per dork**: 1-1000 (default: 100)
- **Request delay**: 1-30 seconds (default: 8s)
- **URL verification**: Enable/disable accessibility checking
- **Search engine**: Choose your preferred engine

### Auto-Save Settings
- **Enable/disable**: Protect against data loss
- **Save interval**: Every 50-500 results (default: 50)
- **Output formats**: TXT, JSON, CSV (multiple selection)
- **Custom filename**: Set your preferred naming

### Proxy Configuration
- **Single proxy**: `http://ip:port` or `ip:port`
- **Proxy file**: Bulk load from text file
- **Manual list**: Enter multiple proxies interactively

## 📊 Output Formats

### TXT Format (Human-Readable)
```
iDork v2.0 - Live Search Results
==================================================
Started: 2025-05-26 11:28:55
Auto-save: Every 50 results
==================================================

1. [DUCKDUCKGO] Admin Login Page
   URL: https://example.com/admin/login
   Query: site:example.com login
   Time: 2025-05-26T11:29:01
--------------------------------------------------
```

### JSON Format (Structured Data)
```json
{
  "metadata": {
    "tool": "iDork v2.0",
    "started": "2025-05-26T11:28:55",
    "total_results": 1500
  },
  "results": [
    {
      "url": "https://example.com/admin",
      "title": "Admin Panel",
      "engine": "duckduckgo",
      "query": "site:example.com admin",
      "timestamp": "2025-05-26T11:29:01"
    }
  ]
}
```

### CSV Format (Spreadsheet-Friendly)
```csv
#,URL,Title,Engine,Query,Timestamp
1,https://example.com/admin,Admin Panel,duckduckgo,site:example.com admin,2025-05-26T11:29:01
```

## 🎯 Use Cases

### 🔒 **Security Research**
- **Penetration testing** - Find attack vectors
- **Bug bounty hunting** - Discover vulnerabilities
- **Security audits** - Assess organizational exposure

### 🕵️ **OSINT (Open Source Intelligence)**
- **Information gathering** - Collect public data
- **Digital footprint analysis** - Map online presence
- **Competitive intelligence** - Research competitors

### 📚 **Academic Research**
- **Data collection** - Gather research materials
- **Web crawling** - Index specific content
- **Digital archaeology** - Find historical data

## ⚠️ Legal Disclaimer

**IMPORTANT: This tool is for educational and authorized testing purposes only.**

- ✅ **Only test systems you own or have explicit permission to test**
- ✅ **Comply with all applicable local, state, and federal laws**
- ✅ **Use responsibly and ethically**
- ❌ **Do not access systems without authorization**
- ❌ **Do not use for malicious purposes**

**The developer assumes no responsibility for misuse of this tool.**

## 📸 Screenshots

### Main Interface
![Main Interface](screenshots/main_interface.png)

### Search Progress
![Search Progress](screenshots/search_progress.png)

### Results Display
![Results Display](screenshots/results_display.png)

## 🐛 Troubleshooting

### Common Issues

#### "No results found"
- **Check internet connection**
- **Try different search engine**
- **Reduce request delay**
- **Verify dork syntax**

#### "Rate limited" errors
- **Increase request delay** (try 10-15 seconds)
- **Use proxy rotation**
- **Switch to different engine**
- **Take breaks between large searches**

#### Auto-save not working
- **Check file permissions** in output directory
- **Ensure sufficient disk space**
- **Try different output format**

#### Search engine errors
- **Install optional dependencies**: `pip install googlesearch-python`
- **Check proxy configuration**
- **Verify internet connectivity**

### Performance Tips

- **Use DuckDuckGo** for best reliability
- **Enable auto-save** for large searches
- **Use proxy rotation** for bulk scanning
- **Increase delay** if getting rate limited
- **Process results in batches** (1000-5000 dorks)

## 🤝 Contributing

We welcome contributions! Here's how you can help:

### Ways to Contribute
- 🐛 **Report bugs** via GitHub Issues
- 💡 **Suggest features** or improvements
- 📝 **Improve documentation**
- 🔧 **Submit pull requests**
- 🌟 **Star the repository**

### Development Setup
```bash
# Fork and clone the repository
git clone https://github.com/yourusername/idork.git
cd idork

# Create development branch
git checkout -b feature/your-feature

# Install development dependencies
pip install -r requirements-dev.txt

# Make your changes and test
python idork.py

# Submit pull request
```

### Code Guidelines
- **Follow PEP 8** Python style guide
- **Add comments** for complex logic
- **Test your changes** thoroughly
- **Update documentation** if needed

## 📚 Documentation

- **[Wiki](https://github.com/yourusername/idork/wiki)** - Detailed guides and tutorials
- **[API Reference](docs/api.md)** - For developers integrating iDork
- **[Dork Database](docs/dorks.md)** - Collection of useful dorks
- **[FAQ](docs/faq.md)** - Frequently asked questions

## 🎖️ Credits

**Developed by:** [root](https://github.com/yourusername) ([@rootbck](https://t.me/rootbck))

### Special Thanks
- **DuckDuckGo** for their excellent search API
- **Rich library** for beautiful terminal interfaces
- **Python community** for amazing libraries
- **Security researchers** who inspired this tool

## 📄 License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## 📞 Support

- **🐛 Bug Reports**: [GitHub Issues](https://github.com/yourusername/idork/issues)
- **💬 Telegram**: [@rootbck](https://t.me/rootbck)
- **📧 Email**: your.email@example.com
- **📖 Documentation**: [Wiki](https://github.com/yourusername/idork/wiki)

---

<div align="center">

**⭐ If you find iDork useful, please consider starring the repository! ⭐**

Made with ❤️ by [root](https://github.com/yourusername)

</div>