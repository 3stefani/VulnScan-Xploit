# ⭐VULN SCAN & XPLOIT⭐
# Advanced Vulnerability and Exploit Scanner

A vulnerability scanner that searches for CVEs and available exploits using multiple data sources.

## Features

- **Complete CVE Search** using the NVD (National Vulnerability Database) API
- **Public Exploit Detection** from multiple trusted sources
- **Detailed Visual Reports** with formatted tables and colors
- **Concurrent Processing** for improved efficiency
- **Risk Analysis** based on CVSS scoring
- **Direct Links** to exploits and technical documentation
- **Intuitive Interface** with Rich for enhanced user experience

## Data Sources

- **NVD (National Vulnerability Database)** - Official vulnerabilities
- **Exploit-DB** - Local exploit database
- **CIRCL CVE Search API** - Additional CVE search API
- **CVEDetails** - Detailed technical information
- **Official NVD References** - Additional links to exploits

## Installation

### Prerequisites

- Python 3.8 or higher
- Internet connection to download updated data

### Install Dependencies

```bash
pip install -r requirements.txt
```

### Main Dependencies

- `requests` - For HTTP requests to APIs
- `rich` - For enhanced console interfaces and formatted tables

## Usage

### Basic Execution

```bash
python main.py
```

### Search Examples

The scanner accepts various search terms:

- **Specific software**: `wordpress`, `apache httpd`, `nginx`
- **Programming languages**: `php`, `python`, `java`
- **Operating systems**: `windows server`, `linux kernel`
- **Services**: `openssh`, `mysql`, `tomcat`

### Example Session

```
⭐ ESCÁNER AVANZADO DE VULNERABILIDADES Y EXPLOITS⭐
==================================

Search examples:
  - General software: wordpress, apache httpd, nginx
  - Specific plugins/versions: WordPress Frontend Login and Registration Blocks Plugin 1.0.7
  - Programming languages: php, python, java
  - Operating systems: windows server, linux kernel
  - Services: openssh, mysql, tomcat
  - More specific services: Apache HTTP Server 2.4.41, MySQL 8.0.25, OpenSSH 7.4

✋ Enter the service/software to analyze: wordpress

⚡ Starting comprehensive analysis for: 'wordpress'
⏳ This process may take a few minutes...
```

## Interpreting Results

### Main Table

The results table includes:

- **CVE ID**: Unique vulnerability identifier
- **Description**: Technical summary of the issue
- **CVSS**: Severity score (0-10)
- **Published**: Publication date
- **Exploits**: Number of available public exploits
- **Exploit URLs**: Direct links to exploits
- **Details**: Links to technical documentation

### CVSS Color Codes

- 🔴 **Red (9.0-10.0)**: Critical vulnerabilities
- 🟠 **Orange (7.0-8.9)**: High vulnerabilities
- 🟡 **Yellow (4.0-6.9)**: Medium vulnerabilities
- 🟢 **Green (0.1-3.9)**: Low vulnerabilities

### Exploit Indicators

- 👻  **Number**: Available public exploits
- ❌ **0**: No known exploits

## Project Structure

```
vuln_scanner/
├── main.py              # Main application
├── vuln_scanner.py      # Core scanner class
├── report_generator.py  # Visual report generator
├── config.py           # Project configuration
├── requirements.txt    # Python dependencies
├── README.md          # This file
└── exploitdb_files.csv # Local database (auto-downloaded)
```

## 🔧 Advanced Configuration

### Customization in config.py

You can modify various scanner aspects:

```python
# Result limits
LIMITS = {
    'max_results_per_search': 20,    # Max CVEs per search
    'max_concurrent_workers': 2,     # Concurrent threads
    'max_exploits_per_cve': 5,       # Exploits per CVE
}

# Connection timeouts
TIMEOUTS = {
    'nvd_request': 15,      # Seconds for NVD
    'circl_request': 10,    # Seconds for CIRCL
    'rate_limit_delay': 0.5 # Delay between requests
}
```

### Environment Variables

```bash
export SCANNER_DEBUG=True          # Enable debug mode
export ENABLE_CACHING=True         # Enable caching
export LOG_LEVEL=DEBUG            # Logging level
```

## 🛡️ Security Considerations

### Responsible Use

This scanner is designed for:
- ✅ Authorized security audits
- ✅ Internal risk assessment
- ✅ Legitimate security research
- ✅ Cybersecurity education

### Limitations

- Results depend on external API availability
- May contain false positives or outdated information
- Does not replace professional pentesting tools
- Requires manual verification of found exploits

## Troubleshooting

### Common Errors

**Connection Error**
```
HTTP Error 403: Could not connect to NVD
```
*Solution*: Check internet connection and try again later.

**Database Not Downloaded**
```
⚠️ Could not download database
```
*Solution*: Verify connectivity and write permissions.

**No Results**
```
❌ No vulnerabilities found for this service
```
*Solution*: Try more specific terms or software versions.

### Logging and Debug

For more debugging information:

```bash
export SCANNER_DEBUG=True
python main.py
```

## 📄 License

This project is licensed under the MIT License. See the `LICENSE` file for details.

## ⚠️ Disclaimer

This software is provided "as is" without warranties. Users are responsible for ethical and legal use of this tool. It should not be used for malicious or unauthorized activities.

## 📞 Support

To report bugs or request features, please create an issue in the project repository.

---

**Developed with ⚡❤️⚡ for the cybersecurity community**
