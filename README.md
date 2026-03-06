# VIGILANCE PRO - AI Security Scanner for Kali Linux

VIGILANCE PRO is a professional-grade web security scanner and AI auditor designed for Kali Linux and penetration testing environments. It combines traditional scanning techniques with the power of the Gemini AI model to provide a comprehensive security assessment.

## Features

- **Deep Scan**: Analyzes security headers, cookies, and content.
- **Path Discovery**: Checks for common sensitive endpoints and misconfigurations.
- **AI Auditor**: Uses Gemini AI to perform an OWASP Top 10 assessment.
- **Rich Terminal UI**: Beautifully formatted output with tables, panels, and progress indicators.
- **JSON Export**: Save full scan data and AI reports for later analysis.

## Installation

1. **Clone the repository**:
   ```bash
   git clone https://github.com/yourusername/vigilance-pro.git
   cd vigilance-pro
   ```

2. **Install dependencies**:
   ```bash
   pip3 install -r requirements.txt
   ```

3. **Set up your API Key**:
   Get an API key from [Google AI Studio](https://aistudio.google.com/app/apikey) and set it as an environment variable:
   ```bash
   export GEMINI_API_KEY='your_api_key_here'
   ```

## Usage

**Basic Scan**:
```bash
python3 vigilance.py https://example.com
```

**Save report to JSON**:
```bash
python3 vigilance.py https://example.com --output report.json
```

**Specify API Key via command line**:
```bash
python3 vigilance.py https://example.com --key YOUR_API_KEY
```

## Security Disclaimer

This tool is for educational and authorized security analysis only. Unauthorized scanning of networks you do not own is strictly prohibited and may be illegal. Use responsibly.

## License

MIT License - See LICENSE file for details.
