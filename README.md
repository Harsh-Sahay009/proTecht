# 🛡️ proTecht - Cybersecurity Compliance Automation Platform

[![Python](https://img.shields.io/badge/Python-3.8+-blue.svg)](https://python.org)
[![Flask](https://img.shields.io/badge/Flask-2.3+-green.svg)](https://flask.palletsprojects.com)
[![License](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)
[![Status](https://img.shields.io/badge/Status-Production%20Ready-brightgreen.svg)]()

> **Enterprise-grade compliance automation with AI-powered recommendations**

proTecht is a comprehensive cybersecurity compliance automation platform that supports multiple frameworks including FedRAMP, NIST 800-53, ISO 27001, and PCI DSS. It provides intelligent analysis, real-time compliance checking, and AI-powered remediation recommendations.

## ✨ Features

### 🏛️ Multi-Framework Support
- **FedRAMP Moderate**: 50+ controls for federal cloud compliance
- **NIST 800-53 Rev. 4**: 19 key controls for enterprise security
- **ISO 27001:2013**: 20 controls for information security management
- **PCI DSS v4.0**: 12 requirements for payment card security

### 🤖 AI-Powered Analysis
- **Intelligent Recommendations**: AI-generated compliance suggestions
- **Risk Assessment**: Automated risk scoring and prioritization
- **Remediation Guidance**: Actionable steps for compliance gaps
- **Continuous Learning**: Adaptive recommendations based on audit results

### 📁 Professional File Handling
- **Drag & Drop Upload**: Modern file upload interface
- **Multiple Formats**: TXT, PDF, DOC, DOCX, MD support
- **Real-Time Processing**: Instant file analysis and text extraction
- **Secure Handling**: Automatic file cleanup and validation

### 🎨 Beautiful Interface
- **Futuristic Design**: Modern, responsive web interface
- **Real-Time Updates**: Live compliance status and scoring
- **Interactive Visualizations**: Dynamic charts and progress indicators
- **Mobile Responsive**: Works seamlessly across all devices

## 🚀 Quick Start

### Prerequisites
- Python 3.8 or higher
- pip package manager

### Installation

1. **Clone the repository**
   ```bash
   git clone https://github.com/yourusername/protecht.git
   cd protecht
   ```

2. **Create virtual environment**
   ```bash
   python -m venv venv
   source venv/bin/activate  # On Windows: venv\Scripts\activate
   ```

3. **Install dependencies**
   ```bash
   pip install -r requirements.txt
   ```

4. **Run the application**
   ```bash
   python main.py
   ```

5. **Access the platform**
   ```
   Open http://localhost:5000 in your browser
   ```

## 📊 Usage

### 1. Select Framework
Choose from 4 major compliance frameworks:
- FedRAMP Moderate
- NIST 800-53 Rev. 4
- ISO 27001:2013
- PCI DSS v4.0

### 2. Upload SSP
- **Drag & Drop**: Simply drag your SSP file into the upload area
- **Click to Browse**: Use the file picker to select your document
- **Paste Text**: Alternatively, paste SSP text directly

### 3. Analyze Compliance
- **Instant Analysis**: Get real-time compliance results
- **Detailed Reports**: View control-by-control analysis
- **AI Recommendations**: Receive intelligent remediation suggestions

### 4. Review Results
- **Compliance Summary**: Overall compliance percentage and scoring
- **Control Details**: Individual control status and findings
- **Action Items**: Prioritized remediation recommendations

## 🏗️ Architecture

```
protecht/
├── src/
│   ├── __init__.py
│   └── protecht.py          # Main application logic
├── docs/                    # Documentation
├── tests/                   # Test suite
├── uploads/                 # Temporary file storage
├── main.py                  # Application entry point
├── requirements.txt         # Python dependencies
└── README.md               # This file
```

## 🔧 Configuration

### Environment Variables
```bash
# Optional: Set Flask environment
export FLASK_ENV=development
export FLASK_DEBUG=1

# Optional: Custom port
export PORT=5000
```

### File Upload Settings
- **Max File Size**: 16MB
- **Supported Formats**: TXT, PDF, DOC, DOCX, MD
- **Auto Cleanup**: Files automatically removed after processing

## 🧪 Testing

Run the test suite:
```bash
pytest tests/
```

Run with coverage:
```bash
pytest --cov=src tests/
```

## 📈 Demo Results

### FedRAMP Moderate Analysis
```json
{
  "compliance_summary": {
    "total_controls": 11,
    "passed_controls": 6,
    "failed_controls": 1,
    "partial_controls": 4,
    "compliance_percentage": 54.5,
    "average_confidence": 77.4
  }
}
```

### AI Recommendations Example
```
🤖 AI-Powered Compliance Analysis

Based on analysis of 11 controls, your overall compliance rate is 54.5%.

🚨 CRITICAL ISSUES - Immediate Action Required:
• AC-2 (Account Management):
  - Users without MFA: bob
  - Enable MFA for all users

🎯 STRATEGIC RECOMMENDATIONS:
• Multi-Factor Authentication: Implement MFA for all users immediately
• Vulnerability Management: Establish formal vulnerability management program
• Data Encryption: Ensure all data at rest and in transit is properly encrypted
```

## 🤝 Contributing

1. Fork the repository
2. Create a feature branch (`git checkout -b feature/amazing-feature`)
3. Commit your changes (`git commit -m 'Add amazing feature'`)
4. Push to the branch (`git push origin feature/amazing-feature`)
5. Open a Pull Request

## 📄 License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## 👨‍💻 Author

**Harsh Sahay**
- LinkedIn: [Harsh Sahay](www.linkedin.com/in/harsh-sahay09)
- GitHub: [@harshsahay](https://github.com/Harsh-Sahay009)

## 🙏 Acknowledgments

- FedRAMP for compliance framework standards
- NIST for cybersecurity guidelines
- ISO for information security management standards
- PCI Security Standards Council for payment security requirements

---

**Made with ❤️ for the cybersecurity community** 
