# proTecht - Cybersecurity Compliance Automation Platform

[![Python](https://img.shields.io/badge/Python-3.8+-blue.svg)](https://python.org)
[![Flask](https://img.shields.io/badge/Flask-2.3+-green.svg)](https://flask.palletsprojects.com)
[![License](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)
[![Status](https://img.shields.io/badge/Status-Production%20Ready-brightgreen.svg)]()

> **Enterprise-grade compliance automation with AI-powered recommendations**

proTecht is a comprehensive cybersecurity compliance automation platform that supports multiple frameworks including FedRAMP, NIST 800-53, ISO 27001, and PCI DSS. It provides intelligent analysis, real-time compliance checking, and AI-powered remediation recommendations.

## Features

### Multi-Framework Support
- **FedRAMP Moderate**: 50+ controls for federal cloud compliance
- **NIST 800-53 Rev. 4**: 19 key controls for enterprise security
- **ISO 27001:2013**: 20 controls for information security management
- **PCI DSS v4.0**: 12 requirements for payment card security

### AI-Powered Analysis
- **Intelligent Recommendations**: AI-generated compliance suggestions
- **Risk Assessment**: Automated risk scoring and prioritization
- **Remediation Guidance**: Actionable steps for compliance gaps
- **Continuous Learning**: Adaptive recommendations based on audit results

### Professional File Handling
- **Drag & Drop Upload**: Modern file upload interface
- **Multiple Formats**: TXT, PDF, DOC, DOCX, MD support
- **Real-Time Processing**: Instant file analysis and text extraction
- **Secure Handling**: Automatic file cleanup and validation

### Beautiful Interface
- **Futuristic Design**: Modern, responsive web interface
- **Real-Time Updates**: Live compliance status and scoring
- **Interactive Visualizations**: Dynamic charts and progress indicators
- **Mobile Responsive**: Works seamlessly across all devices

## Quick Start

### Prerequisites
- Python 3.8 or higher
- pip package manager

### Installation

1. **Clone the repository**
   ```bash
   git clone https://github.com/Harsh-Sahay009/protecht.git
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

## Usage

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

## Architecture

```
proTecht/
├── src/
│   ├── protecht.py          # Main Flask application
│   ├── __init__.py          # Package initialization
│   ├── static/              # Static assets
│   └── templates/           # HTML templates
├── database.py              # Database schema and operations
├── load_aws_data.py         # AWS data loader
├── db_manager.py            # Database management utilities
├── main.py                  # Application entry point
├── requirements.txt         # Python dependencies
├── .gitignore              # Git ignore rules
├── README.md               # Project documentation
├── LICENSE                 # MIT License
├── docs/                   # Documentation directory
├── uploads/                # File upload directory
└── protecht.db             # SQLite database
```

## Configuration

### Environment Variables
Create a `.env` file in the project root:

```bash
# OpenAI API Key for AI recommendations
OPENAI_API_KEY=your_openai_api_key_here

# Database configuration (optional)
DATABASE_URL=sqlite:///protecht.db
```

### API Configuration
- **OpenAI API**: Required for AI-powered recommendations
- **Database**: SQLite for local development, configurable for production
- **File Upload**: 16MB maximum file size, multiple format support

## Testing

### Manual Testing
1. **Start the application**: `python main.py`
2. **Access the interface**: http://localhost:5000
3. **Test file upload**: Upload sample SSP files
4. **Test analysis**: Run compliance analysis
5. **Test AI recommendations**: Generate AI suggestions

### Automated Testing
```bash
# Run tests
pytest

# Run with coverage
pytest --cov=src
```

## Demo Results

### Sample Analysis Output
```
Compliance Analysis Results:
- Overall Compliance: 85.7%
- Controls Analyzed: 7
- Passed Controls: 6
- Partial Controls: 1
- Failed Controls: 0

Control Details:
AC-2: Account Management - PASS (100%)
IA-2: Identification & Authentication - PASS (100%)
CP-7: Alternate Processing Site - PASS (100%)
CP-9: System Backup - PASS (100%)
SC-7: Boundary Protection - PARTIAL (70%)
SI-4: System Monitoring - PASS (100%)
AU-2: Audit Events - PASS (100%)
```

### AI-Powered Compliance Analysis
Based on analysis of 7 controls, your overall compliance rate is 85.7%.

**CRITICAL ISSUES - Immediate Action Required:**
None found.

**MEDIUM PRIORITY - Address Soon:**
• **SC-7 (Boundary Protection)**:
  - Public buckets found: dev-test-binaries

**STRATEGIC RECOMMENDATIONS:**
• **Boundary Protection**: Block public access on all S3 buckets immediately
• **Continuous Improvement**: Focus on addressing partial controls to achieve higher compliance levels

**NEXT STEPS:**
1. **Prioritize Critical Issues**: Address all FAIL controls immediately
2. **Review Partial Controls**: Implement recommendations for PARTIAL controls
3. **Document Remediation**: Keep records of all changes made
4. **Schedule Follow-up**: Plan for regular compliance assessments

## Contributing

1. Fork the repository
2. Create a feature branch: `git checkout -b feature-name`
3. Commit your changes: `git commit -am 'Add feature'`
4. Push to the branch: `git push origin feature-name`
5. Submit a pull request

## License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## Author

**Harsh Sahay**
- GitHub: [@Harsh-Sahay009](https://github.com/Harsh-Sahay009)
- LinkedIn: [Harsh Sahay](https://www.linkedin.com/in/harsh-sahay09/)

**Made with dedication for the cybersecurity community** 
