#!/usr/bin/env python3
"""
proTecht - Cybersecurity Compliance Automation Platform
=======================================================

A comprehensive compliance automation tool that supports multiple frameworks
including FedRAMP, NIST 800-53, ISO 27001, and PCI DSS with AI-powered
recommendations and professional file handling capabilities.

Author: Harsh Sahay
Version: 1.0.0
License: MIT
"""

import sys
import os

# Add src directory to Python path
sys.path.insert(0, os.path.join(os.path.dirname(__file__), 'src'))

from protecht import app

if __name__ == '__main__':
    print("🚀 Starting proTecht - Cybersecurity Compliance Automation Platform")
    print("📊 Server will be available at http://localhost:5000")
    print("🎯 No authentication required!")
    print("=" * 60)
    
    app.run(
        host='0.0.0.0',
        port=5000,
        debug=True,
        use_reloader=True
    )
