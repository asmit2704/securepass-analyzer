# SecurePass Analyzer

Simple CLI tool to analyze password strength and provide suggestions.

## Features
- Length, character-class checks (upper/lower/digits/symbols)
- Entropy estimate (bits)
- Suggestions to strengthen weak passwords
- SHA-256 hash demo (shows hashing concept)
- Colorful CLI output

## Requirements
- Python 3.8+
- pip

## Setup & Run
```bash
git clone https://github.com/YOUR_USERNAME/securepass-analyzer.git
cd securepass-analyzer
python3 -m venv venv            # optional but recommended
source venv/bin/activate       # on Windows use: venv\Scripts\activate
pip install -r requirements.txt
python password_checker.py
