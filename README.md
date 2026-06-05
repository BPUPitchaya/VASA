# VASA - Vulnerability Assessment Scanner Application

A lightweight, Python-based Vulnerability Assessment Scanner designed to detect common security weaknesses in websites and network-facing systems.

## Features

- Port scanning with service detection and banner grabbing
- HTTP/HTTPS header security analysis
- SSL/TLS configuration checking
- CVE (Common Vulnerabilities and Exposures) detection
- Web-based interface for easy interaction
- Real-time scan status with progress tracking
- Multiple scan modes (Quick, Standard, Full)
- Rate limiting and safety checks
- PDF report generation

## Prerequisites

- Python 3.8+ (tested with Python 3.13.3)
- pip (Python package manager)
- nmap (optional, for advanced port scanning)

## Installation & Setup

### 1. Clone the Repository
```bash
git clone <repository-url>
cd VASA
```

### 2. Create and Activate Virtual Environment

**On Windows:**
```bash
python -m venv .venv
.\.venv\Scripts\activate
```

**On macOS/Linux:**
```bash
python3 -m venv .venv
source .venv/bin/activate
```

### 3. Install Dependencies
```bash
pip install -r requirements.txt
```

### 4. Run the Application
```bash
python run.py
```

The application will start on `http://localhost:5000`

## Usage

1. Open your browser and go to `http://localhost:5000`
2. Enter a target URL or IP address
3. Select a scan mode:
   - **Quick Scan**: Fast security headers and Port scan
   - **Standard Scan**: 22 common ports + security analysis
   - **Full Scan**: All ports + comprehensive analysis
4. Check "I have authorization" if scanning external targets
5. Click "Start Scan"
6. Monitor real-time progress
7. View detailed results when complete

## Project Structure

```
VASA/
├── app/                      # Main application package
│   ├── api/                  # API endpoints
│   │   ├── endpoints.py      # Main API routes (scan, status, report)
│   │   └── endpoints_new.py  # Alternative implementation
│   ├── core/                 # Core scanning logic
│   │   └── scanner.py        # Base scanner class
│   ├── middleware/           # Middleware components
│   │   ├── rate_limiter.py   # Rate limiting
│   │   └── safety_checks.py  # Target validation
│   ├── scanners/             # Scanning modules
│   │   ├── port_scanner.py   # Port scanning & banner grabbing
│   │   ├── http_scanner.py   # HTTP/HTTPS analysis
│   │   ├── ssl_scanner.py    # SSL/TLS checking
│   │   ├── headers_scanner.py # Security headers
│   │   ├── cve_checker.py    # CVE detection
│   │   ├── scan_manager.py   # Orchestration
│   │   └── scan_config.py    # Configuration
│   ├── static/               # Frontend files
│   │   ├── homepage.html     # Main page
│   │   ├── homepage.js       # Frontend logic
│   │   ├── homepage.css      # Styling
│   │   ├── resultpage.html   # Results page
│   │   ├── resultpage.js     # Results logic
│   │   └── resultpage.css    # Results styling
│   ├── utils/                # Utility functions
│   │   └── report_generator.py # PDF generation
│   ├── __init__.py           # App factory
│   ├── config.py             # Configuration
│   └── db.py                 # Database operations
│
├── instance/                 # Instance-specific files
│   └── scans.db              # SQLite database
│
├── tests/                    # Test files
│   └── test_scanner.py       # Unit tests
│
├── .venv/                    # Virtual environment
├── requirements.txt          # Python dependencies
├── run.py                    # Application entry point
└── README.md                 # This file
```

## API Endpoints

- `POST /api/scan` - Start a new scan
- `GET /api/scan/status/<scan_id>` - Get scan status
- `GET /api/scan/<scan_id>/report` - Download PDF report
- `GET /api/scans/recent` - List recent scans

## Scan Modes

### Quick Scan
- **Duration**: 3-5 seconds
- **Modules**: HTTP headers, SSL check
- **Ports**: None
- **Best for**: Fast security assessment

### Standard Scan
- **Duration**: 10-20 seconds
- **Modules**: Port scan (22 common ports), HTTP, SSL, headers
- **Ports**: 21-23, 25, 53, 80, 110, 143, 443, 465, 587, 993, 995, 1433, 1521, 3306, 3389, 5432, 5900, 6379, 8080, 8443, 27017, 27018
- **Best for**: Standard security audit

### Full Scan
- **Duration**: 60-180 seconds
- **Modules**: All ports (1-65535), HTTP, SSL, headers, CVE detection
- **Ports**: 1-65535
- **Best for**: Comprehensive security assessment

## Safety Features

- **Private IP blocking**: Prevents scanning internal networks
- **Rate limiting**: 100 requests per 60 seconds (configurable per endpoint)
- **Concurrent scan limits**: Maximum 3 scans per IP
- **Port limits**: Maximum 1000 ports per scan (Standard mode)
- **Authorization checks**: Required for Standard/Full scans

## Dependencies

- **Flask 2.3.3** - Web framework
- **Flask-Cors 4.0.0** - CORS support
- **python-nmap 0.7.1** - Port scanning (optional)
- **requests 2.31.0** - HTTP client
- **cryptography 41.0.3** - SSL/TLS operations
- **packaging 23.1** - Version comparison
- **python-dotenv 1.0.0** - Environment variables

## Database

- **Type**: SQLite
- **Location**: `instance/scans.db`
- **Auto-created**: Database is created automatically on first run


## Development Notes

- **Python Version**: Tested with Python 3.13.3
- **Database**: SQLite (no additional setup required)
- **Frontend**: Vanilla JavaScript (no build process needed)
- **Testing**: Run `pytest` in the root directory


## Contributors

- BPUPitchaya

## License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## Acknowledgments

- Built with Flask
- Uses python-nmap for port scanning capabilities
- Inspired by security assessment tools like OpenVAS and Nmap
