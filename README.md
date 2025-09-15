# Vulnerability Scanner

A lightweight, Python-based Vulnerability Assessment Scanner designed to detect common security weaknesses in websites and network-facing systems.

## Features

- Port scanning with service detection
- HTTP header security analysis
- SSL/TLS configuration checking
- Web-based interface for easy interaction
- Real-time scan results
- PDF report generation

## Prerequisites

- Python 3.8+
- Node.js 16+
- npm or yarn
- nmap (for port scanning)

## Backend Setup

1. Navigate to the backend directory:
   ```bash
   cd backend
   ```

2. Create and activate a virtual environment:
   ```bash
   # On Windows
   python -m venv venv
   .\venv\Scripts\activate
   
   # On macOS/Linux
   python3 -m venv venv
   source venv/bin/activate
   ```

3. Install dependencies:
   ```bash
   pip install -r requirements.txt
   ```

4. Run the backend server:
   ```bash
   python run.py
   ```
   The backend will be available at `http://localhost:5000`

## Frontend Setup

1. Open a new terminal and navigate to the frontend directory:
   ```bash
   cd frontend
   ```

2. Install dependencies:
   ```bash
   npm install
   ```

3. Start the development server:
   ```bash
   npm start
   ```
   The frontend will be available at `http://localhost:3000`

## Usage

1. Open your browser and go to `http://localhost:3000`
2. Enter a target URL or IP address
3. Select a scan type (Quick or Full)
4. Click "Start Scan"
5. View the results in real-time

## Project Structure

```
vulnerability-scanner/
├── backend/               # Backend Flask application
│   ├── app/              # Main application package
│   │   ├── api/          # API routes
│   │   ├── core/         # Core scanning logic
│   │   ├── database/     # Database models and operations
│   │   └── utils/        # Helper functions
│   ├── tests/            # Backend tests
│   └── requirements.txt  # Python dependencies
│
├── frontend/             # Frontend React application
│   ├── public/           # Static files
│   ├── src/              # Source files
│   │   ├── components/   # React components
│   │   ├── pages/        # Page components
│   │   └── services/     # API services
│   └── package.json      # Node.js dependencies
│
└── docs/                 # Documentation
```

## Contributing

1. Fork the repository
2. Create a new branch for your feature
3. Commit your changes
4. Push to the branch
5. Create a new Pull Request

## License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## Acknowledgments

- Built with Flask and React
- Uses python-nmap for port scanning
- Inspired by OpenVAS and other security tools
