from app import app

if __name__ == '__main__':
    print("Starting Vulnerability Scanner Backend...")
    print("API Endpoint: http://localhost:5000/api/scan")
    print("Press Ctrl+C to stop")
    app.run(debug=True, host='0.0.0.0', port=5000)
