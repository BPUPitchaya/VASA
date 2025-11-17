from app import create_app
from flask_cors import CORS
from flask import send_from_directory

app = create_app()

# Configure CORS
CORS(app, resources={
    r"/*": {
        "origins": ["http://localhost:3000", "http://127.0.0.1:3000", "http://localhost:5000"],
        "methods": ["GET", "POST", "PUT", "DELETE", "OPTIONS"],
        "allow_headers": ["Content-Type", "Authorization", "X-Requested-With"],
        "supports_credentials": True
    }
})

# Serve static files
@app.route('/')
def home():
    return send_from_directory("app/static", 'homepage.html')

if __name__ == '__main__':
    print("Starting Vulnerability Scanner Backend...")
    print("API Endpoint: http://localhost:5000/api/scan")
    print("Press Ctrl+C to stop")
    app.run(host='0.0.0.0', port=5000, debug=True)
