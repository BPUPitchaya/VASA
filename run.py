from app import app

from flask_cors import CORS
from flask import send_from_directory
from app.api.endpoints_new import bp as api

CORS(app, resources={r"/api/*": {"origins" : "*"}})
# app.register_blueprint(api)

@app.get("/")
def home():
    return send_from_directory("static", 'homepage.html')

if __name__ == '__main__':
    print("Starting Vulnerability Scanner Backend...")
    print("API Endpoint: http://localhost:5000/api/scan")
    print("Press Ctrl+C to stop")
    app.run(debug=True, host='0.0.0.0', port=5000)
