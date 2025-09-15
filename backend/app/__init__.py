from flask import Flask, jsonify, request, make_response
from flask_cors import CORS, cross_origin
import socket
import sys
import json
from datetime import datetime, timezone
from .scanners.port_scanner import scan_ports, scan_ports_full
from .api.endpoints import bp as api_bp

def is_valid_target(target):
    # Simple validation for IP or domain
    try:
        socket.gethostbyname(target)
        return True
    except socket.gaierror:
        return False

app = Flask(__name__)
# Configure CORS to allow all origins and headers for development
app.config['CORS_HEADERS'] = 'Content-Type'
CORS(app, resources={
    r"/*": {
        "origins": ["http://localhost:3000", "http://127.0.0.1:3000", "http://localhost:5000"],
        "methods": ["GET", "POST", "PUT", "DELETE", "OPTIONS"],
        "allow_headers": ["Content-Type", "Authorization", "X-Requested-With"],
        "supports_credentials": True
    }
})

# Register API blueprint
app.register_blueprint(api_bp)

# Enable CORS for all routes
@app.after_request
def after_request(response):
    response.headers.add('Access-Control-Allow-Origin', '*')
    response.headers.add('Access-Control-Allow-Headers', 'Content-Type,Authorization')
    response.headers.add('Access-Control-Allow-Methods', 'GET,PUT,POST,DELETE,OPTIONS')
    return response

def handle_scan(target, scan_type='quick'):
    """Handle the scanning logic for both endpoints"""
    if not target:
        return {'error': 'Target is required'}, 400
    
    if not is_valid_target(target):
        return {'error': 'Invalid target. Please provide a valid IP address or domain name.'}, 400
    
    try:
        print(f"Starting {scan_type} scan for target: {target}", file=sys.stderr)
        
        # Use different port ranges based on scan type
        if scan_type == 'full':
            ports = '1-1024,3306,3389,5432,5900,6379,8000,8080,8443,27017'
            scan_results = scan_ports_full(target, ports=ports)
        else:
            ports = '21-23,80,443,8080,8443'
            scan_results = scan_ports(target, ports=ports)
            
        return {
            'status': 'completed',
            'target': target,
            'scan_type': 'tcp_connect_scan',
            'scan_start': datetime.now(timezone.utc).isoformat(),
            'scan_end': datetime.now(timezone.utc).isoformat(),
            'port_scan': scan_results
        }
        
    except Exception as e:
        print(f"Error during scan: {str(e)}", file=sys.stderr)
        return {'error': f'Scan failed: {str(e)}'}, 500

@app.route('/api/scan', methods=['POST', 'OPTIONS'])
@cross_origin()
def scan():
    if request.method == 'OPTIONS':
        response = make_response()
        response.headers.add('Access-Control-Allow-Origin', '*')
        response.headers.add('Access-Control-Allow-Headers', 'Content-Type,Authorization')
        response.headers.add('Access-Control-Allow-Methods', 'GET,POST,OPTIONS')
        return response
        
    data = request.get_json()
    target = data.get('target', '').strip()
    return jsonify(handle_scan(target))

@app.route('/api/scan/full', methods=['POST', 'OPTIONS'])
@cross_origin()
def full_scan():
    if request.method == 'OPTIONS':
        response = make_response()
        response.headers.add('Access-Control-Allow-Origin', '*')
        response.headers.add('Access-Control-Allow-Headers', 'Content-Type,Authorization')
        response.headers.add('Access-Control-Allow-Methods', 'GET,POST,OPTIONS')
        return response
        
    data = request.get_json()
    target = data.get('target', '').strip()
    return jsonify(handle_scan(target, 'full'))
    
    # The scan logic has been moved to handle_scan() function
    return jsonify({'error': 'This endpoint is deprecated. Use /api/scan or /api/scan/full instead'}), 400

if __name__ == '__main__':
    app.run(debug=True)
