from flask import Blueprint, jsonify, request
from ..core.scanner import Scanner

scan_bp = Blueprint('scan', __name__)
scanner = Scanner()

@scan_bp.route('/scan', methods=['POST'])
def start_scan():
    data = request.json
    target = data.get('target')
    
    if not target:
        return jsonify({'error': 'Target is required'}), 400
    
    try:
        # Start the scan (this will be async in production)
        results = scanner.scan(target)
        return jsonify(results)
    except Exception as e:
        return jsonify({'error': str(e)}), 500
