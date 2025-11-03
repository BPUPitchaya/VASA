#!/usr/bin/env python3
"""
Minimal Flask App - Test Response Blocking Issue
Tests if the issue is in Flask configuration or application code
"""

from flask import Flask, jsonify
from flask_cors import CORS
import time

app = Flask(__name__)
CORS(app, resources={r"/*": {"origins": "*"}})

@app.route('/test/immediate')
def test_immediate():
    """Immediate response - no processing"""
    return jsonify({"message": "Immediate response", "timestamp": time.time()})

@app.route('/test/delayed')
def test_delayed():
    """Delayed response - 2 second processing"""
    print(f"[{time.time()}] Request received: /test/delayed")
    time.sleep(2)
    print(f"[{time.time()}] Processing complete, sending response...")
    response = jsonify({"message": "Delayed response", "timestamp": time.time()})
    print(f"[{time.time()}] Response object created")
    return response

@app.route('/test/explicit-flush')
def test_explicit_flush():
    """Test with explicit flush"""
    import sys
    print(f"[{time.time()}] Request received: /test/explicit-flush", flush=True)
    time.sleep(1)
    response = jsonify({"message": "Explicit flush", "timestamp": time.time()})
    print(f"[{time.time()}] Response ready, flushing...", flush=True)
    sys.stdout.flush()
    sys.stderr.flush()
    return response

@app.route('/test/chunked')
def test_chunked():
    """Test with chunked encoding"""
    from flask import Response
    import json
    
    def generate():
        yield json.dumps({"message": "Chunked response", "timestamp": time.time()})
    
    return Response(generate(), mimetype='application/json')

if __name__ == '__main__':
    print("=" * 60)
    print("Minimal Flask Test Server")
    print("=" * 60)
    print("\nEndpoints:")
    print("  http://localhost:5001/test/immediate")
    print("  http://localhost:5001/test/delayed")
    print("  http://localhost:5001/test/explicit-flush")
    print("  http://localhost:5001/test/chunked")
    print("\n" + "=" * 60)
    
    app.run(host='0.0.0.0', port=5001, debug=True, threaded=True)
