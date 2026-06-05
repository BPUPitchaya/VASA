from flask import Flask, jsonify, request, make_response, send_from_directory
from flask_cors import CORS
import os

def create_app():
    app = Flask(__name__, static_folder='static')
    
    # Configuration
    app.config['SECRET_KEY'] = os.environ.get('SECRET_KEY') or 'dev-key-123'
    app.config['JSON_SORT_KEYS'] = False
    
    # Import blueprints
    from .api import bp as api_bp
    
    # Register blueprints
    app.register_blueprint(api_bp, url_prefix='/api')
    
    # Serve static files
    @app.route('/')
    def serve_home():
        return send_from_directory('static', 'homepage.html')
    
    # Health check endpoint
    @app.route('/health')
    def health_check():
        return jsonify({'status': 'ok'}), 200
    
    # Error handlers
    @app.errorhandler(404)
    def not_found(error):
        return jsonify({'error': 'Not found'}), 404
    
    @app.errorhandler(500)
    def server_error(error):
        return jsonify({'error': 'Internal server error'}), 500
    
    return app