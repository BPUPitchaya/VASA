import os
import sys
import logging
from datetime import datetime

# Configure basic logging first
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    handlers=[logging.StreamHandler()]
)

# Now import Flask and other dependencies
from flask import Flask, jsonify, g, request
from flask_cors import CORS

# Create a logger for this module
logger = logging.getLogger(__name__)

# Disable noisy loggers
for name in ['werkzeug', 'urllib3', 'asyncio', 'matplotlib', 'PIL']:
    logging.getLogger(name).setLevel(logging.WARNING)

def create_app():
    """Create and configure the Flask application."""
    # Create app first
    app = Flask(__name__)
    
    # Load configuration
    app.config.from_object('app.config.Config')
    
    # Now import other modules that might log
    from .middleware.request_id import RequestIDMiddleware
    from .error_handlers import register_error_handlers, APIError
    
    # Initialize extensions
    CORS(app, resources={
        r"/*": {
            "origins": app.config.get('ALLOWED_ORIGINS', [
                "http://localhost:3000", 
                "http://127.0.0.1:3000", 
                "http://localhost:5000"
            ]),
            "methods": ["GET", "POST", "PUT", "DELETE", "OPTIONS"],
            "allow_headers": ["Content-Type", "Authorization", "X-Requested-With"],
            "supports_credentials": True
        }
    })
    
    # Initialize middleware
    RequestIDMiddleware(app)
    
    # Initialize request logging
    from .middleware.request_logging import RequestLoggingMiddleware
    RequestLoggingMiddleware(app)
    
    # Log application startup
    logger.info("Application started successfully")
    
    # Register error handlers
    register_error_handlers(app)
    
    # Import and register blueprints
    from .api.endpoints import bp as api_bp
    app.register_blueprint(api_bp, url_prefix='/api')
    
    # Add a test route to verify error handling
    @app.route('/api/test/error')
    def test_error():
        """Test error handling."""
        raise APIError("This is a test error", status_code=400)
    
    @app.route('/api/test/validation')
    def test_validation():
        """Test validation error handling."""
        from .error_handlers import ValidationError
        raise ValidationError("Invalid input", field="test_field")
    
    @app.route('/health')
    def health_check():
        """Health check endpoint."""
        return jsonify({
            'status': 'ok',
            'timestamp': datetime.utcnow().isoformat()
        })
    
    return app

# Create the application instance
app = create_app()

if __name__ == '__main__':
    app.run(debug=os.environ.get('FLASK_DEBUG', 'true').lower() == 'true')
