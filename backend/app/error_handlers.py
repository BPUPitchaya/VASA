from flask import jsonify, request
import logging
from datetime import datetime
from werkzeug.exceptions import HTTPException

class APIError(Exception):
    """Base class for API errors."""
    status_code = 500
    error_code = 'internal_server_error'
    
    def __init__(self, message=None, status_code=None, error_code=None, **kwargs):
        super().__init__()
        self.message = message or 'An unexpected error occurred'
        if status_code is not None:
            self.status_code = status_code
        if error_code is not None:
            self.error_code = error_code
        self.details = kwargs
        self.timestamp = datetime.utcnow().isoformat()

class ValidationError(APIError):
    """Raised when request validation fails."""
    status_code = 400
    error_code = 'validation_error'

class UnauthorizedError(APIError):
    """Raised when authentication fails."""
    status_code = 401
    error_code = 'unauthorized'

class ForbiddenError(APIError):
    """Raised when user doesn't have permission."""
    status_code = 403
    error_code = 'forbidden'

class NotFoundError(APIError):
    """Raised when a resource is not found."""
    status_code = 404
    error_code = 'not_found'

class RateLimitError(APIError):
    """Raised when rate limit is exceeded."""
    status_code = 429
    error_code = 'rate_limit_exceeded'

def register_error_handlers(app):
    """Register global error handlers for the application."""
    
    @app.errorhandler(APIError)
    def handle_api_error(error):
        """Handle API errors."""
        response = jsonify({
            'error': {
                'code': error.error_code,
                'message': error.message,
                'details': error.details,
                'timestamp': error.timestamp
            }
        })
        response.status_code = error.status_code
        return response
    
    @app.errorhandler(HTTPException)
    def handle_http_error(error):
        """Handle HTTP exceptions."""
        return jsonify({
            'error': {
                'code': error.name.lower().replace(' ', '_'),
                'message': error.description,
                'status': error.code,
                'timestamp': datetime.utcnow().isoformat()
            }
        }), error.code
    
    @app.errorhandler(Exception)
    def handle_generic_error(error):
        """Handle all other exceptions."""
        # Log the full error with traceback
        app.logger.error(
            "Unhandled exception: %s", 
            str(error),
            exc_info=True,
            extra={
                'request': {
                    'method': request.method,
                    'path': request.path,
                    'endpoint': request.endpoint,
                    'args': dict(request.args),
                    'json': request.get_json(silent=True) or {}
                }
            }
        )
        
        return jsonify({
            'error': {
                'code': 'internal_server_error',
                'message': 'An unexpected error occurred',
                'timestamp': datetime.utcnow().isoformat()
            }
        }), 500
