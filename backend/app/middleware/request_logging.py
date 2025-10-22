import time
import logging
from flask import request, g

logger = logging.getLogger(__name__)

class RequestLoggingMiddleware:
    """Simple request logging middleware."""
    
    def __init__(self, app=None):
        self.app = app
        if app is not None:
            self.init_app(app)
    
    def init_app(self, app):
        @app.before_request
        def start_timer():
            g.start_time = time.time()
        
        @app.after_request
        def log_request(response):
            # Skip static files
            if request.path.startswith('/static/'):
                return response
                
            # Calculate duration
            duration = (time.time() - g.get('start_time', 0)) * 1000  # in ms
            
            # Log the request
            logger.info(
                f"{request.method} {request.path} -> {response.status_code} "
                f"({duration:.1f}ms)"
            )
            
            return response
