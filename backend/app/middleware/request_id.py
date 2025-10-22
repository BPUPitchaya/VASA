import uuid
from flask import request, g

class RequestIDMiddleware:
    """Middleware to add a unique request ID to each request."""
    
    def __init__(self, app=None):
        self.app = app
        if app is not None:
            self.init_app(app)
    
    def init_app(self, app):
        @app.before_request
        def set_request_id():
            """Set a unique request ID for each request."""
            request_id = request.headers.get('X-Request-ID') or f'req_{uuid.uuid4().hex}'
            g.request_id = request_id
            
            # Also set it in the request object for easier access
            request.request_id = request_id
