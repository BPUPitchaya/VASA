import os
import sys
import logging

# Disable Flask's debug mode by default
os.environ['FLASK_DEBUG'] = 'false'

# Configure basic logging first
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    handlers=[logging.StreamHandler()]
)

# Now import the app
from app import create_app, logger

# Create the application instance
app = create_app()

if __name__ == '__main__':
    # Get port from environment variable or use default 5000
    port = int(os.environ.get('PORT', 5000))
    
    # Print startup message
    print("\n" + "=" * 50)
    print("Starting Vulnerability Scanner Backend")
    print("=" * 50)
    print(f"API Endpoint: http://localhost:{port}/api/scan")
    print("Press Ctrl+C to stop\n")
    
    # Run the application
    from werkzeug.serving import run_simple
    run_simple(
        hostname='0.0.0.0',
        port=port,
        application=app,
        use_reloader=False,
        use_debugger=False
    )
