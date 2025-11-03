"""
Simple HTTP Server for VASA Frontend
Serves static files on port 3000
"""
import http.server
import socketserver
import os
import sys

PORT = 3000
DIRECTORY = os.path.dirname(os.path.abspath(__file__))

class CustomHTTPRequestHandler(http.server.SimpleHTTPRequestHandler):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, directory=DIRECTORY, **kwargs)
    
    def do_GET(self):
        # Redirect root to homepage
        if self.path == '/':
            self.send_response(301)
            self.send_header('Location', '/public/homepage.html')
            self.end_headers()
            return
        return super().do_GET()
    
    def end_headers(self):
        # Add CORS headers to allow cross-origin requests
        self.send_header('Access-Control-Allow-Origin', '*')
        self.send_header('Access-Control-Allow-Methods', 'GET, POST, OPTIONS')
        self.send_header('Access-Control-Allow-Headers', 'Content-Type')
        self.send_header('Cache-Control', 'no-store, no-cache, must-revalidate')
        super().end_headers()
    
    def do_OPTIONS(self):
        self.send_response(200)
        self.end_headers()
    
    def log_message(self, format, *args):
        # Custom log format
        sys.stdout.write("%s - [%s] %s\n" %
                         (self.address_string(),
                          self.log_date_time_string(),
                          format % args))

def main():
    try:
        with socketserver.TCPServer(("", PORT), CustomHTTPRequestHandler) as httpd:
            print("=" * 60)
            print("VASA Frontend Server")
            print("=" * 60)
            print(f"Server running at: http://localhost:{PORT}")
            print(f"Homepage: http://localhost:{PORT}/public/homepage.html")
            print(f"Results Page: http://localhost:{PORT}/public/resultpage.html")
            print(f"Directory: {DIRECTORY}")
            print("=" * 60)
            print("Press Ctrl+C to stop the server")
            print()
            
            httpd.serve_forever()
            
    except KeyboardInterrupt:
        print("\n\nShutting down server...")
        sys.exit(0)
    except OSError as e:
        if e.errno == 10048:  # Port already in use
            print(f"\nError: Port {PORT} is already in use!")
            print("Please stop the other process or use a different port.")
            sys.exit(1)
        else:
            raise

if __name__ == "__main__":
    main()
