import os
from dotenv import load_dotenv

# Load environment variables from .env file
load_dotenv()

# Basic configuration
class Config:
    # Flask settings
    SECRET_KEY = os.environ.get('SECRET_KEY') or 'dev-key-change-in-production'
    DEBUG = os.environ.get('FLASK_DEBUG', 'True') == 'True'
    
    # Database settings (SQLite by default)
    SQLALCHEMY_DATABASE_URI = os.environ.get('DATABASE_URL') or 'sqlite:///vuln_scanner.db'
    SQLALCHEMY_TRACK_MODIFICATIONS = False
    
    # Scan settings
    SCAN_TIMEOUT = int(os.environ.get('SCAN_TIMEOUT', '60'))  # seconds
    
    # API settings
    API_PREFIX = '/api/v1'
    
    # Security settings
    CORS_ORIGINS = os.environ.get('CORS_ORIGINS', '*')
    
    # Report settings
    REPORTS_DIR = os.path.join(os.path.dirname(__file__), '..', 'reports')
    
    # Create reports directory if it doesn't exist
    os.makedirs(REPORTS_DIR, exist_ok=True)
