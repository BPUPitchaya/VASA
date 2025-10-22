import os
from datetime import timedelta
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
    CORS_ORIGINS = os.environ.get('CORS_ORIGINS', '*').split(',')
    
    # Report settings
    REPORTS_DIR = os.path.join(os.path.dirname(__file__), '..', 'reports')
    
    # Create reports directory if it doesn't exist
    os.makedirs(REPORTS_DIR, exist_ok=True)
    
    # Logging configuration
    LOG_LEVEL = os.environ.get('LOG_LEVEL', 'INFO').upper()
    LOG_FORMAT = '%(asctime)s - %(name)s - %(levelname)s - %(message)s'
    
    # Rate limiting
    RATELIMIT_DEFAULT = '200 per day;50 per hour'
    
    # Request timeout
    REQUEST_TIMEOUT = int(os.environ.get('REQUEST_TIMEOUT', '30'))  # seconds
    
    # JWT settings (if using authentication)
    JWT_SECRET_KEY = os.environ.get('JWT_SECRET_KEY') or 'change-this-in-production'
    JWT_ACCESS_TOKEN_EXPIRES = timedelta(minutes=30)
    JWT_REFRESH_TOKEN_EXPIRES = timedelta(days=30)
    
    # Allowed origins for CORS
    ALLOWED_ORIGINS = [
        'http://localhost:3000',
        'http://127.0.0.1:3000',
        'http://localhost:5000',
        'http://127.0.0.1:5000'
    ]
    
    # Add any additional allowed origins from environment
    if os.environ.get('ALLOWED_ORIGINS'):
        ALLOWED_ORIGINS.extend(os.environ.get('ALLOWED_ORIGINS', '').split(','))
    
    # Remove duplicates
    ALLOWED_ORIGINS = list(dict.fromkeys(ALLOWED_ORIGINS))


class DevelopmentConfig(Config):
    """Development configuration."""
    DEBUG = True
    LOG_LEVEL = 'DEBUG'


class TestingConfig(Config):
    """Testing configuration."""
    TESTING = True
    DEBUG = False
    SQLALCHEMY_DATABASE_URI = 'sqlite:///:memory:'
    LOG_LEVEL = 'INFO'


class ProductionConfig(Config):
    """Production configuration."""
    DEBUG = False
    LOG_LEVEL = 'WARNING'
    
    # Force HTTPS in production
    PREFERRED_URL_SCHEME = 'https'


# Configuration dictionary
config = {
    'development': DevelopmentConfig,
    'testing': TestingConfig,
    'production': ProductionConfig,
    'default': DevelopmentConfig
}

# Set the configuration based on the FLASK_ENV environment variable
env = os.environ.get('FLASK_ENV', 'development').lower()
CurrentConfig = config.get(env, config['default'])
