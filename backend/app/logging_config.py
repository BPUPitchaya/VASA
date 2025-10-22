import logging

class SimpleFormatter(logging.Formatter):
    """Simple formatter that shows level and message only."""
    def format(self, record):
        return f"{record.levelname}: {record.msg}"

def configure_logging():
    """Configure application logging with simple format."""
    # Clear existing handlers
    root = logging.getLogger()
    for handler in root.handlers[:]:
        root.removeHandler(handler)
    
    # Set up console handler
    console = logging.StreamHandler()
    formatter = SimpleFormatter()
    console.setFormatter(formatter)
    
    # Configure root logger
    root.setLevel(logging.INFO)
    root.addHandler(console)
    
    # Disable noisy loggers
    for name in ['werkzeug', 'urllib3', 'asyncio', 'matplotlib', 'PIL']:
        logging.getLogger(name).setLevel(logging.WARNING)
    
    # Create console handler
    console_handler = logging.StreamHandler(sys.stdout)
    console_handler.setFormatter(formatter)
    console_handler.addFilter(RequestFilter())
    
    # Configure root logger
    root.setLevel(log_level)
    root.addHandler(console_handler)
    
    if app is not None:
        # Configure Flask app logger
        app.logger.handlers = []
        app.logger.propagate = True
        app.logger.setLevel(log_level)
        
        # Configure SQLAlchemy logging if in debug mode
        if app.debug:
            sql_logger = logging.getLogger('sqlalchemy.engine')
            sql_logger.setLevel(logging.INFO)
    else:
        # Basic config if no app provided
        logging.basicConfig(
            level=log_level,
            handlers=[console_handler]
        )
    
    # Disable other noisy loggers
    for logger_name in ['urllib3', 'asyncio', 'matplotlib']:
        logging.getLogger(logger_name).setLevel(logging.WARNING)
