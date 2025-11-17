from flask import Blueprint, jsonify, request, make_response
import socket
import threading
import uuid
import time

# Create the main API blueprint
bp = Blueprint('api', __name__)

# In-memory storage for scan results and active scan managers
scans = {}
scan_lock = threading.Lock()

# Registry for active scan managers (for pause/resume functionality)
SCAN_REGISTRY = {}
SCAN_REGISTRY_LOCK = threading.Lock()

def is_valid_target(target):
    """Validate if the target is a valid IP or domain"""
    try:
        socket.gethostbyname(target)
        return True
    except socket.gaierror:
        return False

# Import routes after creating the blueprint to avoid circular imports
from . import endpoints
