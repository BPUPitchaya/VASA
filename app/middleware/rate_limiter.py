import time
from collections import defaultdict, deque
from functools import wraps
from flask import request, jsonify, current_app
from typing import Callable, Dict, Any, List, Tuple
import asyncio
import threading
from concurrent.futures import ThreadPoolExecutor

class RateLimiter:
    """Implements rate limiting for API endpoints.
    
    This uses a sliding window algorithm to track requests per IP address.
    Thread-safe implementation with a thread pool for async operations.
    """
    
    def __init__(self, max_requests: int = 100, window: int = 60, max_workers: int = 10):
        """Initialize the rate limiter.
        
        Args:
            max_requests: Maximum number of requests allowed in the time window
            window: Time window in seconds
            max_workers: Maximum number of worker threads for async operations
        """
        self.max_requests = max_requests
        self.window = window
        self.requests: Dict[str, deque] = defaultdict(deque)
        self.lock = threading.Lock()
        self.executor = ThreadPoolExecutor(max_workers=max_workers)
    
    def is_rate_limited(self, ip: str) -> bool:
        """Check if an IP address has exceeded the rate limit.
        
        Args:
            ip: IP address to check
            
        Returns:
            bool: True if rate limited, False otherwise
        """
        current_time = time.time()
        
        with self.lock:
            # Remove old requests outside the window
            while self.requests[ip] and self.requests[ip][0] <= current_time - self.window:
                self.requests[ip].popleft()
            
            # Check if we've exceeded the limit
            if len(self.requests[ip]) >= self.max_requests:
                return True
            
            # Add current request
            self.requests[ip].append(current_time)
            return False
    
    def get_remaining_requests(self, ip: str) -> int:
        """Get the number of remaining requests for an IP address.
        
        Args:
            ip: IP address to check
            
        Returns:
            int: Number of remaining requests
        """
        current_time = time.time()
        
        # Remove old requests outside the window
        while self.requests[ip] and self.requests[ip][0] <= current_time - self.window:
            self.requests[ip].popleft()
        
        return max(0, self.max_requests - len(self.requests[ip]))

# Global rate limiter instance with thread pool
def get_rate_limiter():
    if not hasattr(current_app, '_rate_limiter'):
        current_app._rate_limiter = RateLimiter(
            max_requests=100,
            window=60,  # 100 requests per minute
            max_workers=10
        )
    return current_app._rate_limiter

def rate_limit(max_requests: int = 100, window: int = 60):
    """
    Decorator to limit the number of requests from a single IP address.
    Supports both sync and async routes.
    
    Args:
        max_requests: Maximum number of requests allowed within the time window
        window: Time window in seconds
    """
    def decorator(f):
        if asyncio.iscoroutinefunction(f):
            @wraps(f)
            async def async_wrapper(*args, **kwargs):
                rate_limiter = get_rate_limiter()
                ip = request.remote_addr or 'unknown'
                
                # Check rate limit
                if rate_limiter.is_rate_limited(ip):
                    response = jsonify({
                        'status': 'error',
                        'message': 'Rate limit exceeded. Please try again later.'
                    })
                    response.status_code = 429
                    reset_time = time.time() + window
                    return add_rate_limit_headers(response, max_requests, 0, reset_time)
                
                try:
                    # Call the async function
                    response = await f(*args, **kwargs)
                    
                    # Add rate limit headers
                    remaining = max(0, max_requests - len(rate_limiter.requests[ip]) - 1)
                    reset_time = time.time() + window
                    return add_rate_limit_headers(response, max_requests, remaining, reset_time)
                except Exception as e:
                    current_app.logger.error(f"Error in rate-limited async function: {str(e)}")
                    raise
            
            return async_wrapper
        else:
            @wraps(f)
            def sync_wrapper(*args, **kwargs):
                rate_limiter = get_rate_limiter()
                ip = request.remote_addr or 'unknown'
                
                # Check rate limit
                if rate_limiter.is_rate_limited(ip):
                    response = jsonify({
                        'status': 'error',
                        'message': 'Rate limit exceeded. Please try again later.'
                    })
                    response.status_code = 429
                    reset_time = time.time() + window
                    return add_rate_limit_headers(response, max_requests, 0, reset_time)
                
                try:
                    # Call the sync function
                    response = f(*args, **kwargs)
                    
                    # Add rate limit headers
                    remaining = max(0, max_requests - len(rate_limiter.requests[ip]) - 1)
                    reset_time = time.time() + window
                    return add_rate_limit_headers(response, max_requests, remaining, reset_time)
                except Exception as e:
                    current_app.logger.error(f"Error in rate-limited sync function: {str(e)}")
                    raise
            
            return sync_wrapper
    return decorator

def add_rate_limit_headers(response, max_requests: int, remaining: int, reset_time: float):
    """Add rate limit headers to the response."""
    if hasattr(response, 'is_sequence') and not response.is_sequence:
        # Streaming response
        response.headers['X-RateLimit-Limit'] = str(max_requests)
        response.headers['X-RateLimit-Remaining'] = str(remaining)
        response.headers['X-RateLimit-Reset'] = str(int(reset_time))
    elif not hasattr(response, 'headers'):
        # Handle case where response is a tuple (data, status, headers)
        if isinstance(response, tuple) and len(response) >= 2:
            data, status, *rest = response
            headers = {}
            if len(rest) == 1 and isinstance(rest[0], dict):
                headers = rest[0]
            
            headers.update({
                'X-RateLimit-Limit': str(max_requests),
                'X-RateLimit-Remaining': str(remaining),
                'X-RateLimit-Reset': str(int(reset_time))
            })
            return data, status, headers
        return response
    else:
        # Regular response with headers
        response.headers['X-RateLimit-Limit'] = str(max_requests)
        response.headers['X-RateLimit-Remaining'] = str(remaining)
        response.headers['X-RateLimit-Reset'] = str(int(reset_time))
    
    return response
