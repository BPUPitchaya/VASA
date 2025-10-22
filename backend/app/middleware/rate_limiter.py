import time
from collections import defaultdict, deque
from functools import wraps
from flask import request, jsonify, current_app, make_response
from typing import Callable, Dict, Any, List, Tuple, Optional
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
        self.requests: Dict[str, Dict[str, deque]] = defaultdict(lambda: defaultdict(deque))
        self.lock = threading.Lock()
        self.executor = ThreadPoolExecutor(max_workers=max_workers)
    
    def is_rate_limited(self, key: str, max_req: Optional[int] = None, win: Optional[int] = None) -> bool:
        """
        Check if a request should be rate limited.
        
        Args:
            key: Unique key for the rate limit (e.g., 'endpoint:ip')
            max_req: Override for max_requests
            win: Override for window
            
        Returns:
            bool: True if rate limited, False otherwise
        """
        max_requests = max_req if max_req is not None else self.max_requests
        window = win if win is not None else self.window
        current_time = time.time()
        
        with self.lock:
            # Remove old requests outside the window
            while (self.requests[key]['timestamps'] and 
                   self.requests[key]['timestamps'][0] <= current_time - window):
                self.requests[key]['timestamps'].popleft()
            
            # Check if we've exceeded the limit
            if len(self.requests[key]['timestamps']) >= max_requests:
                return True
            
            # Add current request
            self.requests[key]['timestamps'].append(current_time)
            return False
    
    def get_remaining_requests(self, key: str, max_req: Optional[int] = None, win: Optional[int] = None) -> int:
        """
        Get the number of remaining requests for a key.
        
        Args:
            key: Unique key for the rate limit
            max_req: Override for max_requests
            win: Override for window
            
        Returns:
            int: Number of remaining requests
        """
        max_requests = max_req if max_req is not None else self.max_requests
        window = win if win is not None else self.window
        current_time = time.time()
        
        with self.lock:
            # Remove old requests outside the window
            while (self.requests[key]['timestamps'] and 
                   self.requests[key]['timestamps'][0] <= current_time - window):
                self.requests[key]['timestamps'].popleft()
            
            return max(0, max_requests - len(self.requests[key]['timestamps']))

# Global rate limiter instance with thread pool
def get_rate_limiter():
    if not hasattr(current_app, '_rate_limiter'):
        # Create a new rate limiter with default values (these will be overridden by decorators)
        current_app._rate_limiter = RateLimiter(
            max_requests=100,  # Default, but will be overridden by decorators
            window=60,
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
                # Use the same IP resolution as in endpoints.py
                if 'X-Forwarded-For' in request.headers:
                    ip = request.headers['X-Forwarded-For'].split(',')[0].strip()
                else:
                    ip = request.remote_addr or 'unknown'
                
                # Create a unique key per endpoint and IP
                endpoint_key = f"{request.endpoint}:{ip}"
                
                # Check rate limit for this specific endpoint and IP
                if rate_limiter.is_rate_limited(endpoint_key, max_requests, window):
                    remaining = rate_limiter.get_remaining_requests(endpoint_key, max_requests, window)
                    reset_time = int(time.time() + window)
                    
                    response = jsonify({
                        'status': 'error',
                        'message': f'Rate limit exceeded. Please try again in {window} seconds.',
                        'error': 'rate_limit_exceeded',
                        'max_requests': max_requests,
                        'window': window
                    })
                    response.status_code = 429
                    response.headers['X-RateLimit-Limit'] = str(max_requests)
                    response.headers['X-RateLimit-Remaining'] = '0'
                    response.headers['X-RateLimit-Reset'] = str(reset_time)
                    return response
                
                try:
                    # Call the async function
                    response = await f(*args, **kwargs)
                    
                    # Add rate limit headers to successful responses
                    if isinstance(response, tuple) and len(response) == 2 and isinstance(response[1], int):
                        # Handle (response, status_code) tuples
                        resp, status = response
                        resp = make_response(resp, status)
                    else:
                        resp = make_response(response)
                    
                    remaining = rate_limiter.get_remaining_requests(endpoint_key, max_requests, window)
                    reset_time = int(time.time() + window)
                    
                    resp.headers['X-RateLimit-Limit'] = str(max_requests)
                    resp.headers['X-RateLimit-Remaining'] = str(remaining)
                    resp.headers['X-RateLimit-Reset'] = str(reset_time)
                    
                    return resp
                except Exception as e:
                    current_app.logger.error(f"Error in rate-limited async function: {str(e)}")
                    raise
            return async_wrapper
        else:
            @wraps(f)
            def sync_wrapper(*args, **kwargs):
                rate_limiter = get_rate_limiter()
                # Use the same IP resolution as in endpoints.py
                if 'X-Forwarded-For' in request.headers:
                    ip = request.headers['X-Forwarded-For'].split(',')[0].strip()
                else:
                    ip = request.remote_addr or 'unknown'
                
                # Create a unique key per endpoint and IP
                endpoint_key = f"{request.endpoint}:{ip}"
                
                # Check rate limit for this specific endpoint and IP
                if rate_limiter.is_rate_limited(endpoint_key, max_requests, window):
                    remaining = rate_limiter.get_remaining_requests(endpoint_key, max_requests, window)
                    reset_time = int(time.time() + window)
                    
                    response = jsonify({
                        'status': 'error',
                        'message': f'Rate limit exceeded. Please try again in {window} seconds.',
                        'error': 'rate_limit_exceeded',
                        'max_requests': max_requests,
                        'window': window
                    })
                    response.status_code = 429
                    response.headers['X-RateLimit-Limit'] = str(max_requests)
                    response.headers['X-RateLimit-Remaining'] = '0'
                    response.headers['X-RateLimit-Reset'] = str(reset_time)
                    return response
                
                try:
                    # Call the sync function
                    response = f(*args, **kwargs)
                    
                    # Add rate limit headers to successful responses
                    if isinstance(response, tuple) and len(response) == 2 and isinstance(response[1], int):
                        # Handle (response, status_code) tuples
                        resp, status = response
                        resp = make_response(resp, status)
                    else:
                        resp = make_response(response)
                    
                    remaining = rate_limiter.get_remaining_requests(endpoint_key, max_requests, window)
                    reset_time = int(time.time() + window)
                    
                    resp.headers['X-RateLimit-Limit'] = str(max_requests)
                    resp.headers['X-RateLimit-Remaining'] = str(remaining)
                    resp.headers['X-RateLimit-Reset'] = str(reset_time)
                    
                    return resp
                except Exception as e:
                    current_app.logger.error(f"Error in rate-limited sync function: {str(e)}")
                    raise
            
            return sync_wrapper
    return decorator
