#!/usr/bin/env python3
"""
VASA Backend Diagnostic Script
Tests backend connectivity, endpoints, and CORS configuration
"""

import sys
import socket
import requests
import json
from datetime import datetime

# Configuration
BACKEND_HOST = 'localhost'
BACKEND_PORT = 5000
HEALTH_ENDPOINT = f'http://{BACKEND_HOST}:{BACKEND_PORT}/health'
API_SCANS_ENDPOINT = f'http://{BACKEND_HOST}:{BACKEND_PORT}/api/scans/recent'
FRONTEND_ORIGIN = 'http://localhost:8000'

# Color codes for terminal output
class Colors:
    GREEN = '\033[92m'
    RED = '\033[91m'
    YELLOW = '\033[93m'
    BLUE = '\033[94m'
    RESET = '\033[0m'
    BOLD = '\033[1m'

def print_header(text):
    """Print formatted header"""
    print(f"\n{Colors.BOLD}{Colors.BLUE}{'=' * 60}{Colors.RESET}")
    print(f"{Colors.BOLD}{Colors.BLUE}{text.center(60)}{Colors.RESET}")
    print(f"{Colors.BOLD}{Colors.BLUE}{'=' * 60}{Colors.RESET}\n")

def print_test(name, status, details=""):
    """Print test result"""
    icon = f"{Colors.GREEN}✅" if status else f"{Colors.RED}❌"
    status_text = "PASS" if status else "FAIL"
    print(f"{icon} {Colors.BOLD}{name}{Colors.RESET} - {status_text}{Colors.RESET}")
    if details:
        print(f"   {details}")

def print_warning(text):
    """Print warning message"""
    print(f"{Colors.YELLOW}⚠️  {text}{Colors.RESET}")

def print_info(text):
    """Print info message"""
    print(f"{Colors.BLUE}ℹ️  {text}{Colors.RESET}")

def check_port_available(port):
    """
    Check if a port is in use
    Returns: (is_in_use, details)
    """
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.settimeout(1)
    
    try:
        result = sock.connect_ex(('localhost', port))
        if result == 0:
            return True, f"Port {port} is IN USE (something is listening)"
        else:
            return False, f"Port {port} is AVAILABLE (nothing listening)"
    except socket.error as e:
        return False, f"Socket error: {e}"
    finally:
        sock.close()

def check_backend_process():
    """
    Check if backend process is running via port check
    Returns: (is_running, details)
    """
    is_in_use, details = check_port_available(BACKEND_PORT)
    
    if is_in_use:
        return True, f"Backend appears to be running on port {BACKEND_PORT}"
    else:
        return False, f"No process listening on port {BACKEND_PORT}"

def check_health_endpoint():
    """
    Test the /health endpoint
    Returns: (success, status_code, response_data, error)
    """
    try:
        response = requests.get(
            HEALTH_ENDPOINT,
            timeout=5,
            headers={'Accept': 'application/json'}
        )
        
        try:
            data = response.json()
        except:
            data = {"raw_response": response.text}
        
        return response.ok, response.status_code, data, None
        
    except requests.exceptions.ConnectionError as e:
        return False, None, None, f"Connection refused - Backend not running"
    except requests.exceptions.Timeout as e:
        return False, None, None, f"Request timeout - Backend not responding"
    except Exception as e:
        return False, None, None, f"Error: {str(e)}"

def check_api_endpoint():
    """
    Test the /api/scans endpoint
    Returns: (success, status_code, response_data, error, cors_headers)
    """
    try:
        response = requests.get(
            API_SCANS_ENDPOINT,
            timeout=5,
            headers={
                'Accept': 'application/json',
                'Origin': FRONTEND_ORIGIN
            }
        )
        
        # Extract CORS headers
        cors_headers = {
            'Access-Control-Allow-Origin': response.headers.get('Access-Control-Allow-Origin', 'NOT SET'),
            'Access-Control-Allow-Credentials': response.headers.get('Access-Control-Allow-Credentials', 'NOT SET'),
            'Access-Control-Allow-Methods': response.headers.get('Access-Control-Allow-Methods', 'NOT SET')
        }
        
        try:
            data = response.json()
        except:
            data = {"raw_response": response.text}
        
        return response.ok, response.status_code, data, None, cors_headers
        
    except requests.exceptions.ConnectionError as e:
        return False, None, None, f"Connection refused - Backend not running", {}
    except requests.exceptions.Timeout as e:
        return False, None, None, f"Request timeout - Backend not responding", {}
    except Exception as e:
        return False, None, None, f"Error: {str(e)}", {}

def check_cors_configuration(cors_headers):
    """
    Analyze CORS configuration
    Returns: (is_configured, issues)
    """
    issues = []
    
    allowed_origin = cors_headers.get('Access-Control-Allow-Origin', 'NOT SET')
    
    if allowed_origin == 'NOT SET':
        issues.append("CORS headers not present - CORS not configured")
    elif allowed_origin == '*':
        print_warning("CORS allows ALL origins (*) - Security risk!")
    elif FRONTEND_ORIGIN not in allowed_origin and allowed_origin != '*':
        issues.append(f"Frontend origin '{FRONTEND_ORIGIN}' not in allowed origins")
        issues.append(f"Current allowed: {allowed_origin}")
    
    return len(issues) == 0, issues

def analyze_root_cause(port_in_use, health_ok, api_ok):
    """
    Analyze test results to determine root cause
    Returns: (diagnosis, recommendations)
    """
    diagnosis = []
    recommendations = []
    
    # Scenario 1: Port not in use
    if not port_in_use:
        diagnosis.append("❌ Backend is NOT RUNNING")
        diagnosis.append(f"   No process is listening on port {BACKEND_PORT}")
        recommendations.append("Start backend: cd backend && python run.py")
        recommendations.append("Check for startup errors in terminal")
        return diagnosis, recommendations
    
    # Scenario 2: Port in use but health check fails
    if port_in_use and not health_ok:
        diagnosis.append("⚠️  Port is in use BUT health endpoint fails")
        diagnosis.append("   Possible causes:")
        diagnosis.append("   - Wrong application on port 5000")
        diagnosis.append("   - Backend crashed after startup")
        diagnosis.append("   - Backend bound to different interface")
        recommendations.append("Check backend terminal for errors")
        recommendations.append("Try: netstat -ano | findstr :5000  (Windows)")
        recommendations.append("Restart backend if needed")
        return diagnosis, recommendations
    
    # Scenario 3: Health OK but API fails
    if health_ok and not api_ok:
        diagnosis.append("⚠️  Backend running but API endpoint fails")
        diagnosis.append("   Possible causes:")
        diagnosis.append("   - API routes not registered")
        diagnosis.append("   - Blueprint not initialized")
        diagnosis.append("   - Endpoint path incorrect")
        recommendations.append("Check backend logs for route errors")
        recommendations.append("Verify API blueprint is registered")
        return diagnosis, recommendations
    
    # Scenario 4: Everything works
    if health_ok and api_ok:
        diagnosis.append("✅ Backend is running and responding")
        diagnosis.append("   All endpoints accessible")
        return diagnosis, recommendations
    
    # Fallback
    diagnosis.append("⚠️  Unexpected state - manual investigation needed")
    return diagnosis, recommendations

def generate_report():
    """
    Run all checks and generate comprehensive report
    """
    print_header("VASA Backend Diagnostic Report")
    print(f"Timestamp: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    print(f"Backend URL: http://{BACKEND_HOST}:{BACKEND_PORT}")
    print(f"Frontend Origin: {FRONTEND_ORIGIN}\n")
    
    # Test 1: Port Check
    print_header("Test 1: Port Availability Check")
    port_in_use, port_details = check_port_available(BACKEND_PORT)
    print_test("Port Status", port_in_use, port_details)
    
    # Test 2: Backend Process
    print_header("Test 2: Backend Process Check")
    backend_running, process_details = check_backend_process()
    print_test("Backend Process", backend_running, process_details)
    
    # Test 3: Health Endpoint
    print_header("Test 3: Health Endpoint Check")
    health_ok, health_status, health_data, health_error = check_health_endpoint()
    
    if health_ok:
        print_test("Health Endpoint", True, f"Status: {health_status}")
        print(f"   Response: {json.dumps(health_data, indent=2)}")
    else:
        print_test("Health Endpoint", False, health_error or f"Status: {health_status}")
        if health_data:
            print(f"   Data: {json.dumps(health_data, indent=2)}")
    
    # Test 4: API Endpoint
    print_header("Test 4: API Endpoint Check")
    api_ok, api_status, api_data, api_error, cors_headers = check_api_endpoint()
    
    if api_ok:
        print_test("API Endpoint", True, f"Status: {api_status}")
        print(f"   Response: {json.dumps(api_data, indent=2)}")
    else:
        print_test("API Endpoint", False, api_error or f"Status: {api_status}")
        if api_data:
            print(f"   Data: {json.dumps(api_data, indent=2)}")
    
    # Test 5: CORS Configuration
    print_header("Test 5: CORS Configuration Check")
    if cors_headers:
        print_info("CORS Headers:")
        for header, value in cors_headers.items():
            print(f"   {header}: {value}")
        
        cors_ok, cors_issues = check_cors_configuration(cors_headers)
        print_test("CORS Configuration", cors_ok)
        
        if cors_issues:
            print(f"\n{Colors.YELLOW}CORS Issues Found:{Colors.RESET}")
            for issue in cors_issues:
                print(f"   • {issue}")
    else:
        print_test("CORS Configuration", False, "No CORS headers received")
    
    # Root Cause Analysis
    print_header("Root Cause Analysis")
    diagnosis, recommendations = analyze_root_cause(port_in_use, health_ok, api_ok)
    
    print(f"{Colors.BOLD}Diagnosis:{Colors.RESET}")
    for line in diagnosis:
        print(f"  {line}")
    
    if recommendations:
        print(f"\n{Colors.BOLD}Recommendations:{Colors.RESET}")
        for i, rec in enumerate(recommendations, 1):
            print(f"  {i}. {rec}")
    
    # Summary
    print_header("Summary")
    
    total_tests = 5
    passed_tests = sum([port_in_use, backend_running, health_ok, api_ok, cors_headers != {}])
    
    print(f"Tests Passed: {passed_tests}/{total_tests}")
    
    if passed_tests == total_tests:
        print(f"\n{Colors.GREEN}{Colors.BOLD}✅ All systems operational!{Colors.RESET}")
    elif port_in_use and health_ok:
        print(f"\n{Colors.YELLOW}{Colors.BOLD}⚠️  Backend running but issues detected{Colors.RESET}")
    else:
        print(f"\n{Colors.RED}{Colors.BOLD}❌ Critical issues detected{Colors.RESET}")
    
    print("\n" + "=" * 60 + "\n")
    
    return passed_tests == total_tests

if __name__ == '__main__':
    try:
        success = generate_report()
        sys.exit(0 if success else 1)
    except KeyboardInterrupt:
        print(f"\n\n{Colors.YELLOW}Diagnostic interrupted by user{Colors.RESET}")
        sys.exit(130)
    except Exception as e:
        print(f"\n{Colors.RED}Fatal error during diagnosis: {e}{Colors.RESET}")
        sys.exit(1)
