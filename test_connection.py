import socket
import sys

def test_port(host, port, timeout=2.0):
    """Test if a specific port is open on the given host."""
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(timeout)
        result = sock.connect_ex((host, port))
        sock.close()
        return result == 0
    except Exception as e:
        print(f"Error testing port {port}: {e}")
        return False

def main():
    if len(sys.argv) < 2:
        print("Usage: python test_connection.py <host> [port]")
        return
    
    host = sys.argv[1]
    port = int(sys.argv[2]) if len(sys.argv) > 2 else 80
    
    print(f"Testing connection to {host}:{port}")
    
    # First try to resolve the hostname
    try:
        ip = socket.gethostbyname(host)
        print(f"Resolved {host} to {ip}")
    except socket.gaierror as e:
        print(f"Could not resolve {host}: {e}")
        return
    
    # Test the port
    if test_port(host, port):
        print(f"Port {port} is OPEN")
    else:
        print(f"Port {port} is CLOSED or filtered")
    
    # Test some common ports
    common_ports = [21, 22, 23, 25, 53, 80, 110, 143, 443, 587, 993, 995, 1723, 3306, 3389, 5900, 8080, 8443]
    print("\nTesting common ports:")
    
    for port in common_ports:
        if test_port(host, port):
            print(f"Port {port}: OPEN")
        else:
            print(f"Port {port}: closed")

if __name__ == "__main__":
    main()
