import socket

def test_connection():
    target = "scanme.nmap.org"
    port = 80
    
    print(f"Attempting to connect to {target}:{port}")
    
    try:
        # Resolve the hostname to an IP address
        ip = socket.gethostbyname(target)
        print(f"Resolved {target} to {ip}")
        
        # Create a socket object
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(5.0)  # 5 second timeout
        
        print(f"Attempting to connect to {ip}:{port}...")
        
        # Try to connect
        result = s.connect_ex((ip, port))
        
        if result == 0:
            print(f"Successfully connected to {target}:{port}")
            
            # Try to receive some data
            try:
                s.sendall(b"GET / HTTP/1.1\r\nHost: scanme.nmap.org\r\n\r\n")
                response = s.recv(1024)
                print("\nReceived response:")
                print(response.decode('utf-8', errors='replace')[:500])  # Print first 500 chars
            except Exception as e:
                print(f"Error during communication: {e}")
        else:
            print(f"Failed to connect to {target}:{port}. Error code: {result}")
            print("Common error codes:")
            print("  10060: Connection timed out")
            print("  10061: Connection refused")
            print("  10013: Permission denied (may require admin privileges)")
            
    except socket.gaierror as e:
        print(f"Failed to resolve hostname {target}: {e}")
    except socket.timeout:
        print(f"Connection to {target}:{port} timed out")
    except Exception as e:
        print(f"Unexpected error: {e}")
    finally:
        try:
            s.close()
        except:
            pass

if __name__ == "__main__":
    test_connection()
