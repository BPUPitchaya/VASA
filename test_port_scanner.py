import sys
import os
import time

# Add the current directory to the Python path
sys.path.append(os.path.dirname(os.path.abspath(__file__)))

from app.scanners.port_scanner import scan_ports, scan_ports_full

def test_scan(target, scan_type='quick'):
    print(f"Testing {scan_type} scan for target: {target}")
    start_time = time.time()
    
    try:
        if scan_type == 'quick':
            result = scan_ports(target, max_workers=50)
        else:
            result = scan_ports_full(target, max_workers=30)
            
        print("\nScan Results:")
        print(f"Status: {result.get('status')}")
        print(f"Target: {result.get('target')} ({result.get('ip_address')})")
        print(f"Open Ports: {len(result.get('open_ports', []))}")
        
        if 'open_ports' in result and result['open_ports']:
            print("\nOpen Ports:")
            for port in result['open_ports']:
                print(f"- Port {port['port']}/tcp: {port.get('service', 'unknown')}")
                if 'banner' in port:
                    print(f"  Banner: {port['banner']}")
        
        if 'scan_stats' in result:
            stats = result['scan_stats']
            print("\nScan Statistics:")
            for key, value in stats.items():
                print(f"{key.replace('_', ' ').title()}: {value}")
                
    except Exception as e:
        print(f"Error during scan: {str(e)}")
        import traceback
        traceback.print_exc()
    
    print(f"\nTotal time: {time.time() - start_time:.2f} seconds")

if __name__ == "__main__":
    target = input("Enter target to scan (e.g., scanme.nmap.org): ").strip()
    scan_type = input("Scan type (quick/full): ").strip().lower()
    
    if not target:
        target = "scanme.nmap.org"  # Default test target
    if scan_type not in ['quick', 'full']:
        scan_type = 'quick'
        
    test_scan(target, scan_type)
