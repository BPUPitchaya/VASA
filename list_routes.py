from app import app

# List all registered routes
print("\nRegistered Routes:")
print("-" * 50)
for rule in app.url_map.iter_rules():
    methods = ','.join(rule.methods)
    print(f"{rule.endpoint}: {rule.rule} [{methods}]")

# Test CVE endpoint directly
print("\nTesting CVE endpoint...")
try:
    with app.test_client() as c:
        # Test with banner
        response = c.post('/api/scan/cve', 
                         json={"banner": "Apache/2.4.49 (Unix)"},
                         headers={"Content-Type": "application/json"})
        print(f"\nResponse from /api/scan/cve (banner): {response.status_code}")
        print(response.get_json())
        
        # Test with service and version
        response = c.post('/api/scan/cve',
                        json={"service": "apache", "version": "2.4.49"},
                        headers={"Content-Type": "application/json"})
        print(f"\nResponse from /api/scan/cve (service+version): {response.status_code}")
        print(response.get_json())
except Exception as e:
    print(f"Error testing endpoint: {str(e)}")
