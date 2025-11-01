import unittest
from unittest.mock import patch, MagicMock
from app.core.scanner import Scanner

class TestScanner(unittest.TestCase):
    def setUp(self):
        self.scanner = Scanner()
        self.test_target = "example.com"

    @patch('app.core.scanner.Scanner.port_scan')
    @patch('app.core.scanner.Scanner.check_http_headers')
    @patch('app.core.scanner.Scanner.check_ssl')
    def test_scan(self, mock_ssl, mock_http, mock_port):
        # Mock the scan methods
        mock_port.return_value = {'test': 'port_scan_result'}
        mock_http.return_value = {'test': 'http_headers_result'}
        mock_ssl.return_value = {'test': 'ssl_result'}
        
        # Run the scan
        result = self.scanner.scan(self.test_target)
        
        # Assert the results
        self.assertEqual(result['target'], self.test_target)
        self.assertEqual(result['status'], 'completed')
        self.assertEqual(result['results']['port_scan'], {'test': 'port_scan_result'})
        self.assertEqual(result['results']['http_headers'], {'test': 'http_headers_result'})
        self.assertEqual(result['results']['ssl_info'], {'test': 'ssl_result'})

    @patch('nmap.PortScanner')
    def test_port_scan(self, mock_nmap):
        # Setup mock
        mock_scanner = MagicMock()
        mock_scanner.all_hosts.return_value = ['127.0.0.1']
        mock_scanner['127.0.0.1'] = {'test': 'data'}
        mock_nmap.return_value = mock_scanner
        
        # Test the port scan
        result = self.scanner.port_scan(self.test_target)
        self.assertIn('127.0.0.1', result)
        self.assertEqual(result['127.0.0.1'], {'test': 'data'})

    @patch('requests.get')
    def test_check_http_headers(self, mock_get):
        # Setup mock response
        mock_response = MagicMock()
        mock_response.status_code = 200
        mock_response.headers = {
            'X-Content-Type-Options': 'nosniff',
            'X-Frame-Options': 'DENY',
            'Server': 'test-server'
        }
        mock_get.return_value = mock_response
        
        # Test the HTTP headers check
        result = self.scanner.check_http_headers(self.test_target)
        self.assertEqual(result['status_code'], 200)
        self.assertEqual(result['security_headers']['X-Content-Type-Options'], 'nosniff')

if __name__ == '__main__':
    unittest.main()
