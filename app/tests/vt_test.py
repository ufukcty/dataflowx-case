import unittest
from ..virustotal import VirusTotal

class TestVirusTotal(unittest.TestCase):
    success_test_url = 'example.com.tr'
    
    def setUp(self):
        from ..config import VIRUSTOTAL_API_KEY_TEST
        self.vt = VirusTotal(VIRUSTOTAL_API_KEY_TEST)
    
    def test_scan_url(self):
        result = self.vt.scan_url(self.success_test_url)
        self.assertIsNotNone(result)
        self.assertIn('data', result)
        data = result['data']
        self.assertIn('id', data)
        self.assertIn('type', data)
        self.assertIn('links', data)
        
        links = data['links']
        self.assertIn('self', links)
     
    def test_get_url(self):
        result = self.vt.get_url(self.success_test_url)
        self.assertIsNotNone(result)
        self.assertIn('data', result)
        data = result['data']
        self.assertIn('id', data)
        self.assertIn('type', data)
        self.assertIn('links', data)
        
        links = data['links']
        self.assertIn('self', links)
        self.assertIn('attributes', data)
        
        attrs = data['attributes']
        self.assertIn('reputation', attrs)
        self.assertIn('tags', attrs)
        self.assertIn('last_final_url', attrs)
        self.assertIn('last_analysis_stats', attrs)
        self.assertGreaterEqual(len(attrs['last_analysis_stats']), 1)
        
        self.assertEqual(attrs['last_final_url'], "http://"+self.success_test_url+"/")
    
    def test_get_subdomains_v2(self):
        result = self.vt.get_subdomains_v2(self.success_test_url)
        self.assertIsNotNone(result)
        self.assertEqual(len(result), 2)
        
        