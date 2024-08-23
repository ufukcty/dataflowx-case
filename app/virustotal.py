import requests
import base64
import logging
import time

from typing import Dict
from http import HTTPStatus


# https://docs.virustotal.com/v3/reference/url-object
VIRUSTOTAL_URL_URL = "https://www.virustotal.com/api/v3/urls/{id}"

VIRUSTOTAL_SCAN_URL = "https://www.virustotal.com/api/v3/urls"

logger = logging.getLogger('VIRUSTOTAL')

class VirusTotal:
    def __init__(self, api_key: str):
        self.api_key = api_key
    
    def scan_url(self, domain: str) -> Dict:
        if not domain.lower().startswith(("http://", "https://")):
            domain = f"http://{domain}"
        
        data = {'url': domain}
        headers = {
            'x-apikey': self.api_key,
            "accept": "application/json",
            "content-type": "application/x-www-form-urlencoded"
        }
        r = requests.post(VIRUSTOTAL_SCAN_URL, headers=headers, data=data, verify=True)
        if not r.ok:
            logging.error(f"Error submitting URL {domain} to VirusTotal")
            return None
        rjson = r.json()
        link = rjson.get('data', {}).get('links', {}).get('self', '')
        if link:
            logger.info(f"URL {domain} submitted to VirusTotal: {link}")
        
        max_retries = 10
        retry_delay = 100000  
        for _ in range(max_retries):
            try:
                link_response = requests.get(link, headers={'x-apikey': self.api_key}, verify=True, timeout=10)
                link_response.raise_for_status()  
                link_json = link_response.json()

                status = link_json.get('data', {}).get('attributes', {}).get('status', '')
                if status == 'completed':
                    logger.info(f"URL {domain} analysis completed")
                    return link_json
                else:
                    logger.info(f"URL {domain} not yet analyzed by VirusTotal, status: {status}")
            except requests.RequestException as e:
                logging.error(f"Error retrieving analysis for URL {domain}: {e}")

            time.sleep(retry_delay)

        logging.error(f"URL {domain} analysis not completed in the expected time.")
        return None
        
    def get_url(self, domain: str) -> Dict:
        if not domain.lower().startswith(("http://", "https://")):
            domain = f"http://{domain}"

        url_id = base64.urlsafe_b64encode(domain.encode()).decode().strip("=")
        url = VIRUSTOTAL_URL_URL.format(id=url_id)
        
        headers = {'x-apikey': self.api_key}
        r = requests.get(url, headers=headers, verify=True)
        if r.status_code == HTTPStatus.NOT_FOUND:
            logging.error(f"Domain {domain} not found in VirusTotal")
            return None
        if not r.ok:
            logging.error(f"Error getting domain {domain} from VirusTotal")
            return None
        if b"QuotaExceededError" in r.content:
            logging.error(f"VirusTotal quota exceeded")
            return None
        return r.json()
    
    def get_subdomains_v2(self, domain: str) -> Dict:
        if domain.lower().startswith(("http://", "https://")):
            domain = domain.split("://")[1]
        
        url = f'https://www.virustotal.com/vtapi/v2/domain/report?apikey={self.api_key}&domain={domain}'
        response = requests.get(url)
    
        if response.status_code != 200:
            logging.error(f"Error getting subdomains for domain {domain} from VirusTotal")
            return None, None
    
        response = response.json()
        if response.get('response_code') == "0" or response.get('verbose_msg') == 'Domain not found':
            logging.error(f"Domain {domain} not found in VirusTotal")
            return None
        
        subdomains = []
        for subdomain in response.get('subdomains', []):
            subdomains.append(subdomain)
        
        for subdomain in response.get('domain_siblings', []):
            subdomains.append(subdomain)
        return subdomains