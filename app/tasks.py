import logging
import sys
sys.setrecursionlimit(1500)

from .virustotal import VirusTotal

from . import config
from .app import celery
from .models.domain import Domain, DomainInfo
from .models.constants import StatusEnum
from .models.subdomain import SubDomain, AnalysisResult

logger = logging.getLogger('WORKER')

@celery.task
def rescan_domains():
    try:
        reanalyze_domains()
        reanalyze_subdomains()
    except Exception as e:
        logger.error('Rescan domains error: %s', e)

@celery.task
def create_domain(domain_id):
    logging.info('Creating domain %s', domain_id)
    d = Domain.get(domain_id)
    if d is None:
        logging.error('Domain %s not found', domain_id)
        return
    d = d.update(status=StatusEnum.STATUS_INPROGRESS)
    logging.info('Domain %s status updated to in progress', domain_id)
    
    vt = VirusTotal(config.VIRUSTOTAL_API_KEY)
    logging.info("Virustotal connection established with key %s", config.VIRUSTOTAL_API_KEY)
    
    result = vt.get_url(d.name)
    logging.info("Virustotal get_url result received")
    
    ok = save_domain_info(d.id, None, result)
    logging.info('get_url Save domain info result: %s, for domain %s', ok, d.id)
    if not ok:
        r = vt.scan_url(d.name)
        logging.info("Virustotal scan_url result received")
        
        ok = save_domain_info(d.id, None, r, 'scan')
        logging.info('scan_url Save domain info result: %s, for domain %s', ok, d.id)
        if not ok:
            logging.error('Error saving domain info %s: %s', d.id, d.name)
            d = d.update(status=StatusEnum.STATUS_RESCAN)
    
    subdomains = vt.get_subdomains_v2(d.name)
    if subdomains is None:
        d = d.update(status=StatusEnum.STATUS_COMPLETED)
        return
    logging.info('Subdomains received, found %s', len(subdomains))
    
    for subdomain in subdomains:
        s = SubDomain.create(d.id, subdomain, StatusEnum.STATUS_INPROGRESS)
        result = vt.get_url(subdomain)
        logging.info('Subdomain %s %s get_url result received', s.id, subdomain)
        
        ok = save_domain_info(None, s.id, result)
        logging.info('get_url Save domain info result: %s, for subdomain %s', ok, s.id)
        if not ok:
            r = vt.scan_url(d.name)
            logging.info('Virustotal scan_url result received')
            ok = save_domain_info(None, s.id, r, 'scan')
            logging.info('scan_url Save domain info result: %s, for subdomain %s', ok, s.id)
            if not ok:
                logging.error('Error saving domain info %s: %s', s.id , subdomain)
                s.update(status=StatusEnum.STATUS_RESCAN)
                continue
        s.update(status=StatusEnum.STATUS_COMPLETED)
        logger.info('Subdomain %s %s created', s.id, subdomain)
    d.update(status=StatusEnum.STATUS_COMPLETED)
    logging.info('Domain %s created', d.id)

def save_domain_info(d_id, sd_id, result, mode='get'):
    try:
        if result is not None:
            data = result.get('data', {})
        else:
            data = {}
        if data is None:
            return False
        
        vt_id = data.get('id', '')
        vt_link = data.get('links', {}).get('self', '')
        
        if data.get('attributes', {}) is None:
            vt_reputation = 0
            vt_last_final_url = ''
            vt_last_submission_date = 0
            vt_first_submission_date = 0
            vt_last_analysis_date = 0
            vt_times_submitted = 0
            vt_last_analysis_stats_malicious = 0
            vt_last_analysis_stats_suspicious = 0
            vt_last_analysis_stats_undetected = 0
            vt_last_analysis_stats_harmless = 0
            vt_last_analysis_stats_timeout = 0
            vt_categories = ''
        else:
            attrs = data.get('attributes', {})
            vt_reputation = attrs.get('reputation', 0)
            vt_last_final_url = attrs.get('last_final_url', '')
            vt_last_submission_date = attrs.get('last_submission_date', 0)
            vt_first_submission_date = attrs.get('first_submission_date', 0)
            vt_last_analysis_date = attrs.get('last_analysis_date', 0)
            vt_times_submitted = attrs.get('times_submitted', 0)
            
            if attrs.get('last_analysis_stats', {}) is None:
                vt_last_analysis_stats_malicious = 0
                vt_last_analysis_stats_suspicious = 0
                vt_last_analysis_stats_undetected = 0
                vt_last_analysis_stats_harmless = 0
                vt_last_analysis_stats_timeout = 0
            else:
                last_analysis_stats = attrs.get('last_analysis_stats', {})
                vt_last_analysis_stats_malicious = last_analysis_stats.get('malicious', 0)
                vt_last_analysis_stats_suspicious = last_analysis_stats.get('suspicious', 0)
                vt_last_analysis_stats_undetected = last_analysis_stats.get('undetected', 0)
                vt_last_analysis_stats_harmless = last_analysis_stats.get('harmless', 0)
                vt_last_analysis_stats_timeout = last_analysis_stats.get('timeout', 0)
            
            vt_categories = ','.join(attrs.get('categories', [])) 
        
        domain_info = DomainInfo.create(
            vt_id=vt_id,
            vt_link=vt_link,
            vt_reputation=vt_reputation,
            vt_last_final_url=vt_last_final_url,
            vt_last_submission_date=vt_last_submission_date,
            vt_first_submission_date=vt_first_submission_date,
            vt_last_analysis_date=vt_last_analysis_date,
            vt_times_submitted=vt_times_submitted,
            vt_last_analysis_stats_malicious=vt_last_analysis_stats_malicious,
            vt_last_analysis_stats_suspicious=vt_last_analysis_stats_suspicious,
            vt_last_analysis_stats_undetected=vt_last_analysis_stats_undetected,
            vt_last_analysis_stats_harmless=vt_last_analysis_stats_harmless,
            vt_last_analysis_stats_timeout=vt_last_analysis_stats_timeout,
            vt_categories=vt_categories
        )
        result_key = 'last_analysis_results'
        if mode == 'get':
            if result_key not in attrs:
                return False
        else:
            result_key = 'results'
            if result_key not in attrs:
                return False
        
        analyses = attrs[result_key]
        for _, analysis in analyses.items():
            method = analysis['method'] if 'method' in analysis else ''
            engine_name = analysis['engine_name'] if 'engine_name' in analysis else ''
            category = analysis['category'] if 'category' in analysis else ''
            result = analysis['result'] if 'result' in analysis else ''
            a = AnalysisResult.create_or_find(method, engine_name, category, result)
            a.attach_domain_info(domain_info.id)
            a.attach_domain(d_id)
            a.attach_subdomain(sd_id)
        if d_id:
            domain_info.attach_domain(d_id)
        if sd_id:
            domain_info.attach_subdomain(sd_id)
        return True
    except Exception as e:
        logging.error('Error saving domain info %s', e)
        return False
    
def reanalyze_subdomains():
    try:
        vt = VirusTotal(config.VIRUSTOTAL_API_KEY)
        results = SubDomain.query.filter_by(status=StatusEnum.STATUS_RESCAN).limit(10).all()
        if len(results) == 0:
            logger.info('No subdomains STATUS_RESCAN.')
            
        results = SubDomain.query.filter_by(status=StatusEnum.STATUS_INPROGRESS).all()
        if len(results) == 0:
            logger.info('No subdomains STATUS_INPROGRESS.')
            
        domain_info = DomainInfo.query.filter(DomainInfo.vt_last_analysis_date==0).all()
        if len(domain_info) > 0:
            for d in domain_info:
                if d.domain_id is not None:
                    results.append(Domain.get(d.domain_id))
       
        logger.info("Domain info to rescan: %s", len(results))
        for subdomain in results:
            logger.info(subdomain)
            scan_url_result = vt.scan_url(subdomain.name)
            logger.info("Rescan result received")
            if scan_url_result is None:
                logger.error('Error during subdomain rescan %s', subdomain.name)
                continue
            ok = save_domain_info(None, subdomain.id, scan_url_result, 'scan')
            logging.info('Save domain info result: %s', ok)
            if ok:
                subdomain.update(status=StatusEnum.STATUS_COMPLETED)
    except Exception as e:
        logger.error('Error during subdomain rescan: %s', e)
        
def reanalyze_domains():
    try:
        vt = VirusTotal(config.VIRUSTOTAL_API_KEY)    
        domains_to_rescan = Domain.query.filter_by(status=StatusEnum.STATUS_RESCAN).all()
        if len(domains_to_rescan) == 0:
            logger.info('No domains STATUS_RESCAN.')
        
        domains_to_rescan = Domain.query.filter_by(status=StatusEnum.STATUS_INPROGRESS).all()
        if len(domains_to_rescan) == 0:
            logger.info('No domains STATUS_INPROGRESS.')
        
        domain_info = DomainInfo.query.filter(DomainInfo.vt_last_analysis_date==0).all()
        if len(domain_info) > 0:
            for d in domain_info:
                if d.domain_id is not None:
                    domains_to_rescan.append(Domain.get(d.domain_id))
        
        logger.info("Domain info to rescan: %s", len(domains_to_rescan))
        for domain in domains_to_rescan:
            r = vt.scan_url(domain.name)
            ok = save_domain_info(domain.id, None, r, 'scan')
            if ok:
                domain.update(status=StatusEnum.STATUS_COMPLETED)
    except Exception as e:
        logger.error('Error during domain rescan: %s', e)
        