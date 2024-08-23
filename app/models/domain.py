from sqlalchemy import func, Column, Integer, String, Enum as SQLAlchemyEnum
from sqlalchemy.exc import SQLAlchemyError
from datetime import datetime, timezone

from ..db import db
from .constants import StatusEnum

def now_utc() -> datetime:
    return datetime.now(timezone.utc)

class Domain(db.Model):
    __tablename__ = "domain"

    id = Column(Integer, primary_key=True)
    name = Column(String(255), nullable=False)
    status = Column(SQLAlchemyEnum(StatusEnum), nullable=False)
    
    created_at = db.Column(db.DateTime, server_default=func.now())
    updated_at = db.Column(db.DateTime, server_default=func.now(), onupdate=func.now())    
    
    def __repr__(self) -> str:
        return f"<Domain {self.name}>"
    
    @staticmethod
    def create(name: str, status: StatusEnum) -> "Domain":
        domain = Domain(name=name, status=status)
        db.session.add(domain)
        db.session.commit()
        return domain

    @staticmethod
    def get(_id: int) -> "Domain":
        return Domain.query.get(_id)

    @staticmethod
    def list() -> list:
        domains = Domain.query.all() 
        return domains
    
    def update(self, name: str = None, status: StatusEnum = None) -> "Domain":
        if name:
            self.name = name
        if status:
            self.status = status
        db.session.commit()
        return self

    def delete(self) -> None:
        db.session.delete(self)
        db.session.commit()

class DomainInfo(db.Model):
    __tablename__ = "domain_info"
    
    id = Column(Integer, primary_key=True)
    domain_id = Column(Integer, nullable=True)
    subdomain_id = Column(Integer, nullable=True)
    vt_id = Column(String(255), nullable=True)
    vt_link = Column(String(255), nullable=True)
    vt_reputation = Column(Integer, nullable=True)
    vt_last_final_url = Column(String(255), nullable=True)
    vt_last_submission_date = Column(Integer, nullable=True)
    vt_first_submission_date = Column(Integer, nullable=True)
    vt_last_analysis_date = Column(Integer, nullable=True)
    vt_times_submitted = Column(Integer, nullable=True)
    vt_last_analysis_stats_malicious = Column(Integer, nullable=True)
    vt_last_analysis_stats_suspicious = Column(Integer, nullable=True)
    vt_last_analysis_stats_undetected = Column(Integer, nullable=True)
    vt_last_analysis_stats_harmless = Column(Integer, nullable=True)
    vt_last_analysis_stats_timeout = Column(Integer, nullable=True)
    vt_categories = Column(String(255), nullable=True)
    
    def __repr__(self) -> str:
        return f"<DomainInfo {self.vt_id}>"
    
    @staticmethod
    def create(vt_id: str, vt_link: str, vt_reputation: int, vt_last_final_url: str, vt_last_submission_date: int, vt_first_submission_date: int, vt_last_analysis_date: int, vt_times_submitted: int, vt_last_analysis_stats_malicious: int, vt_last_analysis_stats_suspicious: int, vt_last_analysis_stats_undetected: int, vt_last_analysis_stats_harmless: int, vt_last_analysis_stats_timeout: int, vt_categories: str) -> 'DomainInfo':
        try:
            domain_info = DomainInfo(
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
            db.session.add(domain_info)
            db.session.commit()
            return domain_info
        except SQLAlchemyError as e:
            db.session.rollback()
            raise
    
    def attach_domain(self, domain_id: int) -> None:
        self.domain_id = domain_id
        db.session.commit()
        
    def attach_subdomain(self, subdomain_id: int) -> None:
        self.subdomain_id = subdomain_id
        db.session.commit()
    
    def delete(self) -> None:
        db.session.delete(self)
        db.session.commit()
        
    