from sqlalchemy import func, Column, Integer, String, Enum as SQLAlchemyEnum
from datetime import datetime, timezone

from .constants import StatusEnum
from ..db import db

def now_utc() -> datetime:
    return datetime.now(timezone.utc)


class SubDomain(db.Model):
    __tablename__ = "subdomain"

    id = Column(Integer, primary_key=True)
    domain_id = Column(Integer)
    name = Column(String(255), nullable=False) 
    status = Column(SQLAlchemyEnum(StatusEnum), nullable=False)
    created_at = Column(db.DateTime, server_default=func.now())
    updated_at = Column(db.DateTime, server_default=func.now(), onupdate=func.now())
    
    def __repr__(self) -> str:
        return f"<SubDomain {self.name}>"
    
    @staticmethod
    def create(domain_id: int, name: str, status: StatusEnum) -> 'SubDomain':
        subdomain = SubDomain(domain_id=domain_id, name=name, status=status)
        db.session.add(subdomain)
        db.session.commit()
        return subdomain

    def get(_id: int) -> 'SubDomain':
        return SubDomain.query.get(_id)
    
    def update(self, status: StatusEnum) -> 'SubDomain':
        self.status = status
        db.session.commit()
        return self

    def delete(self) -> None:
        db.session.delete(self)
        db.session.commit()

class AnalysisResult(db.Model):
    __tablename__ = "analysis_result"
    
    id = Column(Integer, primary_key=True)
    domain_id = Column(Integer, nullable=True)
    subdomain_id = Column(Integer, nullable=True)
    domain_info_id = Column(Integer, nullable=True)
    method = Column(String(255), nullable=True)  
    engine_name = Column(String(255), nullable=True)  
    category = Column(String(255), nullable=True)  
    result = Column(String(255), nullable=True)  
    created_at = db.Column(db.DateTime, server_default=func.now())
    updated_at = db.Column(db.DateTime, server_default=func.now(), onupdate=func.now())
    
    def __repr__(self) -> str:
        return f"<AnalysisResult {self.engine_name}>"
    
    @staticmethod
    def create(method: str, engine_name: str, category: str, result: str) -> 'AnalysisResult':
        analysis_result = AnalysisResult(method=method, engine_name=engine_name, category=category, result=result)
        db.session.add(analysis_result)
        db.session.commit()
        return analysis_result
    
    def attach_domain(self, domain_id: int) -> None:
        self.domain_id = domain_id
        db.session.commit()
    
    def attach_subdomain(self, subdomain_id: int) -> None:
        self.subdomain_id = subdomain_id
        db.session.commit()
    
    def attach_domain_info(self, domain_info_id: int) -> None:
        self.domain_info_id = domain_info_id
        db.session.commit()
    
    def delete(self) -> None:
        db.session.delete(self)
        db.session.commit()

        