from flask import abort, render_template, redirect, url_for, request
from flask.blueprints import Blueprint
from datetime import datetime
import logging

from .. import db
from ..models.domain import Domain, DomainInfo
from ..models.subdomain import SubDomain, AnalysisResult
from ..models.constants import StatusEnum

blueprint = Blueprint('domain', __name__)

logger = logging.getLogger('DATAFLOWX')

@blueprint.route('/list')
def list():
    domains = Domain.query.all() 
    subdomains = SubDomain.query.all()
    return render_template('domain/list.html', domains=domains, subdomains=subdomains)

@blueprint.route('/<_id>')
def get(_id):
    domain = Domain.get(_id)
    subdomains = SubDomain.query.filter(SubDomain.domain_id == _id).all()
    if not domain:
        abort(404)
    info = DomainInfo.query.filter(DomainInfo.domain_id == _id).first()
    results = AnalysisResult.query.filter(AnalysisResult.domain_id == _id).all()
    return render_template('domain/get.html', domain=domain, subdomains=subdomains, info=info, results=results)

@blueprint.route('/create', methods=['POST'])
def create():
    name = request.form.get('name')
    name = name.removesuffix("/")
    existing_domain = Domain.query.filter_by(name=name).first()
    
    if existing_domain:
        return redirect(url_for('domain.get', _id=existing_domain.id))
    
    domain = Domain.create(name, StatusEnum.STATUS_CREATED)
    with db.transaction():
        db.persist(domain)
    try:
        from ..tasks import create_domain
        create_domain.delay(domain.id)
    except Exception as e:
        logging.error('Error starting domain creation task %s', e)
    return render_template("index.html", _id=domain.id)

@blueprint.route('/<_id>/delete', methods=['POST'])
def delete(_id):
    message = Domain.get(_id)
    if not message:
        abort(404)
    with db.transaction():
        db.delete(message)
    
    di = DomainInfo.query.filter(DomainInfo.domain_id == _id).all()
    for d in di:
        d.delete()
    
    ar = AnalysisResult.query.filter(AnalysisResult.domain_id == _id).all()
    for a in ar:
        a.delete()

    return render_template('index.html')
