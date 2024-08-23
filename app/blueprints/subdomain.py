from flask import abort, render_template, redirect, url_for
from flask.blueprints import Blueprint
from datetime import datetime
import logging

from .. import db
from ..models.domain import DomainInfo
from ..models.subdomain import SubDomain, AnalysisResult

blueprint = Blueprint('subdomain', __name__)

logger = logging.getLogger('DATAFLOWX')


@blueprint.route('/list')
def list():
    subdomains = SubDomain.query.all()
    return render_template('subdomains/list.html', subdomains=subdomains)

@blueprint.route('/<_id>')
def get(_id):
    subdomain = SubDomain.get(_id)
    if not subdomain:
        abort(404)
    info = DomainInfo.query.filter(DomainInfo.subdomain_id == _id).first()
    results = AnalysisResult.query.filter(AnalysisResult.subdomain_id == _id).all()
    return render_template('subdomains/get.html',domain=subdomain, info=info, results=results)

@blueprint.route('/<_id>/delete', methods=['POST'])
def delete(_id):
    message = SubDomain.get(_id)
    if message is None:
        abort(404)
    with db.transaction():
        db.delete(message)
    
    di = DomainInfo.query.filter(DomainInfo.subdomain_id == _id).all()
    for d in di:
        d.delete()
    
    ar = AnalysisResult.query.filter(AnalysisResult.subdomain_id == _id).all()
    for a in ar:
        a.delete()

    return redirect(url_for('subdomain.list'))
