import logging
from flask import Flask

from . import config
from . import db
from .blueprints import index, domain, subdomain
from .celery_utils import make_celery

logger = logging.Logger('DATAFLOWX')
app = Flask(__name__)
app.config.update(
    SQLALCHEMY_TRACK_MODIFICATIONS=False,
    SQLALCHEMY_DATABASE_URI=config.SQLALCHEMY_DATABASE_URI,
    CELERY_BROKER_URL=config.CELERY_BROKER_URL,
    result_backend=config.result_backend,
)

db.init_app(app)

app.register_blueprint(index.blueprint)
app.register_blueprint(domain.blueprint, url_prefix='/domain')
app.register_blueprint(subdomain.blueprint, url_prefix='/subdomain')

celery = make_celery(app)