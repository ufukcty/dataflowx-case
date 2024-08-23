from celery import Celery
from celery.schedules import crontab

def make_celery(app):
    celery = Celery(
        app.import_name,
        broker=app.config['CELERY_BROKER_URL'],
        backend=app.config['result_backend']  
    )
    celery.conf.update(
        result_expires=3600,
        beat_schedule={
            'rescan-every-2-minutes': {
                'task': 'app.tasks.rescan_domains',
                'schedule': crontab(minute='*/1'),
            },
        },
    )
    celery.conf.update(app.config)

    class ContextTask(celery.Task):
        def __call__(self, *args, **kwargs):
            with app.app_context():
                return self.run(*args, **kwargs)

    celery.Task = ContextTask
    return celery
