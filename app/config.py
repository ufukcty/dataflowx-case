import os
from dotenv import load_dotenv

load_dotenv()

CELERY_BROKER_URL = os.getenv('CELERY_BROKER_URL', 'redis://redis:6379')
result_backend = os.getenv('result_backend', 'db+mysql+pymysql://dataflowx_user:dataflowx_password@mysql:3306/dataflowx_db')

MINIO_BUCKET = os.getenv("MINIO_BUCKET", "dataflowx")
MINIO_BASE_URL = os.getenv("MINIO_BASE_URL", "minio:9000")

MINIO_ACCESS_KEY = os.getenv("MINIO_ACCESS_KEY", "minioadmin")
MINIO_SECRET_KEY = os.getenv("MINIO_SECRET_KEY", "minioadmin123")

UPLOADS_FOLDER = os.getenv('UPLOADS_FOLDER', 'data/dataflowx')

SQLALCHEMY_DATABASE_URI = os.getenv('SQLALCHEMY_DATABASE_URI', 'mysql+pymysql://dataflowx_user:dataflowx_password@mysql:3306/dataflowx_db')
SQLALCHEMY_TRACK_MODIFICATIONS = os.getenv('SQLALCHEMY_TRACK_MODIFICATIONS', False)

VIRUSTOTAL_API_KEY = os.getenv('VIRUSTOTAL_API_KEY', 'YOUR_API')
VIRUSTOTAL_API_KEY_TEST = os.getenv('VIRUSTOTAL_API_KEY_TEST', 'YOUR API')
