import json
from . import config

from minio import Minio

minio_client = Minio(
    config.MINIO_BASE_URL,
    access_key= config.MINIO_ACCESS_KEY,
    secret_key= config.MINIO_SECRET_KEY,
    secure=False,
)

if not minio_client.bucket_exists(config.MINIO_BUCKET):
    minio_client.make_bucket(config.MINIO_BUCKET)

policy = {
    "Version": "2012-10-17",
    "Statement": [
        {
            "Effect": "Allow",
            "Principal": {"AWS": ["*"]},
            "Action": ["s3:GetObject", "s3:PutObject"],
            "Resource": [f"arn:aws:s3:::{config.MINIO_BUCKET}/*"]
        }
    ]
}

minio_client.set_bucket_policy(config.MINIO_BUCKET, json.dumps(policy))
