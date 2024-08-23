FROM python:3.11-slim

RUN apt-get update && apt-get install -y --no-install-recommends \
    && rm -rf /var/lib/apt/lists/*

RUN mkdir /app
RUN mkdir /app/data
RUN mkdir /app/data/dataflowx
WORKDIR /app

COPY requirements.txt /app
RUN pip install -r requirements.txt
RUN pip install pymysql cryptography

COPY . /app

EXPOSE 5000

ENV FLASK_APP=app.app

CMD ["python", "run.py"]
