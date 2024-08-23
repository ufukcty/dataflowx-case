# Dataflowx VirusTotal Case

### Demo URL : http://89.252.146.225:5000/

Dataflowx VirusTotal Case is a Docker Compose project that includes a web application and related services. This project uses Flask for the web interface, Celery for asynchronous tasks, Redis for task queue management, MySQL as the database, and Minio for object storage.

## Technologies

- **Flask**: A lightweight web framework for Python.
- **Celery**: An asynchronous task queue/job queue based on distributed message passing.
- **Redis**: An in-memory data structure store, used as a message broker for Celery.
- **MySQL**: A relational database management system.
- **Docker**: A platform to develop, ship, and run applications inside containers.
- **Docker Compose**: A tool for defining and running multi-container Docker applications.
- **SQLAlchemy**: A SQL toolkit and Object-Relational Mapping (ORM) library for Python.
- **Bootstrap**: A front-end framework for developing responsive and mobile-first websites.
- **Minio**: An open-source object storage service compatible with Amazon S3 cloud storage service.

## Run


To start the application and its services, run the following command:

```bash
docker-compose up -d --build
```

For first installation

```bash
docker-compose exec dataflowx bash
flask db init
flask db migration -m "initial commit"
flask db upgrade
```
Once the services are up and running:

- Web Application: Open your browser and navigate to http://localhost:5000 to access the web interface.
- Minio Console: Open your browser and navigate to http://localhost:9001 to access the Minio management console.
