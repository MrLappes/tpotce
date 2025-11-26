# cxc-honeypod

Small proxy service for streaming scripted replies.

## Prerequisites

- Python 3.11+
- Git (optional)
- Docker and Docker Compose (if you plan to run in containers)

## Quick start — run locally

1. Create and activate a virtual environment:

   ```bash
   python -m venv .venv
   source .venv/bin/activate
   ```

2. Install dependencies:

   ```bash
   pip install --upgrade pip
   pip install -r requirements.txt
   ```

3. Create a `.env` file in the project root with at least the following values:

   ```env
   BACKEND_URL=http://localhost:8000
   JWT_SECRET=your-secret-key
   ALGORITHM=HS256
   PORT=8001
   ```

4. Run the application:

   ```bash
   python main.py
   ```

   The server listens on the port defined in `PORT` (default 8001).

Notes:
- The proxy expects the backend service (configured by `BACKEND_URL`) to implement the endpoints used in this project (for example `/sessions/stream/reply`).
- For development you can run the backend locally or point `BACKEND_URL` to a running instance.

## Run with Docker

Build and run the container manually:

1. Build the image:

   ```bash
   docker build -t honeypod-proxy .
   ```

2. Run the container (using your .env file):

   ```bash
   docker run --env-file .env -p 8001:8001 honeypod-proxy
   ```

The container will run the same `main.py` application and expose the port configured in `PORT`.

## Run with Docker Compose

A `docker-compose.yml` is included. To start the service with compose:

   ```bash
   docker-compose up --build
   ```

Docker Compose will read the `.env` file in the project root for environment variables. Make sure `BACKEND_URL` and `JWT_SECRET` are set there.

## Environment variables

The main variables used by the application are:

- BACKEND_URL — base URL of the backend service the proxy forwards to (required)
- JWT_SECRET — secret used to validate JWTs from clients (required for auth)
- ALGORITHM — JWT algorithm (default: HS256)
- HOST — host to bind (default: 0.0.0.0)
- PORT — port to listen on (default: 8001)

## Troubleshooting

- If you see an `Invalid port` error when proxying, ensure `BACKEND_URL` includes the protocol and does not accidentally concatenate paths (for example `http://localhost:8000` — do not append paths without a `/`).
- Check logs for exceptions from the backend and ensure the backend endpoint `/sessions/stream/reply` is available.