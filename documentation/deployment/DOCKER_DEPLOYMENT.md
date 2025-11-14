# Docker Deployment Guide

## Overview

CyberDucky Mini SIEM is deployed using Docker Compose with three main services:
- **PostgreSQL** - Database
- **Backend** - Flask API
- **Frontend** - React application

## Prerequisites

- Docker Desktop (Windows/Mac) or Docker Engine (Linux)
- Docker Compose v2.0+
- 8GB RAM minimum
- 10GB disk space
- Ollama (for AI features)

## Quick Start

### 1. Start Ollama

```bash
# Start Ollama service
ollama serve

# Pull the model (in a new terminal)
ollama pull phi3:mini
```

### 2. Start the Application

**Windows:**
```powershell
.\start-docker.ps1
```

**Linux/Mac:**
```bash
docker-compose up -d
```

### 3. Access the Application

- **Frontend**: http://localhost:5173
- **Backend API**: http://localhost:5001
- **Database**: localhost:5432

### 4. Create an Account

1. Navigate to http://localhost:5173
2. Click "Register"
3. Create an account
4. Login

## Docker Compose Configuration

### Services

**PostgreSQL Database:**
```yaml
postgres:
  image: postgres:15
  environment:
    POSTGRES_DB: cyberducky
    POSTGRES_USER: cyberducky
    POSTGRES_PASSWORD: cyberducky123
  ports:
    - "5432:5432"
  volumes:
    - postgres_data:/var/lib/postgresql/data
```

**Backend (Flask):**
```yaml
backend:
  build: ./backend
  ports:
    - "5001:5000"
  environment:
    DATABASE_URL: postgresql://cyberducky:cyberducky123@postgres:5432/cyberducky
    JWT_SECRET_KEY: your-secret-key-change-in-production
    OLLAMA_URL: http://host.docker.internal:11434
  depends_on:
    - postgres
  volumes:
    - ./backend/uploads:/app/uploads
```

**Frontend (React):**
```yaml
frontend:
  build: ./frontend
  ports:
    - "5173:5173"
  environment:
    VITE_API_URL: http://localhost:5001
  volumes:
    - ./frontend:/app
    - /app/node_modules
```

## Environment Variables

### Backend

| Variable | Description | Default |
|----------|-------------|---------|
| `DATABASE_URL` | PostgreSQL connection string | `postgresql://...` |
| `JWT_SECRET_KEY` | Secret key for JWT tokens | `dev-secret-key` |
| `OLLAMA_URL` | Ollama API endpoint | `http://host.docker.internal:11434` |
| `FLASK_ENV` | Flask environment | `development` |

### Frontend

| Variable | Description | Default |
|----------|-------------|---------|
| `VITE_API_URL` | Backend API URL | `http://localhost:5001` |

## Volume Mounts

### Backend Uploads

```yaml
volumes:
  - ./backend/uploads:/app/uploads
```

**Purpose:** Persist uploaded log files

### Frontend Source

```yaml
volumes:
  - ./frontend:/app
  - /app/node_modules
```

**Purpose:** Hot reload during development

### PostgreSQL Data

```yaml
volumes:
  - postgres_data:/var/lib/postgresql/data
```

**Purpose:** Persist database data

## Common Commands

### Start Services

```bash
docker-compose up -d
```

### Stop Services

```bash
docker-compose down
```

### View Logs

```bash
# All services
docker-compose logs -f

# Specific service
docker-compose logs -f backend
docker-compose logs -f frontend
docker-compose logs -f postgres
```

### Restart Service

```bash
docker-compose restart backend
docker-compose restart frontend
```

### Rebuild Service

```bash
docker-compose up -d --build backend
docker-compose up -d --build frontend
```

### Access Container Shell

```bash
docker-compose exec backend bash
docker-compose exec frontend sh
docker-compose exec postgres psql -U cyberducky
```

### Database Operations

```bash
# Access PostgreSQL
docker-compose exec postgres psql -U cyberducky -d cyberducky

# Backup database
docker-compose exec postgres pg_dump -U cyberducky cyberducky > backup.sql

# Restore database
docker-compose exec -T postgres psql -U cyberducky cyberducky < backup.sql
```

## Troubleshooting

### Port Already in Use

**Error:** `Bind for 0.0.0.0:5001 failed: port is already allocated`

**Solution:**
```bash
# Find process using port
netstat -ano | findstr :5001  # Windows
lsof -i :5001                 # Linux/Mac

# Kill process or change port in docker-compose.yml
```

### Database Connection Failed

**Error:** `could not connect to server: Connection refused`

**Solution:**
```bash
# Check if postgres is running
docker-compose ps

# Restart postgres
docker-compose restart postgres

# Check logs
docker-compose logs postgres
```

### Ollama Connection Failed

**Error:** `Failed to connect to Ollama`

**Solution:**
```bash
# Check if Ollama is running
curl http://localhost:11434/api/tags

# Start Ollama
ollama serve

# Check Docker can reach host
docker-compose exec backend curl http://host.docker.internal:11434/api/tags
```

### Frontend Not Loading

**Error:** Blank page or connection refused

**Solution:**
```bash
# Check frontend logs
docker-compose logs frontend

# Rebuild frontend
docker-compose up -d --build frontend

# Check if port 5173 is accessible
curl http://localhost:5173
```

## Production Deployment

### Security Checklist

- [ ] Change `JWT_SECRET_KEY` to a strong random value
- [ ] Change database password
- [ ] Use HTTPS (add nginx reverse proxy)
- [ ] Enable CORS only for specific domains
- [ ] Set `FLASK_ENV=production`
- [ ] Enable rate limiting
- [ ] Set up database backups
- [ ] Configure log rotation
- [ ] Use secrets management (Docker secrets, Vault)

### Production docker-compose.yml

```yaml
version: '3.8'

services:
  postgres:
    image: postgres:15
    environment:
      POSTGRES_DB: cyberducky
      POSTGRES_USER: cyberducky
      POSTGRES_PASSWORD_FILE: /run/secrets/db_password
    secrets:
      - db_password
    volumes:
      - postgres_data:/var/lib/postgresql/data
    restart: always

  backend:
    build: ./backend
    environment:
      DATABASE_URL_FILE: /run/secrets/database_url
      JWT_SECRET_KEY_FILE: /run/secrets/jwt_secret
      FLASK_ENV: production
    secrets:
      - database_url
      - jwt_secret
    restart: always

  frontend:
    build: ./frontend
    restart: always

  nginx:
    image: nginx:alpine
    ports:
      - "80:80"
      - "443:443"
    volumes:
      - ./nginx.conf:/etc/nginx/nginx.conf
      - ./ssl:/etc/nginx/ssl
    depends_on:
      - backend
      - frontend
    restart: always

secrets:
  db_password:
    file: ./secrets/db_password.txt
  database_url:
    file: ./secrets/database_url.txt
  jwt_secret:
    file: ./secrets/jwt_secret.txt

volumes:
  postgres_data:
```


