# CyberDucky Mini SIEM - Production Deployment Guide

## Pre-Deployment Checklist

### System Requirements
- [ ] Docker 20.10+ installed
- [ ] Docker Compose 2.0+ installed
- [ ] Ollama installed and running
- [ ] 16GB RAM minimum (8GB absolute minimum)
- [ ] 50GB disk space available
- [ ] Domain name configured (optional, for SSL)

### Security Requirements
- [ ] Generated strong SECRET_KEY (64+ characters)
- [ ] Generated strong JWT_SECRET_KEY (64+ characters)
- [ ] Changed default PostgreSQL password
- [ ] Reviewed and configured CORS settings
- [ ] Firewall configured (allow only 80, 443)
- [ ] SSL/TLS certificates obtained (for HTTPS)

## Deployment Steps

### 1. Clone Repository
```bash
git clone <repository-url>
cd CyberDuckyMiniSIEM
```

### 2. Configure Environment
```bash
# Copy example environment file
cp .env.example .env

# Generate secrets
openssl rand -hex 32  # Use for SECRET_KEY
openssl rand -hex 32  # Use for JWT_SECRET_KEY

# Edit .env file with your values
nano .env
```

**Required .env variables:**
```bash
POSTGRES_USER=cyberducky_prod
POSTGRES_PASSWORD=<STRONG_PASSWORD>
POSTGRES_DB=cyberducky_siem_prod
SECRET_KEY=<GENERATED_SECRET>
JWT_SECRET_KEY=<GENERATED_JWT_SECRET>
OLLAMA_MODEL=phi3:mini
VITE_API_URL=http://your-domain.com/api
```

### 3. Pull Ollama Model
```bash
ollama serve
ollama pull phi3:mini
```

### 4. Build and Deploy
```bash
# Build images
docker-compose -f docker-compose.prod.yml build

# Start services
docker-compose -f docker-compose.prod.yml up -d

# Check status
docker-compose -f docker-compose.prod.yml ps
```

### 5. Verify Deployment
```bash
# Check backend health
curl http://localhost/api/health

# Check logs
docker-compose -f docker-compose.prod.yml logs -f backend

# Verify database
docker-compose -f docker-compose.prod.yml exec db psql -U cyberducky_prod -d cyberducky_siem_prod -c "SELECT 1;"
```

### 6. Create Admin User
```bash
# Access the frontend
# Navigate to http://your-domain.com
# Click "Register" and create first admin account
```

## Post-Deployment

### Enable HTTPS (Recommended)
```bash
# Install certbot
sudo apt-get install certbot python3-certbot-nginx

# Obtain certificate
sudo certbot --nginx -d your-domain.com

# Update nginx/nginx.conf with SSL configuration
# Restart nginx
docker-compose -f docker-compose.prod.yml restart nginx
```

### Set Up Backups
```bash
# Database backup script
#!/bin/bash
BACKUP_DIR="/backups/cyberducky"
DATE=$(date +%Y%m%d_%H%M%S)
docker-compose -f docker-compose.prod.yml exec -T db pg_dump -U cyberducky_prod cyberducky_siem_prod > "$BACKUP_DIR/db_$DATE.sql"

# Add to crontab for daily backups
0 2 * * * /path/to/backup-script.sh
```

### Monitoring
```bash
# View logs
docker-compose -f docker-compose.prod.yml logs -f

# Check resource usage
docker stats

# Monitor disk space
df -h
```

## Maintenance

### Update Application
```bash
# Pull latest changes
git pull

# Rebuild and restart
docker-compose -f docker-compose.prod.yml down
docker-compose -f docker-compose.prod.yml build
docker-compose -f docker-compose.prod.yml up -d
```

### Database Maintenance
```bash
# Vacuum database
docker-compose -f docker-compose.prod.yml exec db psql -U cyberducky_prod -d cyberducky_siem_prod -c "VACUUM ANALYZE;"

# Check database size
docker-compose -f docker-compose.prod.yml exec db psql -U cyberducky_prod -d cyberducky_siem_prod -c "SELECT pg_size_pretty(pg_database_size('cyberducky_siem_prod'));"
```

## Troubleshooting

### Backend Won't Start
```bash
# Check environment variables
docker-compose -f docker-compose.prod.yml exec backend env | grep SECRET_KEY

# Check database connection
docker-compose -f docker-compose.prod.yml logs backend | grep -i error
```

### Database Connection Errors
```bash
# Verify database is running
docker-compose -f docker-compose.prod.yml ps db

# Check database logs
docker-compose -f docker-compose.prod.yml logs db
```

### Ollama Not Responding
```bash
# Check Ollama status
docker-compose -f docker-compose.prod.yml exec ollama ollama list

# Restart Ollama
docker-compose -f docker-compose.prod.yml restart ollama
```

## Security Hardening

### Firewall Configuration
```bash
# Allow only HTTP and HTTPS
sudo ufw allow 80/tcp
sudo ufw allow 443/tcp
sudo ufw enable
```

### Regular Updates
```bash
# Update Docker images
docker-compose -f docker-compose.prod.yml pull
docker-compose -f docker-compose.prod.yml up -d
```

## Support

For issues, check:
1. Application logs: `docker-compose -f docker-compose.prod.yml logs`
2. README.md for detailed documentation
3. Backend health endpoint: `http://your-domain.com/api/health`

