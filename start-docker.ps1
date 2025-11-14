# CyberDucky Mini SIEM - Docker Startup Script
# This script starts the backend and database using Docker Compose

Write-Host "========================================" -ForegroundColor Cyan
Write-Host "CyberDucky Mini SIEM - Docker Startup" -ForegroundColor Cyan
Write-Host "========================================" -ForegroundColor Cyan
Write-Host ""

# Check if Docker is running
Write-Host "Checking if Docker is running..." -ForegroundColor Yellow
$dockerRunning = docker info 2>&1 | Out-Null
if ($LASTEXITCODE -ne 0) {
    Write-Host "❌ Docker is not running!" -ForegroundColor Red
    Write-Host "Please start Docker Desktop and try again." -ForegroundColor Red
    exit 1
}
Write-Host "✅ Docker is running" -ForegroundColor Green
Write-Host ""

# Stop any existing containers
Write-Host "Stopping any existing containers..." -ForegroundColor Yellow
docker-compose down 2>&1 | Out-Null
Write-Host "✅ Cleaned up old containers" -ForegroundColor Green
Write-Host ""

# Build and start containers
Write-Host "Building and starting containers..." -ForegroundColor Yellow
Write-Host "This may take a few minutes on first run..." -ForegroundColor Yellow
Write-Host ""

docker-compose up -d --build

if ($LASTEXITCODE -eq 0) {
    Write-Host ""
    Write-Host "========================================" -ForegroundColor Green
    Write-Host "✅ SUCCESS! Services are starting..." -ForegroundColor Green
    Write-Host "========================================" -ForegroundColor Green
    Write-Host ""
    Write-Host "Services:" -ForegroundColor Cyan
    Write-Host "  🗄️  Database:  http://localhost:5432" -ForegroundColor White
    Write-Host "  🐍 Backend:   http://localhost:5000" -ForegroundColor White
    Write-Host "  ⚛️  Frontend:  http://localhost:5173" -ForegroundColor White
    Write-Host "  🤖 Ollama:    http://localhost:11434" -ForegroundColor White
    Write-Host ""
    Write-Host "Waiting for services to be ready..." -ForegroundColor Yellow
    Start-Sleep -Seconds 15
    Write-Host ""

    # Check backend health
    Write-Host "Testing backend health..." -ForegroundColor Yellow
    try {
        $response = Invoke-WebRequest -Uri "http://localhost:5000/health" -TimeoutSec 5 -ErrorAction Stop
        Write-Host "✅ Backend is healthy!" -ForegroundColor Green
    } catch {
        Write-Host "⚠️  Backend is still starting up..." -ForegroundColor Yellow
        Write-Host "   Wait a few more seconds and try: http://localhost:5000/health" -ForegroundColor Yellow
    }

    Write-Host ""
    Write-Host "========================================" -ForegroundColor Cyan
    Write-Host "Next Steps:" -ForegroundColor Cyan
    Write-Host "========================================" -ForegroundColor Cyan
    Write-Host "1. Open the app: http://localhost:5173" -ForegroundColor White
    Write-Host "2. Register an account and login" -ForegroundColor White
    Write-Host "3. Upload logs from backend/sample_data/" -ForegroundColor White
    Write-Host "4. View Overview Dashboard" -ForegroundColor White
    Write-Host ""
    Write-Host "📚 See README.md for complete documentation" -ForegroundColor White
    Write-Host "📚 See documentation/ folder for guides" -ForegroundColor White
    Write-Host ""
} else {
    Write-Host ""
    Write-Host "========================================" -ForegroundColor Red
    Write-Host "❌ ERROR: Failed to start services" -ForegroundColor Red
    Write-Host "========================================" -ForegroundColor Red
    Write-Host ""
    Write-Host "Check the logs above for errors." -ForegroundColor Yellow
    Write-Host "Common issues:" -ForegroundColor Yellow
    Write-Host "  - Port 5000 or 5432 already in use" -ForegroundColor White
    Write-Host "  - Docker Desktop not running" -ForegroundColor White
    Write-Host "  - Insufficient disk space" -ForegroundColor White
    Write-Host ""
    exit 1
}

