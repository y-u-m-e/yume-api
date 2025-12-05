# Yume API Deployment Script
# Usage: .\scripts\deploy.ps1 [staging|production]

param(
    [Parameter(Position=0)]
    [ValidateSet("staging", "production", "prod")]
    [string]$Environment = "production"
)

$ErrorActionPreference = "Stop"

Write-Host "🚀 Yume API Deployment Script" -ForegroundColor Cyan
Write-Host "================================" -ForegroundColor Cyan

# Normalize environment name
if ($Environment -eq "prod") { $Environment = "production" }

Write-Host "📦 Environment: $Environment" -ForegroundColor Yellow

# Run tests
Write-Host "`n🧪 Running tests..." -ForegroundColor Blue
npm test
if ($LASTEXITCODE -ne 0) {
    Write-Host "❌ Tests failed! Aborting deployment." -ForegroundColor Red
    exit 1
}
Write-Host "✅ Tests passed!" -ForegroundColor Green

# Deploy based on environment
if ($Environment -eq "staging") {
    Write-Host "`n🔄 Deploying to STAGING..." -ForegroundColor Yellow
    npx wrangler deploy --env staging
    $url = "https://api-staging.itai.gg"
} else {
    Write-Host "`n🔄 Deploying to PRODUCTION..." -ForegroundColor Yellow
    npx wrangler deploy
    $url = "https://api.itai.gg"
}

if ($LASTEXITCODE -ne 0) {
    Write-Host "❌ Deployment failed!" -ForegroundColor Red
    exit 1
}

# Health check
Write-Host "`n🏥 Running health check..." -ForegroundColor Blue
Start-Sleep -Seconds 3
try {
    $response = Invoke-RestMethod -Uri "$url/health" -TimeoutSec 10
    Write-Host "✅ Health check passed!" -ForegroundColor Green
    Write-Host "   Status: $($response.status)"
    Write-Host "   Environment: $($response.environment)"
    Write-Host "   DB Latency: $($response.checks.database.latency_ms)ms"
} catch {
    Write-Host "⚠️ Health check failed: $_" -ForegroundColor Yellow
}

Write-Host "`n✅ Deployment complete!" -ForegroundColor Green
Write-Host "🌐 URL: $url" -ForegroundColor Cyan

