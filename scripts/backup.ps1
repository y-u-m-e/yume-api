# Yume API Database Backup Script
# Usage: .\scripts\backup.ps1

$ErrorActionPreference = "Stop"

Write-Host "💾 Yume API Database Backup" -ForegroundColor Cyan
Write-Host "============================" -ForegroundColor Cyan

# Create backups directory if it doesn't exist
$backupDir = "backups"
if (!(Test-Path $backupDir)) {
    New-Item -ItemType Directory -Path $backupDir | Out-Null
}

# Generate filename with timestamp
$timestamp = Get-Date -Format "yyyy-MM-dd_HH-mm-ss"
$filename = "backup_$timestamp.sql"
$filepath = Join-Path $backupDir $filename

Write-Host "`n📦 Exporting database..." -ForegroundColor Yellow
npx wrangler d1 export event_tracking --output=$filepath

if ($LASTEXITCODE -ne 0) {
    Write-Host "❌ Backup failed!" -ForegroundColor Red
    exit 1
}

# Get file size
$fileSize = (Get-Item $filepath).Length / 1KB
Write-Host "✅ Backup created: $filepath ($([math]::Round($fileSize, 2)) KB)" -ForegroundColor Green

# Upload to R2 (optional)
$uploadToR2 = Read-Host "`nUpload to R2 bucket? (y/N)"
if ($uploadToR2 -eq "y" -or $uploadToR2 -eq "Y") {
    Write-Host "`n☁️ Uploading to R2..." -ForegroundColor Yellow
    npx wrangler r2 object put yume-backups/db-backups/$filename --file=$filepath
    
    if ($LASTEXITCODE -eq 0) {
        Write-Host "✅ Uploaded to R2: yume-backups/db-backups/$filename" -ForegroundColor Green
    } else {
        Write-Host "⚠️ R2 upload failed (backup saved locally)" -ForegroundColor Yellow
    }
}

# Cleanup old local backups (keep last 10)
$backups = Get-ChildItem $backupDir -Filter "backup_*.sql" | Sort-Object LastWriteTime -Descending
if ($backups.Count -gt 10) {
    Write-Host "`n🧹 Cleaning up old backups..." -ForegroundColor Yellow
    $backups | Select-Object -Skip 10 | ForEach-Object {
        Remove-Item $_.FullName
        Write-Host "   Deleted: $($_.Name)" -ForegroundColor Gray
    }
}

Write-Host "`n✅ Backup complete!" -ForegroundColor Green

