# Database Backups

Strategies for backing up the D1 database.

## Manual Backup

```bash
npx wrangler d1 export yume-attendance --output=backup-$(date +%Y%m%d).sql
```

## Automated Backups (GitHub Actions)

`.github/workflows/backup.yml`:

```yaml
name: Database Backup

on:
  schedule:
    - cron: '0 2 * * *'  # Daily at 2 AM UTC
  workflow_dispatch:  # Manual trigger

jobs:
  backup:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      
      - name: Setup Node
        uses: actions/setup-node@v4
        with:
          node-version: '20'
          
      - name: Install Wrangler
        run: npm install -g wrangler
        
      - name: Export Database
        env:
          CLOUDFLARE_API_TOKEN: ${{ secrets.CLOUDFLARE_API_TOKEN }}
          CLOUDFLARE_ACCOUNT_ID: ${{ secrets.CLOUDFLARE_ACCOUNT_ID }}
        run: |
          wrangler d1 export yume-attendance --output=backup.sql
          
      - name: Upload Backup Artifact
        uses: actions/upload-artifact@v4
        with:
          name: db-backup-${{ github.run_id }}
          path: backup.sql
          retention-days: 30
```

## Backup to R2 (Optional)

If R2 is enabled, backups can be stored there:

```bash
# Export and upload
wrangler d1 export yume-attendance --output=backup.sql
wrangler r2 object put yume-backups/backup-$(date +%Y%m%d).sql --file=backup.sql
```

## Restore from Backup

```bash
# Download backup (if from R2)
wrangler r2 object get yume-backups/backup-20251205.sql --file=restore.sql

# Execute restore
wrangler d1 execute yume-attendance --file=restore.sql
```

## Backup Schedule

| Frequency | Retention | Location |
|-----------|-----------|----------|
| Daily | 30 days | GitHub Artifacts |
| Weekly | 90 days | R2 Bucket (optional) |
| Before major changes | Indefinite | Local + R2 |

## Best Practices

1. **Test restores** - A backup is only good if you can restore it
2. **Multiple locations** - Don't rely on one storage
3. **Encrypt sensitive data** - If backing up externally
4. **Document process** - Know how to restore quickly

