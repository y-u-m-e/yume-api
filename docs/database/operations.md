# Database Operations

Common D1 database operations.

## Wrangler CLI

### List Databases

```bash
npx wrangler d1 list
```

### Execute SQL

```bash
# Run a query
npx wrangler d1 execute yume-attendance --command="SELECT COUNT(*) FROM attendance"

# Run from file
npx wrangler d1 execute yume-attendance --file=./schema.sql
```

### Export Database

```bash
npx wrangler d1 export yume-attendance --output=backup.sql
```

### Import Database

```bash
npx wrangler d1 execute yume-attendance --file=backup.sql
```

## Common Queries

### Count All Records

```sql
SELECT COUNT(*) as total FROM attendance;
```

### Records Per Event

```sql
SELECT event, COUNT(*) as attendees
FROM attendance
GROUP BY event
ORDER BY attendees DESC;
```

### Most Active Players

```sql
SELECT name, COUNT(*) as events
FROM attendance
GROUP BY name
ORDER BY events DESC
LIMIT 10;
```

### Records in Date Range

```sql
SELECT * FROM attendance
WHERE date BETWEEN '2025-12-01' AND '2025-12-31'
ORDER BY date DESC;
```

### Find Duplicates

```sql
SELECT name, event, date, COUNT(*) as count
FROM attendance
GROUP BY name, event, date
HAVING count > 1;
```

### Delete Duplicates (Keep Lowest ID)

```sql
DELETE FROM attendance
WHERE id NOT IN (
  SELECT MIN(id)
  FROM attendance
  GROUP BY name, event, date
);
```

## Backup Best Practices

1. **Daily exports** - Schedule via CI/CD
2. **Before major changes** - Manual export
3. **Store off-site** - R2 bucket or external storage
4. **Test restores** - Verify backups work

## Performance Tips

- Use indexes for frequently queried columns
- Limit result sets with pagination
- Use prepared statements (automatic in Wrangler)
- Batch inserts when possible

