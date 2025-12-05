# Database Schema

The API uses Cloudflare D1, a SQLite-compatible database.

## Tables

### attendance

Stores event attendance records.

```sql
CREATE TABLE IF NOT EXISTS attendance (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  name TEXT NOT NULL,
  event TEXT NOT NULL,
  date TEXT NOT NULL
);
```

| Column | Type | Description |
|--------|------|-------------|
| `id` | INTEGER | Auto-incrementing primary key |
| `name` | TEXT | Player name (RSN) |
| `event` | TEXT | Event name |
| `date` | TEXT | Date in YYYY-MM-DD format |

## Indexes

Consider adding indexes for common queries:

```sql
-- Speed up name searches
CREATE INDEX idx_attendance_name ON attendance(name);

-- Speed up date range queries
CREATE INDEX idx_attendance_date ON attendance(date);

-- Speed up event filtering
CREATE INDEX idx_attendance_event ON attendance(event);
```

## Sample Data

```sql
INSERT INTO attendance (name, event, date) VALUES
  ('y u m e', 'Wildy Wednesday', '2025-12-01'),
  ('Player2', 'Wildy Wednesday', '2025-12-01'),
  ('y u m e', 'PvM Sunday', '2025-12-03');
```

## D1 Configuration

In `wrangler.jsonc`:

```json
{
  "d1_databases": [
    {
      "binding": "DB",
      "database_name": "yume-attendance",
      "database_id": "your-database-id"
    }
  ]
}
```

