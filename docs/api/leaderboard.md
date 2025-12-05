# Leaderboard API

Get top attendees ranked by event count.

## Get Leaderboard

```http
GET /attendance
```

### Query Parameters

| Parameter | Type | Default | Description |
|-----------|------|---------|-------------|
| `top` | number | 10 | Number of top players (max: 100) |
| `start` | date | - | Start date (YYYY-MM-DD) |
| `end` | date | - | End date (YYYY-MM-DD) |

### Example Requests

```bash
# Top 10 all time
curl "https://api.itai.gg/attendance?top=10"

# Top 25 in December 2025
curl "https://api.itai.gg/attendance?top=25&start=2025-12-01&end=2025-12-31"

# Top 5 last week
curl "https://api.itai.gg/attendance?top=5&start=2025-11-28&end=2025-12-05"
```

### Response

```json
{
  "results": [
    { "name": "y u m e", "event_count": 47 },
    { "name": "Player2", "event_count": 42 },
    { "name": "Player3", "event_count": 38 }
  ],
  "total": 3,
  "query": {
    "top": 10,
    "start": "2025-12-01",
    "end": "2025-12-31"
  }
}
```

### Use Cases

1. **Monthly Leaderboard** - Set start/end to first/last day of month
2. **All-Time Leaders** - No date filters
3. **Weekly Contest** - Rolling 7-day window
4. **Event Series** - Filter to specific date range

## Calculation

The leaderboard counts distinct events per player:

```sql
SELECT name, COUNT(*) as event_count
FROM attendance
WHERE date BETWEEN ? AND ?
GROUP BY name
ORDER BY event_count DESC
LIMIT ?
```

