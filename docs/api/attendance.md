# Attendance Records API

CRUD operations for managing attendance records.

## List Records

```http
GET /attendance/records
```

### Query Parameters

| Parameter | Type | Default | Description |
|-----------|------|---------|-------------|
| `name` | string | - | Filter by player name (partial match) |
| `event` | string | - | Filter by event name (partial match) |
| `start` | date | - | Start date (YYYY-MM-DD) |
| `end` | date | - | End date (YYYY-MM-DD) |
| `page` | number | 1 | Page number |
| `limit` | number | 20 | Results per page (max: 5000) |

### Example Request

```bash
curl "https://api.itai.gg/attendance/records?name=yume&page=1&limit=10"
```

### Response

```json
{
  "results": [
    {
      "id": 1,
      "name": "y u m e",
      "event": "Wildy Wednesday",
      "date": "2025-12-01"
    },
    {
      "id": 2,
      "name": "y u m e",
      "event": "PvM Sunday",
      "date": "2025-12-03"
    }
  ],
  "total": 45,
  "page": 1,
  "limit": 10
}
```

---

## Create Record

```http
POST /attendance/records
Content-Type: application/json
```

### Request Body

```json
{
  "name": "y u m e",
  "event": "Wildy Wednesday",
  "date": "2025-12-05"
}
```

### Validation

| Field | Rules |
|-------|-------|
| `name` | Required, max 100 chars |
| `event` | Required, max 255 chars |
| `date` | Required, format YYYY-MM-DD |

### Response

```json
{
  "success": true,
  "id": 123
}
```

---

## Update Record

```http
PUT /attendance/records/:id
Content-Type: application/json
```

### Request Body

```json
{
  "name": "y u m e",
  "event": "Wildy Wednesday",
  "date": "2025-12-05"
}
```

### Response

```json
{
  "success": true
}
```

### Errors

| Status | Message |
|--------|---------|
| 400 | Invalid ID |
| 400 | All fields required |
| 404 | Record not found |

---

## Delete Record

```http
DELETE /attendance/records/:id
```

### Response

```json
{
  "success": true
}
```

### Errors

| Status | Message |
|--------|---------|
| 400 | Invalid ID |
| 404 | Record not found |

---

## Security

All inputs are sanitized:
- Strings are trimmed and length-limited
- LIKE patterns are escaped to prevent wildcard injection
- Dates are validated against YYYY-MM-DD format
- IDs are validated as positive integers

