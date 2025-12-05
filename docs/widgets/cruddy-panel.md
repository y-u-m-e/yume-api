# CruDDy Panel

Full CRUD (Create, Read, Update, Delete) admin interface for attendance records.

## Features

- ✅ View, search, and filter records
- ✅ Group records by event
- ✅ Leaderboard with top attendees
- ✅ Add, edit, and delete records
- ✅ Find and remove duplicates
- ✅ Discord OAuth2 authentication
- ✅ Pagination

## Usage

```html
<div id="cruddy-root"></div>
<script src="https://api.itai.gg/cdn/cruddy-panel.js"></script>
<script>
  CruddyPanel.mount('#cruddy-root', {
    apiBase: 'https://api.itai.gg'
  });
</script>
```

## Options

| Option | Type | Default | Description |
|--------|------|---------|-------------|
| `apiBase` | string | `''` | API base URL |

## Authentication

The panel requires Discord login:

1. User clicks "Login with Discord"
2. Redirected to Discord OAuth2
3. User ID checked against whitelist
4. If authorized, full access granted
5. If not, "Unauthorized" screen shown

### Adding Authorized Users

Edit `ALLOWED_USER_IDS` in the API's `wrangler.jsonc`:

```json
{
  "vars": {
    "ALLOWED_USER_IDS": "USER_ID_1, USER_ID_2, USER_ID_3"
  }
}
```

## Tabs

### View Records

- Table view of all attendance records
- Search by name or event
- Filter by date range
- Pagination (20 per page)
- Edit/Delete buttons per row

### View by Event

- Records grouped by event name + date
- Expandable event cards
- Shows attendee count per event
- Delete entire event option
- Edit/Delete per attendee

### Leaderboard

- Top X attendees (5, 10, 25, 50, 100)
- Date range filtering
- Visual progress bars
- Medal colors for top 3:
  - 🥇 Gold (#ffd700)
  - 🥈 Silver (#c0c0c0)
  - 🥉 Bronze (#cd7f32)
- Summary stats:
  - Total events
  - Unique participants
  - Average per person

### Add Record

Form to create new records:
- Player Name
- Event Name
- Date (defaults to today)

## Duplicate Detection

The "Find Duplicates" feature:

1. Scans all records
2. Groups by name + event + date
3. Shows groups with 2+ records
4. Marks lowest ID to keep
5. Bulk delete extras

## Keyboard Shortcuts

| Key | Action |
|-----|--------|
| Enter | Submit forms |
| Escape | Close modals |

