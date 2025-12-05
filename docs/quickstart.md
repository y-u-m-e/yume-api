# Quick Start

Get up and running with Yume Tools in under 5 minutes.

## Using the Widgets

### 1. Add to Your Website

Copy and paste this code into your HTML (or Carrd embed):

```html
<!-- Navigation Bar -->
<div id="nav-bar-root"></div>
<script src="https://api.itai.gg/cdn/nav-bar.js"></script>
<script>
  NavBar.mount('#nav-bar-root', {
    baseUrl: 'https://your-site.com',
    sticky: true
  });
</script>
```

### 2. Available Widgets

| Widget | Script URL |
|--------|-----------|
| Navigation Bar | `https://api.itai.gg/cdn/nav-bar.js` |
| Mention Widget | `https://api.itai.gg/cdn/mention-widget.js` |
| Event Parser | `https://api.itai.gg/cdn/event-parser-widget.js` |
| CruDDy Panel | `https://api.itai.gg/cdn/cruddy-panel.js` |

### 3. That's It!

The widgets are self-contained with their own styles. No additional CSS needed.

## Using the API

### Check API Health

```bash
curl https://api.itai.gg/health
```

### Get Attendance Leaderboard

```bash
curl "https://api.itai.gg/attendance?top=10"
```

### Get Records

```bash
curl "https://api.itai.gg/attendance/records?limit=20"
```

## Next Steps

- [Widget Documentation](widgets/overview.md) - Detailed widget guides
- [API Reference](api/overview.md) - Full API documentation
- [Local Development](development/setup.md) - Set up your own instance

