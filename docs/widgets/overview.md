# Widgets Overview

Yume Tools provides four embeddable widgets for OSRS clan management.

## Available Widgets

| Widget | Purpose | Auth Required |
|--------|---------|---------------|
| [Navigation Bar](navbar.md) | Site navigation | No |
| [Mention Widget](mention.md) | Auto-generate Discord mentions | No |
| [Event Parser](event-parser.md) | Parse event logs | No |
| [CruDDy Panel](cruddy-panel.md) | Manage attendance records | Yes (Discord) |

## CDN URLs

All widgets are served through the API CDN for instant cache invalidation:

```
https://api.itai.gg/cdn/nav-bar.js
https://api.itai.gg/cdn/mention-widget.js
https://api.itai.gg/cdn/event-parser-widget.js
https://api.itai.gg/cdn/cruddy-panel.js
```

## Common Pattern

All widgets follow the same mounting pattern:

```html
<!-- 1. Create a container -->
<div id="widget-root"></div>

<!-- 2. Load the script -->
<script src="https://api.itai.gg/cdn/widget-name.js"></script>

<!-- 3. Mount the widget -->
<script>
  WidgetName.mount('#widget-root', {
    // options
  });
</script>
```

## Theming

All widgets use a consistent teal glassmorphism theme:

- **Primary Color:** `#5eead4` (Teal)
- **Secondary:** `#2dd4bf` (Bright teal)
- **Font:** Outfit (body), Space Mono (navbar)
- **Style:** Glassmorphism with backdrop blur

## Carrd Integration

When using with Carrd:

1. Add an **Embed** element
2. Set type to **Code**
3. Paste the widget code
4. **Don't** check "Defer loading"

