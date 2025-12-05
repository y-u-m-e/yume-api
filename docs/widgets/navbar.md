# Navigation Bar

A minimal, elegant navigation bar with animated underline effects.

## Preview

```
HOME    MENTIONS    EVENT LOGS    CRUDDY PANEL
────                                          
```

## Features

- ✅ Minimal underline style
- ✅ Uppercase monospace typography
- ✅ Animated hover effects
- ✅ Active state highlighting
- ✅ Responsive (icons only on mobile)
- ✅ Hash-based navigation

## Usage

```html
<div id="nav-bar-root"></div>
<script src="https://api.itai.gg/cdn/nav-bar.js"></script>
<script>
  NavBar.mount('#nav-bar-root', {
    baseUrl: 'https://yumes-tools.itai.gg',
    sticky: true
  });
</script>
```

## Options

| Option | Type | Default | Description |
|--------|------|---------|-------------|
| `baseUrl` | string | `''` | Base URL for navigation links |
| `sticky` | boolean | `true` | Make navbar sticky on scroll |

## Navigation Items

The navbar includes these links:

| Label | Hash | Target Section |
|-------|------|----------------|
| Home | `#home` | Top of page |
| Mentions | `#msg-maker` | Mention widget section |
| Event Logs | `#log-maker` | Event parser section |
| Cruddy Panel | `#cruddy-panel` | Admin panel section |

## Styling

- **Font:** Space Mono (monospace)
- **Text:** Uppercase with letter-spacing
- **Colors:** 
  - Default: `rgba(255, 255, 255, 0.5)`
  - Hover: `rgba(255, 255, 255, 0.9)`
  - Active: `#5eead4` (teal)
- **Underline:** Animated width transition

## Responsive Behavior

On screens smaller than 600px:
- Text labels are hidden
- Only icons are shown
- Gap between items reduces

