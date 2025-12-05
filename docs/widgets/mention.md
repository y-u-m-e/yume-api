# Mention Widget

Automatically generates Discord @mentions based on active timezones.

## How It Works

1. User types their message
2. Widget checks current time in three regions:
   - **@US** - America/New_York (EST/EDT)
   - **@EU** - UTC
   - **@AU** - Australia/Sydney (AEDT/AEST)
3. Regions in "active hours" (8 AM - 10 PM) get their mention added
4. User copies the final message

## Usage

```html
<div id="mention-root"></div>
<script src="https://api.itai.gg/cdn/mention-widget.js"></script>
<script>
  MentionWidget.mount('#mention-root');
</script>
```

## Example Output

If it's currently:
- 2 PM in New York ✅
- 7 PM in London ✅  
- 4 AM in Sydney ❌

The output would be:
```
@US @EU Hey everyone! Event starting soon!
```

## Features

- ✅ Real-time timezone detection
- ✅ Automatic mention generation
- ✅ Live message preview
- ✅ One-click copy to clipboard
- ✅ No configuration needed

## Time Windows

| Region | Timezone | Active Hours |
|--------|----------|--------------|
| @US | America/New_York | 8 AM - 10 PM |
| @EU | UTC | 8 AM - 10 PM |
| @AU | Australia/Sydney | 8 AM - 10 PM |

## Styling

The widget uses the standard teal glassmorphism theme with:
- Dark semi-transparent background
- Teal accent colors
- Gradient button

