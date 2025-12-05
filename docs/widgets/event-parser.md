# Event Parser Widget

Parses event attendance logs and formats them for Discord.

## Features

- ✅ Multiple input format support
- ✅ Auto-detects misplaced input
- ✅ Sends to Discord webhook
- ✅ Copy formatted output
- ✅ Custom modal dialogs

## Usage

```html
<div id="event-parser-root"></div>
<script src="https://api.itai.gg/cdn/event-parser-widget.js"></script>
<script>
  EventParserWidget.mount('#event-parser-root', {
    webhook: 'https://api.itai.gg/'
  });
</script>
```

## Options

| Option | Type | Default | Description |
|--------|------|---------|-------------|
| `webhook` | string | `'https://api.itai.gg/'` | Webhook relay URL |

## Supported Log Formats

### Format 1: Table with Headers

```
Name | Time | Late
PlayerOne | 60:00 | -
PlayerTwo | 45:30 | -
```

### Format 2: Code-Fenced Table

````
```
Name | Time | Late
PlayerOne | 60:00 | -
PlayerTwo | 45:30 | -
```
````

### Format 3: Group Attendance

```
Group attendance (5)
PlayerOne - 00:10
PlayerTwo - 00:05
PlayerThree - 00:03
```

### Format 4: Full Event Log

```
Event name: Wildy Wednesday
Hosted by: y u m e
Event Duration: 60:39
Present Members
------------------------------
Name | Time | Late
PlayerOne | 60:00 | -
PlayerTwo | 45:30 | -
Thanks for coming!
```

## Input Fields

| Field | Description |
|-------|-------------|
| Event Name | Name of the event (e.g., "Wildy Wednesday") |
| Event Time | When the event occurred (e.g., "7:00 PM EST") |
| Event Notes | Any additional notes |
| Event Log | Paste the attendance log here |

## Output Format

```
Event Name:
Wildy Wednesday

Event Time:
7:00 PM EST

Event Notes:
Great turnout!

Attendance:
PlayerOne, PlayerTwo, PlayerThree
```

## Error Handling

The widget detects common mistakes:

- **Log in Notes Field**: Offers to move content to correct field
- **No Names Found**: Shows helpful error message
- **Empty Output**: Prevents copying empty content

