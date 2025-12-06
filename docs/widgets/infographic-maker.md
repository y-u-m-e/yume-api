# Infographic Maker

A powerful canvas-based tool for creating OSRS-style infographics with layers, text effects, and preset assets.

## Features

- **Layer Management** - Add, reorder, lock, hide, and delete layers
- **Drawing Tools** - Select, Rectangle, Text, Circle, Line, Image
- **OSRS Presets** - Skill icons, Prayer icons, Poll backdrop
- **Common Presets** - Dark panels, title boxes, borders
- **Text Effects** - Custom fonts (RuneScape UF), shadows, strokes
- **Layer Properties** - Opacity, rotation, blur
- **Export** - PNG export with optional transparent background
- **Paste Support** - Paste images directly from clipboard (Ctrl+V)

## Installation

Add the widget to your HTML:

```html
<div id="infographic-root"></div>
<script src="https://api.itai.gg/cdn/infographic-maker.js"></script>
<script>
  InfographicMaker.mount('#infographic-root');
</script>
```

## Canvas Sizes

| Size | Dimensions | Use Case |
|------|------------|----------|
| HD | 1280 × 720 | Standard |
| Full HD | 1920 × 1080 | High resolution |
| Discord Embed | 800 × 600 | Discord embeds |
| Discord Banner | 800 × 320 | Discord banners |
| Custom | Any | User-defined |

## Tools

### Select Tool
Click to select layers, drag to move, use corner handles to resize.

### Rectangle Tool
Click and drag to create rectangles. Properties:
- Fill color
- Stroke color and width
- Border radius

### Text Tool
Click to place text. Properties:
- Font family (RuneScape UF, Outfit, Arial, Impact, Georgia)
- Font size and color
- Text alignment (left, center, right)
- Stroke (outline) with color and width
- Shadow with color, blur, and offset

### Circle Tool
Click and drag to create circles with fill and stroke.

### Line Tool
Click and drag to create lines with stroke color and width.

### Image Tool
Upload images via the upload area or drag-and-drop.

## OSRS Assets

### Skill Icons
All 23 OSRS skill icons available via the Skills modal:
- Attack, Strength, Defence, Ranged, Prayer, Magic
- Runecraft, Construction, Hitpoints, Agility, Herblore
- Thieving, Crafting, Fletching, Slayer, Hunter
- Mining, Smithing, Fishing, Cooking, Firemaking
- Woodcutting, Farming

### Prayer Icons
21 prayer icons including:
- Protection prayers (Melee, Magic, Missiles)
- Offensive prayers (Piety, Rigour, Augury)
- Utility prayers (Preserve, Rapid Heal, etc.)

### Poll Backdrop
OSRS-style poll/menu background image.

## Layer Properties

All layers have these common properties:
- **Name** - Layer identifier
- **Position** - X and Y coordinates
- **Size** - Width and Height
- **Opacity** - 0% to 100%
- **Rotation** - -180° to +180°
- **Blur** - 0 to 20px

## Keyboard Shortcuts

| Key | Action |
|-----|--------|
| Ctrl+V | Paste image from clipboard |
| Delete | Delete selected layer (when layer selected) |

## Background Options

- **Color Picker** - Choose any background color
- **Transparent** - Check "None" for transparent PNG export

## Export

Click "Export PNG" to download the canvas as a PNG image. If transparent background is enabled, the PNG will have alpha transparency.

## Mobile Support

The widget is responsive with:
- Collapsible properties panel
- Touch-friendly controls
- Adaptive toolbar layout

## Example Usage

### Creating a Skill Comparison Infographic

1. Set canvas size to 1280×720
2. Add a Dark Panel preset as background
3. Click "Skills" and add relevant skill icons
4. Use Text tool to add labels with RuneScape font
5. Enable text shadow for better readability
6. Export as PNG

### Creating a Discord Banner

1. Set canvas size to 800×320 (Discord Banner)
2. Set transparent background
3. Add text with stroke and shadow
4. Add skill icons or prayer icons
5. Export as PNG with transparency

