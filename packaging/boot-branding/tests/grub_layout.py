#!/usr/bin/env python3
"""Geometry regression model, not a native GRUB renderer or boot test.

GRUB 2.12 gui_image returns RAW bitmap dimensions as its minimum. gui_canvas
raises each requested dimension to that minimum, then clamps each axis to the
viewport independently. The original 1100x550 image therefore distorted at low
resolutions despite a requested 320x160 rectangle. Keep the original untouched
and use the independently validated 320x160 proportional copy for this widget.
"""
from pathlib import Path
import re


def dimension(spec, extent):
    absolute = fraction = 0
    tokens = re.findall(r"([+-]?\d+)(%?)", spec)
    if "".join(number + suffix for number, suffix in tokens) != spec:
        raise ValueError("ANDEIVA_BOOT_GRUB_DIMENSION")
    for number, suffix in tokens:
        value = int(number)
        if suffix:
            sign = -1 if value < 0 else 1
            fraction += sign * ((abs(value) * 65536 + 50) // 100)
        else:
            absolute += value
    return int(extent * fraction / 65536) + absolute


def rectangle(properties, viewport, minimum=(0, 0)):
    width, height = viewport
    x = dimension(properties["left"], width)
    y = dimension(properties["top"], height)
    w = max(dimension(properties["width"], width), minimum[0])
    h = max(dimension(properties["height"], height), minimum[1])
    if w <= 0:
        w = 32
    if h <= 0:
        h = 32
    if x >= width:
        x = width - 32
    if y >= height:
        y = height - 32
    x, y = max(0, x), max(0, y)
    return x, y, min(w, width - x), min(h, height - y)


def components(theme):
    found = []
    for kind, body in re.findall(r"\+\s+(image|label|boot_menu)\s*\{([^}]+)\}", theme):
        fields = {}
        for key, value in re.findall(r'^\s*([a-z_]+)\s*=\s*(.+?)\s*$', body, re.M):
            fields[key] = value.strip('"')
        found.append((kind, fields))
    if [kind for kind, _ in found] != ["image", "label", "boot_menu", "label"]:
        raise ValueError("ANDEIVA_BOOT_GRUB_COMPONENTS")
    return [fields for _, fields in found]


def validate(theme):
    image, title, menu, hint = components(theme)
    if image["file"] != "andeiva-grub-logo.png":
        raise ValueError("ANDEIVA_BOOT_GRUB_IMAGE_SOURCE")
    rows = int(menu["item_height"]) * 3 + int(menu["item_spacing"]) * 2 + int(menu["item_padding"]) * 2
    for viewport in ((640, 400), (640, 480), (800, 600), (1280, 800)):
        logo = rectangle(image, viewport, (320, 160))
        heading = rectangle(title, viewport, (88, 16))
        listing = rectangle(menu, viewport, (150, rows))
        footer = rectangle(hint, viewport, (len(hint["text"]) * 8, 16))
        if logo[2:] != (320, 160) or logo[0] * 2 + logo[2] != viewport[0]:
            raise ValueError("ANDEIVA_BOOT_GRUB_LOGO_DISTORTED")
        if not (logo[1] + logo[3] + 8 <= heading[1]
                and heading[1] + heading[3] + 8 <= listing[1]
                and listing[1] + listing[3] + 4 <= footer[1]
                and footer[1] + footer[3] <= viewport[1]):
            raise ValueError(f"ANDEIVA_BOOT_GRUB_OVERLAP: {viewport}: {logo}, {heading}, {listing}, {footer}")
        if listing[3] < rows or listing[2] < 300:
            raise ValueError("ANDEIVA_BOOT_GRUB_MENU_SPACE")
        recovery = "ANDEIVA GNU/Linux, with Linux 6.12.116+deb13-amd64 (recovery mode)"
        if len(recovery) * 8 + int(menu["item_padding"]) * 2 > listing[2]:
            raise ValueError("ANDEIVA_BOOT_GRUB_RECOVERY_LABEL")
    # Regression proof: feeding the original bitmap reproduces minimum/clamping.
    old = rectangle(image, (640, 400), (1100, 550))
    if old[2] == 2 * old[3] or old[1] + old[3] <= rectangle(menu, (640, 400), (150, rows))[1]:
        raise ValueError("ANDEIVA_BOOT_GRUB_REGRESSION_MODEL")


if __name__ == "__main__":
    validate((Path(__file__).resolve().parents[1] / "grub" / "theme.txt").read_text())
    print("ANDEIVA_BOOT_GRUB_GEOMETRY_OK")
