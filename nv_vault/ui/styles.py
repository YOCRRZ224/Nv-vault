import gi
gi.require_version("Gtk", "4.0")
gi.require_version("Gdk", "4.0")
from gi.repository import Gtk, Gdk

NAUTILUS_CSS = """
.nautilus-tile {
    background-color: alpha(@card_bg_color, 0.75);
    border-radius: 12px;
    padding: 12px;
    border: 1px solid alpha(@borders, 0.4);
    transition: all 150ms ease-in-out;
}
.nautilus-tile:hover {
    background-color: alpha(@view_fg_color, 0.08);
    border-color: alpha(@accent_bg_color, 0.6);
}
flowboxchild:selected .nautilus-tile {
    background-color: alpha(@accent_bg_color, 0.22);
    border-color: @accent_bg_color;
}
.nautilus-pathbar {
    background-color: alpha(@view_fg_color, 0.06);
    border-radius: 8px;
    padding: 4px 10px;
}
.key-monospace {
    font-family: monospace;
    font-size: 0.92em;
}
.inspector-pane {
    background-color: @view_bg_color;
    border-left: 1px solid @borders;
}
"""

def apply_custom_css():
    provider = Gtk.CssProvider()
    provider.load_from_data(NAUTILUS_CSS.encode("utf-8"))
    display = Gdk.Display.get_default()
    if display:
        Gtk.StyleContext.add_provider_for_display(
            display, provider, Gtk.STYLE_PROVIDER_PRIORITY_APPLICATION
        )
