from pathlib import Path
import gi
gi.require_version("Gtk", "4.0")
gi.require_version("Adw", "1")
from gi.repository import Gtk, Adw, GLib, Gdk
from ..crypto import CryptoEngine

IMAGE_EXTENSIONS = {".png", ".jpg", ".jpeg", ".webp", ".gif", ".bmp", ".svg"}
TEXT_EXTENSIONS = {".txt", ".md", ".py", ".json", ".sh", ".js", ".html", ".css", ".c", ".cpp", ".log", ".ini", ".yaml", ".yml"}

def copy_to_clipboard(widget: Gtk.Widget, text: str):
    clipboard = widget.get_clipboard()
    clipboard.set(text)

class KeyDisplayDialog(Adw.Window):
    """Native modal dialog for displaying One-Time M.Key or Shareable I.Key with Copy button."""
    def __init__(self, parent: Gtk.Window, title: str, subtitle: str, key_hex: str, on_toast=None):
        super().__init__(
            title=title,
            transient_for=parent,
            modal=True,
            default_width=500,
            default_height=270,
            resizable=False
        )
        self.key_hex = key_hex
        self.on_toast = on_toast

        toolbar = Adw.ToolbarView()
        header = Adw.HeaderBar()
        toolbar.add_top_bar(header)

        box = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=16)
        box.set_margin_top(20)
        box.set_margin_bottom(24)
        box.set_margin_start(24)
        box.set_margin_end(24)

        icon = Gtk.Image.new_from_icon_name("dialog-password-symbolic")
        icon.set_pixel_size(40)
        icon.add_css_class("accent")
        box.append(icon)

        lbl = Gtk.Label(label=subtitle, wrap=True, justify=Gtk.Justification.CENTER)
        lbl.add_css_class("body")
        box.append(lbl)

        # Entry + Copy button row
        entry_box = Gtk.Box(orientation=Gtk.Orientation.HORIZONTAL, spacing=8)
        self.entry = Gtk.Entry(text=key_hex, editable=False, hexpand=True)
        self.entry.add_css_class("key-monospace")

        copy_btn = Gtk.Button(icon_name="edit-copy-symbolic", tooltip_text="Copy Key to Clipboard")
        copy_btn.connect("clicked", self._on_copy)

        entry_box.append(self.entry)
        entry_box.append(copy_btn)
        box.append(entry_box)

        done_btn = Gtk.Button(label="I Have Saved This Key", css_classes=["suggested-action", "pill"])
        done_btn.set_halign(Gtk.Align.CENTER)
        done_btn.connect("clicked", lambda _: self.close())
        box.append(done_btn)

        toolbar.set_content(box)
        self.set_content(toolbar)

    def _on_copy(self, _btn):
        copy_to_clipboard(self, self.key_hex)
        if self.on_toast:
            self.on_toast("Key copied to clipboard!")


class SharedFileUnlockDialog(Adw.Window):
    """Dialog to unlock an external .nv file using only its I.Key."""
    def __init__(self, parent: Gtk.Window, nv_path: Path, on_toast=None):
        super().__init__(
            title=f"Unlock {nv_path.name}",
            transient_for=parent,
            modal=True,
            default_width=450,
            default_height=250,
            resizable=False
        )
        self.parent_win = parent
        self.nv_path = nv_path
        self.on_toast = on_toast

        toolbar = Adw.ToolbarView()
        toolbar.add_top_bar(Adw.HeaderBar())

        box = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=14)
        box.set_margin_top(20)
        box.set_margin_bottom(20)
        box.set_margin_start(24)
        box.set_margin_end(24)

        lbl = Gtk.Label(
            label=f"Enter the 64-character Individual Key (I.Key) to unlock '{nv_path.name}' without needing the sender's Master Key:",
            wrap=True,
            justify=Gtk.Justification.LEFT,
            xalign=0
        )
        box.append(lbl)

        self.entry = Gtk.Entry(placeholder_text="Paste 64-char hex I.Key here...")
        self.entry.add_css_class("key-monospace")
        self.entry.connect("activate", self._on_unlock)
        box.append(self.entry)

        btn = Gtk.Button(label="Decrypt & View in RAM", css_classes=["suggested-action", "pill"])
        btn.set_halign(Gtk.Align.END)
        btn.connect("clicked", self._on_unlock)
        box.append(btn)

        toolbar.set_content(box)
        self.set_content(toolbar)

    def _on_unlock(self, *_args):
        try:
            header, plaintext = CryptoEngine.decrypt_nv_with_ikey(self.nv_path, self.entry.get_text())
            self.close()
            viewer = StandaloneFileViewer(self.parent_win, header, plaintext)
            viewer.present()
        except Exception as e:
            if self.on_toast:
                self.on_toast(f"Decryption failed: {e}")


class StandaloneFileViewer(Adw.Window):
    """Full window viewer for inspecting decrypted images or text in RAM."""
    def __init__(self, parent: Gtk.Window, header: dict, plaintext: bytes, ikey_hex: str | None = None, on_toast=None):
        orig_name = header.get("orig_name", "Decrypted File")
        super().__init__(
            title=f"{orig_name} — NV Viewer",
            transient_for=parent,
            default_width=760,
            default_height=560
        )
        self.ikey_hex = ikey_hex
        self.on_toast = on_toast

        toolbar = Adw.ToolbarView()
        hb = Adw.HeaderBar()

        if ikey_hex:
            share_btn = Gtk.Button(label="Copy Share I.Key", icon_name="emblem-shared-symbolic")
            share_btn.connect("clicked", self._on_copy_ikey)
            hb.pack_end(share_btn)

        toolbar.add_top_bar(hb)

        scroll = Gtk.ScrolledWindow(vexpand=True, hexpand=True)
        ext = header.get("ext", "").lower()

        if ext in IMAGE_EXTENSIONS:
            try:
                texture = Gdk.Texture.new_from_bytes(GLib.Bytes.new(plaintext))
                pic = Gtk.Picture.new_for_paintable(texture)
                pic.set_can_shrink(True)
                pic.set_margin_top(12)
                pic.set_margin_bottom(12)
                pic.set_margin_start(12)
                pic.set_margin_end(12)
                scroll.set_child(pic)
            except Exception as e:
                scroll.set_child(Gtk.Label(label=f"Could not render image preview: {e}"))
        else:
            tv = Gtk.TextView(editable=False, monospace=True, wrap_mode=Gtk.WrapMode.WORD_CHAR)
            tv.set_top_margin(16)
            tv.set_bottom_margin(16)
            tv.set_left_margin(16)
            tv.set_right_margin(16)
            tv.get_buffer().set_text(plaintext.decode("utf-8", errors="replace"))
            scroll.set_child(tv)

        toolbar.set_content(scroll)
        self.set_content(toolbar)

    def _on_copy_ikey(self, _btn):
        if self.ikey_hex:
            copy_to_clipboard(self, self.ikey_hex)
            if self.on_toast:
                self.on_toast("Shareable I.Key copied to clipboard!")


class VaultSettingsDialog(Adw.Window):
    """Settings modal to migrate/import an existing M.Key on a new device."""
    def __init__(self, parent: Gtk.Window, vault_manager, on_updated_callback, on_toast):
        super().__init__(
            title="Vault Settings & Device Migration",
            transient_for=parent,
            modal=True,
            default_width=480,
            default_height=340,
            resizable=False
        )
        self.vault = vault_manager
        self.on_updated = on_updated_callback
        self.on_toast = on_toast

        toolbar = Adw.ToolbarView()
        toolbar.add_top_bar(Adw.HeaderBar())

        box = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=14)
        box.set_margin_top(20)
        box.set_margin_bottom(20)
        box.set_margin_start(24)
        box.set_margin_end(24)

        title = Gtk.Label(label="Migrate Master Key (M.Key)", css_classes=["title-3"], xalign=0)
        desc = Gtk.Label(
            label="Switched devices? Paste the Master Key (M.Key) from your previous device and enter a password to re-bind this vault folder.",
            wrap=True,
            xalign=0,
            css_classes=["dim-label"]
        )

        self.mkey_entry = Gtk.Entry(placeholder_text="Paste 64-character hex M.Key...")
        self.mkey_entry.add_css_class("key-monospace")

        self.pw_entry = Gtk.PasswordEntry(show_peek_icon=True, placeholder_text="Enter Vault Password to encrypt M.Key")

        save_btn = Gtk.Button(label="Import & Apply M.Key", css_classes=["suggested-action", "pill"])
        save_btn.set_halign(Gtk.Align.END)
        save_btn.connect("clicked", self._on_save)

        for w in [title, desc, self.mkey_entry, self.pw_entry, save_btn]:
            box.append(w)

        toolbar.set_content(box)
        self.set_content(toolbar)

    def _on_save(self, _btn):
        mkey_hex = self.mkey_entry.get_text().strip()
        pw = self.pw_entry.get_text()
        if not mkey_hex or not pw:
            self.on_toast("Both M.Key and Password are required.")
            return
        try:
            self.vault.import_mkey_with_password(pw, mkey_hex)
            self.on_toast("Master Key (M.Key) updated! Gallery refreshed.")
            self.on_updated()
            self.close()
        except Exception as e:
            self.on_toast(f"Failed to import M.Key: {e}")
