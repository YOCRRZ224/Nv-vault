import threading
from pathlib import Path

import gi
gi.require_version("Gtk", "4.0")
gi.require_version("Adw", "1")
from gi.repository import Gtk, Adw, Gio, GLib, GObject, Gdk, Pango

from ..crypto import CryptoEngine
from ..vault import VaultManager
from .dialogs import (
    IMAGE_EXTENSIONS,
    TEXT_EXTENSIONS,
    KeyDisplayDialog,
    SharedFileUnlockDialog,
    StandaloneFileViewer,
    VaultSettingsDialog,
    copy_to_clipboard,
)
from .styles import apply_custom_css


def format_size(num_bytes: int) -> str:
    for unit in ["B", "KB", "MB", "GB"]:
        if num_bytes < 1024.0:
            return f"{num_bytes:.1f} {unit}" if unit != "B" else f"{num_bytes} B"
        num_bytes /= 1024.0
    return f"{num_bytes:.1f} TB"


class NVVaultWindow(Adw.ApplicationWindow):
    def __init__(self, app):
        super().__init__(application=app, title="NV Files", default_width=1020, default_height=660)
        apply_custom_css()

        default_dir = Path.home() / "NVVault"
        self.vault = VaultManager(default_dir)

        # State tracking for Nautilus filters, view modes, and selection
        self.current_category = "all"   # "all", "images", "documents"
        self.view_mode = "grid"         # "grid" or "list"
        self.search_query = ""
        self.vault_items = []           # List of dicts with parsed metadata
        self.selected_item = None       # Currently inspected item dict

        self.toast_overlay = Adw.ToastOverlay()
        self.set_content(self.toast_overlay)

        self.root_stack = Gtk.Stack(transition_type=Gtk.StackTransitionType.CROSSFADE)
        self.toast_overlay.set_child(self.root_stack)

        self._build_auth_page()
        self._build_nautilus_page()

        self._refresh_auth_state()

    def show_toast(self, text: str):
        self.toast_overlay.add_toast(Adw.Toast.new(text))

    # ==========================================
    # 1. AUTHENTICATION / LOCK VIEW
    # ==========================================
    def _build_auth_page(self):
        toolbar = Adw.ToolbarView()
        hb = Adw.HeaderBar()

        ext_btn = Gtk.Button(label="Open Shared .nv (I.Key)", icon_name="document-open-symbolic")
        ext_btn.connect("clicked", self._on_pick_external_nv)
        hb.pack_end(ext_btn)
        toolbar.add_top_bar(hb)

        clamp = Adw.Clamp(maximum_size=420, tightening_threshold=360)
        box = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=16)
        box.set_valign(Gtk.Align.CENTER)
        box.set_margin_top(24)
        box.set_margin_bottom(24)
        box.set_margin_start(20)
        box.set_margin_end(20)

        icon = Gtk.Image.new_from_icon_name("system-lock-screen-symbolic")
        icon.set_pixel_size(64)
        icon.add_css_class("accent")
        box.append(icon)

        self.auth_title = Gtk.Label(css_classes=["title-1"])
        self.auth_subtitle = Gtk.Label(
            css_classes=["dim-label"],
            wrap=True,
            justify=Gtk.Justification.CENTER
        )
        box.append(self.auth_title)
        box.append(self.auth_subtitle)

        # Folder chooser row
        folder_btn = Gtk.Button(css_classes=["flat"])
        folder_box = Gtk.Box(orientation=Gtk.Orientation.HORIZONTAL, spacing=8, halign=Gtk.Align.CENTER)
        folder_box.append(Gtk.Image.new_from_icon_name("folder-symbolic"))
        self.folder_lbl = Gtk.Label(ellipsize=Pango.EllipsizeMode.MIDDLE)
        folder_box.append(self.folder_lbl)
        folder_btn.set_child(folder_box)
        folder_btn.connect("clicked", self._on_select_vault_folder)
        box.append(folder_btn)

        self.pass_entry = Gtk.PasswordEntry(show_peek_icon=True, placeholder_text="Enter Vault Password")
        self.pass_entry.connect("activate", self._on_auth_submit)
        box.append(self.pass_entry)

        self.mkey_setup_entry = Gtk.Entry(
            placeholder_text="Optional: Paste existing M.Key (Hex) if migrating device"
        )
        self.mkey_setup_entry.add_css_class("key-monospace")
        box.append(self.mkey_setup_entry)

        self.auth_spinner = Gtk.Spinner(spinning=False, visible=False)
        box.append(self.auth_spinner)

        self.auth_submit_btn = Gtk.Button(css_classes=["suggested-action", "pill"])
        self.auth_submit_btn.connect("clicked", self._on_auth_submit)
        box.append(self.auth_submit_btn)

        clamp.set_child(box)
        toolbar.set_content(clamp)
        self.root_stack.add_named(toolbar, "auth")

    def _refresh_auth_state(self):
        self.folder_lbl.set_text(str(self.vault.vault_dir))
        self.pass_entry.set_text("")
        if self.vault.is_initialized():
            self.auth_title.set_text("Unlock NV Vault")
            self.auth_subtitle.set_text(
                "Enter your password to derive P.Key via Argon2id and unlock your Nautilus vault gallery."
            )
            self.mkey_setup_entry.set_visible(False)
            self.auth_submit_btn.set_label("Unlock Vault")
        else:
            self.auth_title.set_text("Create NV Vault")
            self.auth_subtitle.set_text(
                "Set a master password for this folder. We will derive P.Key using Argon2id and generate your one-time Master Key (M.Key)."
            )
            self.mkey_setup_entry.set_visible(True)
            self.auth_submit_btn.set_label("Initialize Vault")

    def _on_auth_submit(self, *_args):
        pw = self.pass_entry.get_text()
        if not pw:
            self.show_toast("Please enter a password.")
            return

        is_setup = not self.vault.is_initialized()
        imported_mkey = self.mkey_setup_entry.get_text().strip() or None

        self.auth_submit_btn.set_sensitive(False)
        self.pass_entry.set_sensitive(False)
        self.auth_spinner.set_visible(True)
        self.auth_spinner.start()

        def worker():
            try:
                if is_setup:
                    mkey_hex = self.vault.setup_vault(pw, imported_mkey)
                    GLib.idle_add(self._on_auth_complete, True, mkey_hex, None)
                else:
                    ok = self.vault.unlock_vault(pw)
                    if ok:
                        GLib.idle_add(self._on_auth_complete, False, None, None)
                    else:
                        GLib.idle_add(self._on_auth_complete, False, None, "Invalid password! Failed to unlock M.Key.")
            except Exception as e:
                GLib.idle_add(self._on_auth_complete, is_setup, None, str(e))

        threading.Thread(target=worker, daemon=True).start()

    def _on_auth_complete(self, is_setup: bool, mkey_hex: str | None, error_msg: str | None):
        self.auth_spinner.stop()
        self.auth_spinner.set_visible(False)
        self.auth_submit_btn.set_sensitive(True)
        self.pass_entry.set_sensitive(True)

        if error_msg:
            self.show_toast(error_msg)
            return

        self.path_label.set_text(self.vault.vault_dir.name)
        self.reload_vault_files()
        self.root_stack.set_visible_child_name("nautilus")

        if is_setup and mkey_hex:
            dlg = KeyDisplayDialog(
                self,
                "One-Time Master Key (M.Key)",
                "Save this Master Key (M.Key) somewhere safe! It is shown only once.\n"
                "If you switch devices, open Settings -> Migrate M.Key to unlock all your existing .nv files.",
                mkey_hex,
                on_toast=self.show_toast
            )
            dlg.present()

    # ==========================================
    # 2. NAUTILUS SPLIT VIEW (SIDEBAR + CONTENT + INSPECTOR)
    # ==========================================
    def _build_nautilus_page(self):
        # Outer NavigationSplitView: Nautilus Left Sidebar + Main Content Area
        self.nav_split = Adw.NavigationSplitView(
            min_sidebar_width=210,
            max_sidebar_width=260,
            sidebar_width_fraction=0.22
        )

        # --- LEFT SIDEBAR (Nautilus Places) ---
        sidebar_toolbar = Adw.ToolbarView()
        sidebar_hb = Adw.HeaderBar()
        sidebar_hb.set_title_widget(Gtk.Label(label="NV Files", css_classes=["title"]))
        sidebar_toolbar.add_top_bar(sidebar_hb)

        sidebar_box = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=6)
        self.sidebar_list = Gtk.ListBox(css_classes=["navigation-sidebar"], vexpand=True)
        self.sidebar_list.set_selection_mode(Gtk.SelectionMode.SINGLE)
        self.sidebar_list.connect("row-selected", self._on_sidebar_Place_selected)

        places = [
            ("all", "folder-symbolic", "All Vault Files"),
            ("images", "image-x-generic-symbolic", "Images"),
            ("documents", "text-x-generic-symbolic", "Documents & Code"),
        ]
        for key, icon_name, title in places:
            row = Gtk.ListBoxRow()
            row.place_key = key
            hbox = Gtk.Box(orientation=Gtk.Orientation.HORIZONTAL, spacing=12)
            hbox.set_margin_top(8)
            hbox.set_margin_bottom(8)
            hbox.set_margin_start(12)
            hbox.set_margin_end(12)
            hbox.append(Gtk.Image.new_from_icon_name(icon_name))
            hbox.append(Gtk.Label(label=title, xalign=0))
            row.set_child(hbox)
            self.sidebar_list.append(row)

        sidebar_box.append(self.sidebar_list)
        sidebar_box.append(Gtk.Separator(orientation=Gtk.Orientation.HORIZONTAL))

        # Sidebar bottom actions (External .nv, Folder, Settings, Lock)
        actions_box = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=4)
        actions_box.set_margin_top(8)
        actions_box.set_margin_bottom(12)
        actions_box.set_margin_start(10)
        actions_box.set_margin_end(10)

        btn_shared = self._make_sidebar_button("document-open-symbolic", "Open Shared .nv (I.Key)", self._on_pick_external_nv)
        btn_folder = self._make_sidebar_button("folder-open-symbolic", "Switch Vault Folder", self._on_select_vault_folder)
        btn_settings = self._make_sidebar_button("emblem-system-symbolic", "Migrate M.Key / Settings", self._on_open_settings)
        btn_lock = self._make_sidebar_button("system-lock-screen-symbolic", "Lock Vault", self._on_lock_vault)

        for b in [btn_shared, btn_folder, btn_settings, btn_lock]:
            actions_box.append(b)

        sidebar_box.append(actions_box)
        sidebar_toolbar.set_content(sidebar_box)

        self.nav_split.set_sidebar(Adw.NavigationPage.new(sidebar_toolbar, "Sidebar"))

        # --- MAIN CONTENT AREA (HeaderBar + OverlaySplitView for Grid/List & Inspector) ---
        content_toolbar = Adw.ToolbarView()
        content_hb = Adw.HeaderBar()

        # Left side of HeaderBar: Encrypt (+ Add File)
        add_btn = Gtk.Button(css_classes=["suggested-action"])
        add_btn_box = Gtk.Box(orientation=Gtk.Orientation.HORIZONTAL, spacing=6)
        add_btn_box.append(Gtk.Image.new_from_icon_name("list-add-symbolic"))
        add_btn_box.append(Gtk.Label(label="Add to .nv"))
        add_btn.set_child(add_btn_box)
        add_btn.set_tooltip_text("Encrypt an image or text file into a .nv container")
        add_btn.connect("clicked", self._on_add_file_to_vault)
        content_hb.pack_start(add_btn)

        # Center of HeaderBar: Nautilus Path Pill
        path_box = Gtk.Box(orientation=Gtk.Orientation.HORIZONTAL, spacing=6, css_classes=["nautilus-pathbar"])
        path_box.append(Gtk.Image.new_from_icon_name("drive-harddisk-solidstate-symbolic"))
        self.path_label = Gtk.Label(label=self.vault.vault_dir.name, css_classes=["heading"])
        path_box.append(self.path_label)
        content_hb.set_title_widget(path_box)

        # Right side of HeaderBar: Search Toggle, Grid/List View Toggle, Inspector Toggle
        self.inspector_toggle = Gtk.ToggleButton(
            icon_name="sidebar-show-right-symbolic",
            active=True,
            tooltip_text="Toggle File Inspector Pane"
        )
        content_hb.pack_end(self.inspector_toggle)

        self.view_mode_btn = Gtk.Button(
            icon_name="view-list-symbolic",
            tooltip_text="Switch between Grid and List view"
        )
        self.view_mode_btn.connect("clicked", self._on_toggle_view_mode)
        content_hb.pack_end(self.view_mode_btn)

        self.search_toggle = Gtk.ToggleButton(
            icon_name="system-search-symbolic",
            tooltip_text="Search files in vault"
        )
        content_hb.pack_end(self.search_toggle)

        content_toolbar.add_top_bar(content_hb)

        # Search Bar under HeaderBar
        self.search_bar = Gtk.SearchBar()
        self.search_entry = Gtk.SearchEntry(placeholder_text="Filter .nv files by original name...", hexpand=True)
        self.search_entry.connect("search-changed", self._on_search_changed)
        self.search_bar.set_child(self.search_entry)
        self.search_bar.connect_entry(self.search_entry)
        self.search_toggle.bind_property("active", self.search_bar, "search-mode-enabled", GObject.BindingFlags.BIDIRECTIONAL)
        content_toolbar.add_top_bar(self.search_bar)

        # Inner Split: Center Files View + Right Inspector Drawer
        self.inspector_split = Adw.OverlaySplitView(
            sidebar_position=Gtk.PackType.END,
            min_sidebar_width=280,
            max_sidebar_width=340,
            sidebar_width_fraction=0.30,
            show_sidebar=True
        )
        self.inspector_toggle.bind_property(
            "active", self.inspector_split, "show-sidebar", GObject.BindingFlags.BIDIRECTIONAL
        )

        # Center Stack: Empty StatusPage vs Grid View vs List View
        self.files_stack = Gtk.Stack(transition_type=Gtk.StackTransitionType.CROSSFADE)

        self.empty_status = Adw.StatusPage(
            icon_name="folder-documents-symbolic",
            title="No .nv Files Found",
            description="Click '+ Add to .nv' in the top bar to encrypt images or documents into your vault."
        )
        self.files_stack.add_named(self.empty_status, "empty")

        # Grid View (FlowBox like Nautilus icon grid)
        grid_scroll = Gtk.ScrolledWindow(vexpand=True, hexpand=True)
        self.flowbox = Gtk.FlowBox(
            valign=Gtk.Align.START,
            max_children_per_line=8,
            min_children_per_line=2,
            selection_mode=Gtk.SelectionMode.SINGLE,
            homogeneous=True,
            column_spacing=14,
            row_spacing=14,
            margin_top=18,
            margin_bottom=18,
            margin_start=18,
            margin_end=18
        )
        self.flowbox.connect("child-activated", self._on_grid_child_activated)
        self.flowbox.connect("selected-children-changed", self._on_grid_selection_changed)
        grid_scroll.set_child(self.flowbox)
        self.files_stack.add_named(grid_scroll, "grid")

        # List View (Nautilus boxed list rows)
        list_scroll = Gtk.ScrolledWindow(vexpand=True, hexpand=True)
        list_clamp = Adw.Clamp(maximum_size=900, margin_top=18, margin_bottom=18, margin_start=18, margin_end=18)
        self.listbox = Gtk.ListBox(css_classes=["boxed-list"], selection_mode=Gtk.SelectionMode.SINGLE, valign=Gtk.Align.START)
        self.listbox.connect("row-selected", self._on_list_row_selected)
        self.listbox.connect("row-activated", self._on_list_row_activated)
        list_clamp.set_child(self.listbox)
        list_scroll.set_child(list_clamp)
        self.files_stack.add_named(list_scroll, "list")

        self.inspector_split.set_content(self.files_stack)
        self.inspector_split.set_sidebar(self._build_inspector_pane())

        content_toolbar.set_content(self.inspector_split)
        self.nav_split.set_content(Adw.NavigationPage.new(content_toolbar, "Vault Files"))

        self.root_stack.add_named(self.nav_split, "nautilus")
        self.sidebar_list.select_row(self.sidebar_list.get_row_at_index(0))

    def _make_sidebar_button(self, icon_name: str, label: str, callback) -> Gtk.Button:
        btn = Gtk.Button(css_classes=["flat"])
        box = Gtk.Box(orientation=Gtk.Orientation.HORIZONTAL, spacing=12)
        box.set_margin_top(4)
        box.set_margin_bottom(4)
        box.set_margin_start(6)
        box.append(Gtk.Image.new_from_icon_name(icon_name))
        box.append(Gtk.Label(label=label, xalign=0))
        btn.set_child(box)
        btn.connect("clicked", callback)
        return btn

    def _build_inspector_pane(self) -> Gtk.Widget:
        box = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=12, css_classes=["inspector-pane"])
        box.set_margin_top(16)
        box.set_margin_bottom(16)
        box.set_margin_start(16)
        box.set_margin_end(16)

        self.insp_title = Gtk.Label(
            label="Select a File",
            css_classes=["title-3"],
            wrap=True,
            ellipsize=Pango.EllipsizeMode.MIDDLE,
            xalign=0
        )
        self.insp_subtitle = Gtk.Label(label="Click any .nv item to decrypt in RAM", css_classes=["dim-label"], xalign=0)
        box.append(self.insp_title)
        box.append(self.insp_subtitle)

        # Preview Card
        preview_frame = Gtk.Frame(vexpand=True)
        self.insp_scroll = Gtk.ScrolledWindow(vexpand=True, hexpand=True)
        self.insp_placeholder = Adw.StatusPage(
            icon_name="document-properties-symbolic",
            title="Inspector",
            description="Decrypted preview and Individual Key (I.Key) envelope actions appear here."
        )
        self.insp_scroll.set_child(self.insp_placeholder)
        preview_frame.set_child(self.insp_scroll)
        box.append(preview_frame)

        # Action Buttons for the selected .nv file
        self.insp_actions_box = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=8, visible=False)

        open_full_btn = Gtk.Button(label="Open Full Viewer", icon_name="view-fullscreen-symbolic")
        open_full_btn.connect("clicked", self._on_open_selected_full)

        share_ikey_btn = Gtk.Button(label="Get Shareable I.Key", css_classes=["suggested-action"])
        share_ikey_btn.connect("clicked", self._on_show_selected_ikey)

        export_btn = Gtk.Button(label="Export Decrypted Copy...")
        export_btn.connect("clicked", self._on_export_selected_file)

        delete_btn = Gtk.Button(label="Delete .nv File", css_classes=["destructive-action"])
        delete_btn.connect("clicked", self._on_delete_selected_file)

        for b in [open_full_btn, share_ikey_btn, export_btn, delete_btn]:
            self.insp_actions_box.append(b)

        box.append(self.insp_actions_box)
        return box

    # ==========================================
    # 3. GALLERY POPULATION & FILTERING
    # ==========================================
    def reload_vault_files(self):
        self.vault_items.clear()
        for nv_path in sorted(self.vault.vault_dir.glob("*.nv")):
            try:
                header = CryptoEngine.read_header_only(nv_path)
                orig_name = header.get("orig_name", nv_path.stem)
                ext = header.get("ext", "").lower()
                size = header.get("size", nv_path.stat().st_size)
            except Exception:
                orig_name = nv_path.name
                ext = ""
                size = nv_path.stat().st_size

            self.vault_items.append({
                "nv_path": nv_path,
                "orig_name": orig_name,
                "ext": ext,
                "size": size
            })

        self._apply_filters_and_populate()

    def _apply_filters_and_populate(self):
        # Clear existing children
        while (child := self.flowbox.get_child_at_index(0)) is not None:
            self.flowbox.remove(child)
        while (row := self.listbox.get_row_at_index(0)) is not None:
            self.listbox.remove(row)

        filtered = []
        for item in self.vault_items:
            ext = item["ext"]
            if self.current_category == "images" and ext not in IMAGE_EXTENSIONS:
                continue
            if self.current_category == "documents" and ext in IMAGE_EXTENSIONS:
                continue
            if self.search_query and self.search_query not in item["orig_name"].lower() and self.search_query not in item["nv_path"].name.lower():
                continue
            filtered.append(item)

        if not filtered:
            self.files_stack.set_visible_child_name("empty")
            return

        for item in filtered:
            # 1. Build Nautilus Grid Tile
            tile = self._create_grid_tile(item)
            self.flowbox.append(tile)

            # 2. Build Nautilus List Row
            row = self._create_list_row(item)
            self.listbox.append(row)

        self.files_stack.set_visible_child_name(self.view_mode)

    def _create_grid_tile(self, item: dict) -> Gtk.FlowBoxChild:
        child = Gtk.FlowBoxChild()
        child.item_data = item

        card = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=8, css_classes=["nautilus-tile"])
        card.set_size_request(145, 155)
        card.set_valign(Gtk.Align.CENTER)

        # Thumbnail / Icon Stack
        thumb_stack = Gtk.Stack()
        thumb_stack.set_size_request(96, 88)
        icon_name = "image-x-generic-symbolic" if item["ext"] in IMAGE_EXTENSIONS else "text-x-generic-symbolic"
        icon = Gtk.Image.new_from_icon_name(icon_name)
        icon.set_pixel_size(52)
        thumb_stack.add_named(icon, "icon")
        card.append(thumb_stack)

        # Async thumbnail decryption for images if M.Key is unlocked
        if item["ext"] in IMAGE_EXTENSIONS and self.vault.m_key:
            self._load_image_thumbnail_async(item["nv_path"], thumb_stack)

        name_lbl = Gtk.Label(
            label=item["orig_name"],
            ellipsize=Pango.EllipsizeMode.MIDDLE,
            max_width_chars=16,
            justify=Gtk.Justification.CENTER,
            css_classes=["heading"]
        )
        meta_lbl = Gtk.Label(
            label=f"{item['nv_path'].name} • {format_size(item['size'])}",
            ellipsize=Pango.EllipsizeMode.END,
            css_classes=["caption", "dim-label"]
        )

        card.append(name_lbl)
        card.append(meta_lbl)
        child.set_child(card)
        return child

    def _load_image_thumbnail_async(self, nv_path: Path, thumb_stack: Gtk.Stack):
        m_key = self.vault.m_key
        if not m_key:
            return

        def worker():
            try:
                _, plaintext, _ = CryptoEngine.decrypt_nv_with_mkey(nv_path, m_key)
                gbytes = GLib.Bytes.new(plaintext)
                texture = Gdk.Texture.new_from_bytes(gbytes)

                def attach_thumb():
                    pic = Gtk.Picture.new_for_paintable(texture)
                    pic.set_can_shrink(True)
                    pic.set_content_fit(Gtk.ContentFit.COVER)
                    thumb_stack.add_named(pic, "thumb")
                    thumb_stack.set_visible_child_name("thumb")
                GLib.idle_add(attach_thumb)
            except Exception:
                pass

        threading.Thread(target=worker, daemon=True).start()

    def _create_list_row(self, item: dict) -> Gtk.ListBoxRow:
        icon_name = "image-x-generic-symbolic" if item["ext"] in IMAGE_EXTENSIONS else "text-x-generic-symbolic"
        row = Adw.ActionRow(
            title=GLib.markup_escape_text(item["orig_name"]),
            subtitle=f"Container: {item['nv_path'].name}  •  Size: {format_size(item['size'])}"
        )
        row.item_data = item
        row.add_prefix(Gtk.Image.new_from_icon_name(icon_name))
        badge = Gtk.Label(label=item["ext"].upper() or ".NV", css_classes=["caption", "dim-label"])
        row.add_suffix(badge)
        return row

    # ==========================================
    # 4. SELECTION, PREVIEW & ACTIONS
    # ==========================================
    def _on_sidebar_Place_selected(self, _listbox, row):
        if not row:
            return
        self.current_category = row.place_key
        self._apply_filters_and_populate()

    def _on_search_changed(self, entry):
        self.search_query = entry.get_text().strip().lower()
        self._apply_filters_and_populate()

    def _on_toggle_view_mode(self, btn):
        if self.view_mode == "grid":
            self.view_mode = "list"
            btn.set_icon_name("view-grid-symbolic")
        else:
            self.view_mode = "grid"
            btn.set_icon_name("view-list-symbolic")
        if self.vault_items:
            self.files_stack.set_visible_child_name(self.view_mode)

    def _on_grid_selection_changed(self, flowbox):
        selected = flowbox.get_selected_children()
        if selected:
            self._inspect_item(selected[0].item_data)

    def _on_grid_child_activated(self, _flowbox, child):
        self._inspect_item(child.item_data, open_modal=False)

    def _on_list_row_selected(self, _listbox, row):
        if row and hasattr(row, "item_data"):
            self._inspect_item(row.item_data)

    def _on_list_row_activated(self, _listbox, row):
        if row and hasattr(row, "item_data"):
            self._inspect_item(row.item_data, open_modal=True)

    def _inspect_item(self, item: dict, open_modal: bool = False):
        if not self.vault.m_key:
            return
        nv_path = item["nv_path"]
        try:
            header, plaintext, ikey_hex = CryptoEngine.decrypt_nv_with_mkey(nv_path, self.vault.m_key)
            self.selected_item = {
                "nv_path": nv_path,
                "header": header,
                "plaintext": plaintext,
                "ikey_hex": ikey_hex
            }
            self.insp_title.set_text(header.get("orig_name", nv_path.name))
            self.insp_subtitle.set_text(f"{nv_path.name} • {format_size(len(plaintext))} (Decrypted in RAM)")
            self.insp_actions_box.set_visible(True)

            ext = header.get("ext", "").lower()
            if ext in IMAGE_EXTENSIONS:
                texture = Gdk.Texture.new_from_bytes(GLib.Bytes.new(plaintext))
                pic = Gtk.Picture.new_for_paintable(texture)
                pic.set_can_shrink(True)
                self.insp_scroll.set_child(pic)
            else:
                tv = Gtk.TextView(editable=False, monospace=True, wrap_mode=Gtk.WrapMode.WORD_CHAR)
                tv.set_top_margin(10)
                tv.set_bottom_margin(10)
                tv.set_left_margin(10)
                tv.set_right_margin(10)
                tv.get_buffer().set_text(plaintext.decode("utf-8", errors="replace"))
                self.insp_scroll.set_child(tv)

            if open_modal:
                viewer = StandaloneFileViewer(self, header, plaintext, ikey_hex, on_toast=self.show_toast)
                viewer.present()

        except Exception:
            self.selected_item = None
            self.insp_title.set_text(f"{nv_path.name} (Locked)")
            self.insp_subtitle.set_text("Encrypted with a different Master Key (M.Key)")
            self.insp_actions_box.set_visible(False)
            status = Adw.StatusPage(
                icon_name="dialog-password-symbolic",
                title="Different M.Key",
                description="Use 'Open Shared .nv (I.Key)' in the sidebar if you have this file's Individual Key."
            )
            self.insp_scroll.set_child(status)

    def _on_open_selected_full(self, _btn):
        if self.selected_item:
            viewer = StandaloneFileViewer(
                self,
                self.selected_item["header"],
                self.selected_item["plaintext"],
                self.selected_item["ikey_hex"],
                on_toast=self.show_toast
            )
            viewer.present()

    def _on_show_selected_ikey(self, _btn):
        if self.selected_item:
            orig_name = self.selected_item["header"].get("orig_name", "File")
            dlg = KeyDisplayDialog(
                self,
                f"Share Key (I.Key) — {orig_name}",
                "Give this Individual Key (I.Key) along with the .nv file to your recipient.\n"
                "It unlocks ONLY this file without exposing your Vault Master Key (M.Key):",
                self.selected_item["ikey_hex"],
                on_toast=self.show_toast
            )
            dlg.present()

    def _on_export_selected_file(self, _btn):
        if not self.selected_item:
            return
        orig_name = self.selected_item["header"].get("orig_name", "decrypted_file")
        dialog = Gtk.FileDialog(title="Export Decrypted File", initial_name=orig_name)
        dialog.save(self, None, self._on_export_save_finish)

    def _on_export_save_finish(self, dialog, result):
        try:
            gfile = dialog.save_finish(result)
            if gfile and self.selected_item:
                out_path = Path(gfile.get_path())
                out_path.write_bytes(self.selected_item["plaintext"])
                self.show_toast(f"Exported to {out_path.name}")
        except GLib.Error:
            pass

    def _on_delete_selected_file(self, _btn):
        if not self.selected_item:
            return
        nv_path: Path = self.selected_item["nv_path"]
        try:
            nv_path.unlink(missing_ok=True)
            self.selected_item = None
            self.insp_actions_box.set_visible(False)
            self.insp_title.set_text("Select a File")
            self.insp_subtitle.set_text("File deleted from vault")
            self.insp_scroll.set_child(self.insp_placeholder)
            self.reload_vault_files()
            self.show_toast(f"Deleted {nv_path.name}")
        except Exception as e:
            self.show_toast(f"Delete failed: {e}")

    # ==========================================
    # 5. ADD FILE, SWITCH FOLDER, SETTINGS & LOCK
    # ==========================================
    def _on_add_file_to_vault(self, _btn):
        dialog = Gtk.FileDialog(title="Select File to Convert to .nv")
        dialog.open(self, None, self._on_add_file_finish)

    def _on_add_file_finish(self, dialog, result):
        try:
            gfile = dialog.open_finish(result)
            if gfile and self.vault.m_key:
                in_path = Path(gfile.get_path())
                out_path, ikey_hex = CryptoEngine.encrypt_to_nv(in_path, self.vault.vault_dir, self.vault.m_key)
                self.reload_vault_files()
                dlg = KeyDisplayDialog(
                    self,
                    f"Created {out_path.name}",
                    "Here is the Individual Key (I.Key) generated for this file.\n"
                    "If you share this .nv file with someone else, send them this I.Key instead of your M.Key:",
                    ikey_hex,
                    on_toast=self.show_toast
                )
                dlg.present()
        except GLib.Error:
            pass
        except Exception as e:
            self.show_toast(f"Encryption failed: {e}")

    def _on_pick_external_nv(self, _btn):
        dialog = Gtk.FileDialog(title="Select Shared .nv Container")
        dialog.open(self, None, self._on_pick_external_nv_finish)

    def _on_pick_external_nv_finish(self, dialog, result):
        try:
            gfile = dialog.open_finish(result)
            if gfile:
                unlock_dlg = SharedFileUnlockDialog(self, Path(gfile.get_path()), on_toast=self.show_toast)
                unlock_dlg.present()
        except GLib.Error:
            pass

    def _on_select_vault_folder(self, _btn):
        dialog = Gtk.FileDialog(title="Choose NV Vault Folder")
        dialog.select_folder(self, None, self._on_select_vault_folder_finish)

    def _on_select_vault_folder_finish(self, dialog, result):
        try:
            folder = dialog.select_folder_finish(result)
            if folder:
                self.vault.set_directory(Path(folder.get_path()))
                self._refresh_auth_state()
                self.root_stack.set_visible_child_name("auth")
        except GLib.Error:
            pass

    def _on_open_settings(self, _btn):
        dlg = VaultSettingsDialog(self, self.vault, self.reload_vault_files, self.show_toast)
        dlg.present()

    def _on_lock_vault(self, _btn):
        self.vault.lock()
        self.selected_item = None
        self._refresh_auth_state()
        self.root_stack.set_visible_child_name("auth")
        self.show_toast("Vault locked.")
