#!/usr/bin/env python3
import sys
import gi

gi.require_version("Gtk", "4.0")
gi.require_version("Adw", "1")
from gi.repository import Adw, Gio

from nv_vault.ui.window import NVVaultWindow


class NVVaultApplication(Adw.Application):
    def __init__(self):
        super().__init__(
            application_id="io.github.yocrrz.nvvault",
            flags=Gio.ApplicationFlags.FLAGS_NONE
        )

    def do_activate(self):
        win = self.props.active_window
        if not win:
            win = NVVaultWindow(self)
        win.present()


def main():
    app = NVVaultApplication()
    return app.run(sys.argv)


if __name__ == "__main__":
    sys.exit(main())
