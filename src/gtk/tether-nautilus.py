# GNOME Files' right-click "Send with Tether", the counterpart of tether-send.desktop for Dolphin.
# Loaded by nautilus-python from share/nautilus-python/extensions.

import gettext

from gi.repository import GLib, GObject, Gio, Nautilus

_ = gettext.translation("tether", fallback=True).gettext


class TetherSendMenu(GObject.GObject, Nautilus.MenuProvider):
    def get_file_items(self, files):
        program = GLib.find_program_in_path("tether-gtk")
        paths = [f.get_location().get_path() for f in files if f.get_file_type() == Gio.FileType.REGULAR]
        if not program or not paths or None in paths:
            return []

        item = Nautilus.MenuItem(name="TetherSendMenu::Send", label=_("Send to iPhone"), icon="tether")
        item.connect("activate", lambda _item: Gio.Subprocess.new([program, "--send", *paths], Gio.SubprocessFlags.NONE))
        return [item]
