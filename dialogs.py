#!/usr/bin/python
#
# Copyright (C) 2011
#
# Douglas Schilling Landgraf <dougsland@redhat.com>
#
# system-config-rhev - Red Hat Enterprise Virtualization Configuration 
#
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, version 2 of the License
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 675 Mass Ave, Cambridge, MA 02139, USA.

import os
import gtk.glade

builder = gtk.Builder()

def show_about(version, authors):
	if os.access("./glade/dialog-about.glade", os.F_OK):
		builder.add_from_file("./glade/dialog-about.glade")
	else:
		builder.add_from_file("/usr/share/system-config-rhev/dialog-about.glade")

	about_dialog = builder.get_object("dialog-about")

	about_dialog.set_version(version)
	about_dialog.set_authors(authors)

	about_dialog.run()
	about_dialog.hide()

	return True

def show_info_message(name, msg_info):
	if os.access("./glade/dialog-info-message.glade", os.F_OK):
		builder.add_from_file("./glade/dialog-info-message.glade")
	else:
		builder.add_from_file("/usr/share/system-config-rhev/dialog-info-message.glade")

	dialog_info_message = builder.get_object("dialog-info-message")
	dialog_info_message.set_markup("<b>" + name + "</b>")
	dialog_info_message.format_secondary_markup(msg_info)
	dialog_info_message.run()
	dialog_info_message.hide()

	return True

def show_error_message(msg_error):
	if os.access("./glade/dialog-error-message.glade", os.F_OK):
		builder.add_from_file("./glade/dialog-error-message.glade")
	else:
		builder.add_from_file("/usr/share/system-config-rhev/dialog-error-message.glade")

	dialog_error_message = builder.get_object("dialog-error-message")
	dialog_error_message.set_markup("<b>Error!</b>")
	dialog_error_message.format_secondary_markup(msg_error)
	dialog_error_message.run()
	dialog_error_message.hide()
	
	return False
