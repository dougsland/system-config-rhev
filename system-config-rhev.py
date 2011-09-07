#!/usr/bin/python
#
# Copyright (C) 2011
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

import sys
import os
import pygtk
import libvirtCallbacks
import vdsmCallbacks
import dialogs as dialog
import subprocess
from confparser import *
from libvirtPage import *

pygtk.require("2.0")
try:
	import gtk
	import gtk.glade
except: 
	sys.exit(1)


VERSION = "1.0.0"

VDSM_CONFIG_FILE = "/etc/vdsm/vdsm.conf"
LIBVIRT_CONFIG_FILE = "/etc/libvirt/libvirtd.conf"

AUTHORS = [
    "Douglas Schilling Landgraf <dougsland@redhat.com>"
    ]

# Dict to vdsm.conf
vdsmConf  = {}
libvirtConf = {}

# reading libvirt file
libvirtConf = confToDict(LIBVIRT_CONFIG_FILE)

# inheritance methods from callback classes
class MainWindow(libvirtCallbacks.load, vdsmCallbacks.load):


	def __init__(self):

		self.version = VERSION
		self.authors = AUTHORS
		self.windowAbout = None

		# Service 
		self.serviceVdsm     = "no"
		self.serviceLibvirt  = "no"
		self.serviceSelected = "no"

		# config files
		self.libvirtConf = libvirtConf

		self.builder = gtk.Builder()
		if os.access("./glade/system-config-rhev.glade", os.F_OK):
			self.builder.add_from_file("./glade/system-config-rhev.glade")
		else:
			self.builder.add_from_file("/usr/share/system-config-rhev/system-config-rhev.glade")
		

		# Setting main window
		self.window  = self.builder.get_object("MainWindow")

		# Build libvirt notebook page
		loadLibvirtPage(self)

	def _run(self):
        	"""
		Show main window and call gtk.main()
		"""
		self.window.show_all()
		gtk.main()

	def settings(self):
        	"""
		Load widgets and settings
	        """

		dic = {
			"destroy" :
			self.on_MainWindow_destroy,
			"on_menuitemAbout_activate" :
			self.on_menuitemAbout_activate,
		}	
		self.builder.connect_signals(self)

		# Set libvirt Page
		setLibvirtPage(self, libvirtConf)

	# Callbacks
	def on_MainWindow_destroy(self, *args):
		#quit main window
	        gtk.main_quit()

	def on_button_apply_yes_button_press_event(self, widget, data=None):
		try:
			self.apply_dialog.hide()
		except:
			pass

		if os.access("./glade/dialog-select-service.glade", os.F_OK):
			self.builder.add_from_file("./glade/dialog-select-service.glade")
		else:
			self.builder.add_from_file("/usr/share/system-config-rhev/dialog-select-service.glade")

		self.select_service_dialog = self.builder.get_object("dialog-select-service")

		self.builder.connect_signals(self)
	
		self.select_service_dialog.run()
		self.select_service_dialog.hide()
		return True

	def on_checkbutton_libvirt_toggled(self, widget, data=None):
		if widget.get_active() == False:
			# not selected
			self.serviceLibvirt = "no"
		else:
			self.serviceLibvirt = "yes"

	def on_checkbutton_vdsm_toggled(self, widget, data=None):
		if widget.get_active() == False:
			# not selected
			self.serviceVdsm = "no"
		else:
			self.serviceVdsm = "yes"

	def on_button_select_service_restart_clicked(self, widget, data=None):
		if self.serviceLibvirt != "no":
			if os.path.exists("/etc/init.d/libvirtd") != True:
				dialog.show_error_message("Cannot locate /etc/init.d/libvirtd!\n Please verify if you have libvirt installed!")
				return

			ret = subprocess.call(["/etc/init.d/libvirtd", "restart"])
			self.serviceSelected = "yes"
			if ret != 0:
				dialog.show_error_message("Cannot restart libvirtd!\n Please verify if your user has the rights to do it!")
			else:
				dialog.show_info_message("libvirtd", "service libvirtd restarted!")

		if self.serviceVdsm != "no":
			if os.path.exists("/etc/init.d/vdsmd") != True:
				dialog.show_error_message("Cannot locate /etc/init.d/vdsmd!\n Please verify if you have vdsm installed!")
				return

			ret = subprocess.call(["/etc/init.d/vdsmd", "restart"])
			self.serviceSelected = "yes"
			if ret != 0:
				dialog.show_error_message("Cannot restart vdsmd!\n Please verify if your user has the rights to do it!")
			else:
				dialog.show_info_message("vdsmd", "service vdsmd restarted!")

		if self.serviceSelected == "no":
			dialog.show_info_message("Info", "No service select, cancelled restart!")

		# Setting back the original state
		self.serviceVdsm     = "no"
		self.serviceLibvirt  = "no"
		self.serviceSelected = "no"

	def on_toolbutton_restart_clicked(self, *args):
		self.on_button_apply_yes_button_press_event(self)

	def on_toolbutton_apply_clicked(self, *args):
		if os.access("./glade/dialog-apply-message.glade", os.F_OK):
			self.builder.add_from_file("./glade/dialog-apply-message.glade")
		else:
			self.builder.add_from_file("/usr/share/system-config-rhev/dialog-apply-message.glade")

		self.apply_dialog = self.builder.get_object("dialog-apply-message")

		self.builder.connect_signals(self)

		# Salving current status
		self.libvirtConf['listen_tls']                 = self.listen_tls_entry.get_text() 
		self.libvirtConf['listen_tcp']                 = self.listen_tcp_entry.get_text() 
		self.libvirtConf['tls_port']                   = self.tls_port_entry.get_text() 
		self.libvirtConf['tcp_port']                   = self.tcp_port_entry.get_text() 
		self.libvirtConf['listen_addr']                = self.listen_addr_entry.get_text() 
		self.libvirtConf['mdns_adv']                   = self.mdns_adv_entry.get_text() 
		self.libvirtConf['mdns_name']                  = self.mdns_name_entry.get_text() 
		self.libvirtConf['unix_sock_group']            = self.unix_sock_group_entry.get_text() 
		self.libvirtConf['unix_sock_ro_perms']         = self.unix_sock_ro_perms_entry.get_text() 
		self.libvirtConf['unix_sock_rw_perms']         = self.unix_sock_rw_perms_entry.get_text() 
		self.libvirtConf['unix_sock_dir']              = self.unix_sock_dir_entry.get_text() 
		self.libvirtConf['auth_unix_ro']               = self.auth_unix_ro_entry.get_text() 
		self.libvirtConf['auth_unix_rw']               = self.auth_unix_rw_entry.get_text() 
		self.libvirtConf['auth_tcp']                   = self.auth_tcp_entry.get_text() 
		self.libvirtConf['auth_tls']                   = self.auth_tls_entry.get_text() 
		self.libvirtConf['key_file']                   = self.key_file_entry.get_text() 
		self.libvirtConf['cert_file']                  = self.cert_file_entry.get_text() 
		self.libvirtConf['ca_file']                    = self.ca_file_entry.get_text() 
		self.libvirtConf['crl_file']                   = self.crl_file_entry.get_text() 
		self.libvirtConf['tls_no_verify_certificate']  = self.tls_no_verify_certificate_entry.get_text() 
		self.libvirtConf['tls_allowed_dn_list']        = self.tls_allowed_dn_list_entry.get_text() 
		self.libvirtConf['sasl_allowed_username_list'] = self.sasl_allowed_username_list_entry.get_text() 
		self.libvirtConf['max_clients']                = self.max_clients_entry.get_text() 
		self.libvirtConf['min_workers']                = self.min_workers_entry.get_text() 
		self.libvirtConf['max_workers']                = self.max_workers_entry.get_text() 
		self.libvirtConf['max_requests']               = self.max_requests_entry.get_text() 
		self.libvirtConf['max_client_requests']        = self.max_client_requests_entry.get_text() 
		self.libvirtConf['log_level']                  = self.log_level_entry.get_text() 
		self.libvirtConf['log_filters']                = self.log_filters_entry.get_text() 
		self.libvirtConf['log_outputs']                = self.log_outputs_entry.get_text() 
		self.libvirtConf['audit_level']                = self.audit_level_entry.get_text() 
		self.libvirtConf['audit_logging']              = self.audit_logging_entry.get_text() 
		self.libvirtConf['host_uuid']                  = self.host_uuid_entry.get_text() 
		self.libvirtConf['save_image_format']	       = self.save_image_format_entry.get_text() 

		ret = writeDictToFile(LIBVIRT_CONFIG_FILE, libvirtConf)
		if (ret != 0):
			dialog.show_error_message("Cannot write into config file!\n Please verify!")

		self.apply_dialog.run()
		self.apply_dialog.hide()
		return True

	def on_menuitemAbout_activate(self, widget):
		dialog.show_about(self.version, self.authors)


if __name__ == "__main__":


	app = MainWindow()
	app.settings()
	app._run()
