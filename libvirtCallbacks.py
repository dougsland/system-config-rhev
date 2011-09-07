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

import dialogs as dialog

class load:

############################ INFO DIALOG ####################################

	def on_eventbox_listen_tcp_button_press_event(self, *args):
		msg = "Listen for unencrypted TCP connections on the public TCP/IP port. "     \
			"NB, must pass the --listen flag to the libvirtd process for this to " \
			"have any effect.\n\n"						       \
			"Using the TCP socket requires SASL authentication by default. Only "  \
			"SASL mechanisms which support data encryption are allowed. This is "  \
			"DIGEST_MD5 and GSSAPI (Kerberos5)"
		dialog.show_info_message("listen_tcp", msg)

	def on_eventbox_tcp_port_button_press_event(self, *args):
		msg = "Override the port for accepting insecure TCP connections.\n" \
			"This can be a port number, or service name"
		dialog.show_info_message("tcp_port", msg)

	def on_eventbox_tls_port_button_press_event(self, *args):
		msg = "Override the port for accepting secure TLS connections.\n" \
			"This can be a port number, or service name"
		dialog.show_info_message("tls_port", msg)

	def on_eventbox_listen_tls_button_press_event(self, *args):
		msg = "TLS connections on the public TCP/IP port.\n" 			       \
			"NB, must pass the --listen flag to the libvirtd process for this to " \
			"have any effect.\n\n" 						       \
			"It is necessary to setup a CA and issue server certificates before "  \
			"using this capability."
		dialog.show_info_message("listen_tls", msg)

	def on_eventbox_mdns_adv_button_press_event(self, *args):
		msg = "Flag toggling mDNS advertizement of the libvirt service.\n\n" \
			"Alternatively can disable for all services on a host by "   \
			"stopping the Avahi daemon"
		dialog.show_info_message("mdns_adv", msg)

	def on_eventbox_listen_addr_button_press_event(self, *args):
		msg = "Override the default configuration which binds to all network " \
			"interfaces.\n\nThis can be a numeric IPv4/6 address, or hostname."
		dialog.show_info_message("listen_addr", msg)

	def on_eventbox_mdns_name_button_press_event(self, *args):
		msg = "Override the default mDNS advertizement name.\nThis must be " 	   \
			"unique on the immediate broadcast network.\n\n" 		   \
			"The default is \"Virtualization Host HOSTNAME\", where HOSTNAME " \
			"is subsituted for the short hostname of the machine (without domain)"
		dialog.show_info_message("mdns_name", msg)

	def on_eventbox_unix_sock_group_button_press_event(self, *args):
		msg = "Set the UNIX domain socket group ownership. This can be used to "      \
			"allow a \'trusted\' set of users access to management capabilities " \
			"without becoming root.\n\n" 					      \
			"This is restricted to 'root' by default"
		dialog.show_info_message("unix_sock_group", msg)
		
	def on_eventbox_unix_sock_ro_perms_button_press_event(self, *args):
		msg = "Set the UNIX socket permissions for the R/O socket.\n\nThis is used " \
			"for monitoring VM status only.\n\n" 				     \
			"Default allows any user. If setting group ownership may want to "   \
			"restrict this."

		dialog.show_info_message("unix_sock_ro_perms", msg)

	def on_eventbox_unix_rw_perms_button_press_event(self, *args):
		msg = "Set the UNIX socket permissions for the R/W socket.\n\nThis is used " \
			"for full management of VMs\n\n" 				     \
			"Default allows only root. If PolicyKit is enabled on the socket, "  \
			"the default will change to allow everyone (eg, 0777)\n\n" 	     \
			"If not using PolicyKit and setting group ownership for access "     \
			"control then you may want to relax this."
		dialog.show_info_message("unix_rw_perms", msg)

	def on_eventbox_unix_sock_dir_button_press_event(self, *args):
		msg = "Set the name of the directory in which sockets will be found/created."
		dialog.show_info_message("unix_sock_dir", msg)

	def on_eventbox_auth_unix_ro_button_press_event(self, *args):
		msg = "Set an authentication scheme for UNIX read-only sockets " 	  \
			"By default socket permissions allow anyone to connect\n\n"       \
			"To restrict monitoring of domains you may wish to enable " 	  \
			"an authentication mechanism\n\n" 				  \
			"- none: do not perform auth checks. If you can connect to the "  \
			"socket you are allowed. This is suitable if there are " 	  \
			"restrictions on connecting to the socket (eg, UNIX "  		  \
			"socket permissions), or if there is a lower layer in " 	  \
			"the network providing auth (eg, TLS/x509 certificates)\n\n" 	  \
			"- sasl: use SASL infrastructure. The actual auth scheme is then" \
			"controlled from /etc/sasl2/libvirt.conf. For the TCP " 	  \
			"socket only GSSAPI DIGEST-MD5 mechanisms will be used. " 	  \
			"For non-TCP or TLS sockets,  any scheme is allowed.\n\n" 	  \
			"- polkit: use PolicyKit to authenticate. This is only suitable"  \
			"for use on the UNIX sockets. The default policy will" 		  \
			"require a user to supply their own password to gain" 		  \
			"full read/write access (aka sudo like), while anyone" 		  \
			"is allowed read/only access."
		dialog.show_info_message("auth_unix_ro", msg)

	def on_eventbox_auth_unix_rw_button_press_event(self, *args):
		msg = "Set an authentication scheme for UNIX read-write sockets " 	\
			"By default socket permissions only allow root. If PolicyKit "  \
			"support was compiled into libvirt, the default will be to "    \
			"use 'polkit' auth.\n\n" 					\
			"If the unix_sock_rw_perms are changed you may wish to enable " \
			"an authentication mechanism here"
		dialog.show_info_message("auth_unix_rw", msg)

	def on_eventbox_auth_tcp_button_press_event(self, *args):
		msg = "Change the authentication scheme for TCP sockets.\n\n" 		 \
			"If you don't enable SASL, then all TCP traffic is cleartext.\n" \
			"Don't do this outside of a dev/test scenario. For real world "  \
			"use, always enable SASL and use the GSSAPI or DIGEST-MD5 "      \
			"mechanism in /etc/sasl2/libvirt.conf"
		dialog.show_info_message("auth_tcp", msg)

	def on_eventbox_auth_tls_button_press_event(self, *args):
		msg = "Change the authentication scheme for TLS sockets.\n\n" 		\
			"TLS sockets already have encryption provided by the TLS " 	\
			"layer, and limited authentication is done by certificates\n" 	\
			"It is possible to make use of any SASL authentication " 	\
			"mechanism as well, by using 'sasl' for this option"
		dialog.show_info_message("auth_tls", msg)
		
	def on_eventbox_key_file_button_press_event(self, *args):
		msg = "Override the default server key file path."
		dialog.show_info_message("key_file", msg)

	def on_eventbox_cert_file_button_press_event(self, *args):
		msg = "Override the default server certificate file path."
		dialog.show_info_message("cert_file", msg)

	def on_eventbox_ca_file_button_press_event(self, *args):
		msg = "Override the default CA certificate path."
		dialog.show_info_message("ca_file", msg)

	def on_eventbox_crl_file_button_press_event(self, *args):
		msg = "Specify a certificate revocation list."
		dialog.show_info_message("crl_file", msg)

	def on_eventbox_tls_no_verify_certificate_button_press_event(self, *args):
		msg = "Flag to disable verification of client certificates\n" 				\
			"Client certificate verification is the primary authentication mechanism.\n\n"  \
			"Any client which does not present a certificate signed by the CA " 		\
			"will be rejected.\n\n" 							\
			"Default is to always verify.\n" 						\
			"verification - make sure an IP whitelist is set"
		dialog.show_info_message("tls_no_verify_certificate", msg)
		
	def on_eventbox_tls_allowed_dn_list_button_press_event(self, *args):
		msg = "A whitelist of allowed x509  Distinguished Names" 		      \
			"This list may contain wildcards such as\n\n" 			      \
			"\"C=GB,ST=London,L=London,O=Red Hat,CN=*\"\n\n" 		      \
			"See the POSIX fnmatch function for the format of the wildcards.\n"   \
			"NB If this is an empty list, no client can connect, so comment out " \
			"entirely rather than using empty list to disable these checks\n\n"   \
			"By default, no DN's are checked"
		dialog.show_info_message("tls_allowed_dn_list", msg)

	def on_eventbox_max_clients_button_press_event(self, *args):
		msg = "The maximum number of concurrent client connections to allow " \
			"over all sockets combined.\n"
		dialog.show_info_message("max_clients", msg)

	def on_eventbox_min_workers_button_press_event(self, *args):
		msg = "The minimum limit sets the number of workers to start up "    \
			"initially. If the number of active clients exceeds this, "  \
			"then more threads are spawned, upto max_workers limit.\n\n" \
			"Typically you'd want max_workers to equal maximum number "  \
			"of clients allowed"
		dialog.show_info_message("min_workers", msg)

	def on_eventbox_max_workers_button_press_event(self, *args):
		msg = "The maximum limit sets the number of workers"
		dialog.show_info_message("max_workers", msg)

	def on_eventbox_max_requests_button_press_event(self, *args):
		msg = "Total global limit on concurrent RPC calls. Should be "        \
			"at least as large as max_workers. Beyond this, RPC requests "\
			"will be read into memory and queued. This directly impact "  \
			"memory usage, currently each request requires 256 KB of "    \
			"memory.\n\nSo by default upto 5 MB of memory is used\n\n"    \
			"XXX this isn't actually enforced yet, only the per-client"
		dialog.show_info_message("max_requests", msg)

	def on_eventbox_max_client_requests_button_press_event(self, *args):
		msg = "Limit on concurrent requests from a single client " 	      \
			"connection. To avoid one client monopolizing the server "    \
			"this should be a small fraction of the global max_requests " \
			"and max_workers parameter"
		dialog.show_info_message("max_client_requests", msg)

	def on_eventbox_log_filters_button_press_event(self, *args):
		msg = "A filter allows to select a different logging level for a given category " 	 \
			"of logs.\n\n"								 	 \
			"The format for a filter is:\n\n" 					 	 \
			"x:name\n"								 	 \
			"where name is a match string e.g. remote or qemu\n"			 	 \
			"the x prefix is the minimal level where matching messages should be logged\n\n" \
			"1: DEBUG\n"									 \
			"2: INFO\n"									 \
			"3: WARNING\n"									 \
			"4: ERROR\n\n"									 \
			"Multiple filter can be defined in a single @filters, they just need to be "	 \
			"separated by spaces.\n\n" 							 \
			"e.g:\n"									 \
			"log_filters=\"3:remote 4:event\"\n"						 \
			"to only get warning or errors from the remote layer and only errors from "	 \
			"the event layer."
		dialog.show_info_message("log_filters", msg)

	def on_eventbox_log_outputs_button_press_event(self, *args):
		msg = "An output is one of the places to save logging informations\n\n" 	        \
			"The format for an output can be:\n"					        \
			"x:stderr\n"								        \
			"output goes to stderr\n"						        \
			"x:syslog:name\n"							        \
			"use syslog for the output and use the given name as the ident\n" 	        \
			"x:file:file_path\n"							        \
			"output to a file, with the given filepath\n"				        \
			"In all case the x prefix is the minimal level, acting as a filter\n\n"         \
			"1: DEBUG\n"								        \
			"2: INFO\n"								        \
			"3: WARNING\n"								        \
			"4: ERROR\n\n"								        \
			"Multiple output can be defined, they just need to be separated by spaces.\n\n" \
			"e.g.:\n"								        \
			"log_outputs=\"3:syslog:libvirtd\"\n"					        \
			"to log all warnings and errors to syslog under the libvirtd ident"
		dialog.show_info_message("log_outputs", msg)

	def on_eventbox_audit_level_button_press_event(self, *args):
		msg = "This setting allows usage of the auditing subsystem to be altered" 		\
			"audit_level == 0  -> disable all auditing\n" 					\
			"audit_level == 1  -> enable auditing, only if enabled on host (default)\n"	\
			"audit_level == 2  -> enable auditing, and exit if disabled on host\n"		\
			"audit_level = 2\n\n"								\
			"If set to 1, then audit messages will also be sent "				\
			"via libvirt logging infrastructure. Defaults to 0"				
		dialog.show_info_message("audit_level", msg)

	def on_eventbox_audit_logging_button_press_event(sef, *args):
		msg = "This setting allows usage of the auditing subsystem to be altered:\n\n" 		\
			"audit_level == 0  -> disable all auditing\n" 					\
			"audit_level == 1  -> enable auditing, only if enabled on host (default)\n"	\
			"audit_level == 2  -> enable auditing, and exit if disabled on host\n"		\
			"audit_level = 2\n\n"								\
			"If set to 1, then audit messages will also be sent "				\
			"via libvirt logging infrastructure. Defaults to 0"				
		dialog.show_info_message("audit_logging", msg)

	def on_eventbox_log_level_button_press_event(self, *args):
		msg = "Logging level: 4 errors, 3 warnings, 2 informations, 1 debug " \
			"basically 1 will log everything possible"
		dialog.show_info_message("log_level", msg)

	def on_eventbox_host_uuids_button_press_event(self, *args):
		msg = "Provide the UUID of the host here in case the command " \
			"'dmidecode -s system-uuid' does not provide a valid uuid.\n\nIn case " \
			"'dmidecode' does not provide a valid UUID and none is provided here, a " \
			"temporary UUID will be generated.\n\n" \
			"Keep the format of the example UUID below. UUID must not have all digits " \
			"be the same.\n\n" \
			"NB This default all-zeros UUID will not work. Replace" \
			"it with the output of the \'uuidgen\'"
		dialog.show_info_message("host_uuids", msg)

	def on_eventbox_image_save_image_format_button_press_event(self, *args):
		msg = "image format"
		dialog.show_info_message("save_image_format", msg)

############################ END INFO DIALOG ##################################

############################ CHECKBOX #########################################

# Network Connectivity controls 

	def on_radiobutton_listen_tls_enable_toggled(self, widget, data=None):
		self.libvirtConf['listen_tls'] = self.listen_tls_entry.get_text()
		if widget.get_active() == False:
			# disabled selected
			self.listen_tls_entry.set_sensitive(False)
			self.libvirtConf['listen_tls_status'] = "commented"
		else:
			# enable selected
			self.listen_tls_entry.set_sensitive(True)
			self.libvirtConf['listen_tls_status'] = "activated"

	def on_radiobutton_listen_tcp_enable_toggled(self, widget, data=None):
		if widget.get_active() == False:
			# disable selected
			self.listen_tcp_entry.set_sensitive(False)
			self.libvirtConf['listen_tcp_status'] = "commented"
		else:
			# enable selected
			self.listen_tcp_entry.set_sensitive(True)
			self.libvirtConf['listen_tcp_status'] = "activated"

	def on_radiobutton_tls_port_enable_toggled(self, widget, data=None):
		if widget.get_active() == False:
			# disable selected
			self.tls_port_entry.set_sensitive(False)
			self.libvirtConf['tls_port_status'] = "commented"
		else:
			# enable selected
			self.tls_port_entry.set_sensitive(True)
			self.libvirtConf['tls_port_status'] = "activated"


	def on_radiobutton_tcp_port_enable_toggled(self, widget, data=None):
		if widget.get_active() == False:
			# disable selected
			self.tcp_port_entry.set_sensitive(False)
			self.libvirtConf['tcp_port_status'] = "commented"
		else:
			# enable selected
			self.tcp_port_entry.set_sensitive(True)
			self.libvirtConf['tcp_port_status'] = "activated"

	def on_radiobutton_listen_addr_enable_toggled(self, widget, data=None):
		if widget.get_active() == False:
			# disable selected
			self.listen_addr_entry.set_sensitive(False)
			self.libvirtConf['listen_addr_status'] = "commented"
		else:
			# enable selected
			self.listen_addr_entry.set_sensitive(True)
			self.libvirtConf['listen_addr_status'] = "activated"
		
	def on_radiobutton_mdns_adv_enable_toggled(self, widget, data=None):
		if widget.get_active() == False:
			# disable selected
			self.mdns_adv_entry.set_sensitive(False)
			self.libvirtConf['mdns_adv_status'] = "commented"
		else:
			# enable selected
			self.mdns_adv_entry.set_sensitive(True)
			self.libvirtConf['mdns_adv_status'] = "activated"

	def on_radiobutton_mdns_name_enable_toggled(self, widget, data=None):			
		if widget.get_active() == False:
			# disable selected
			self.mdns_name_entry.set_sensitive(False)
			self.libvirtConf['mdns_name_status'] = "commented"
		else:
			# enable selected
			self.mdns_name_entry.set_sensitive(True)
			self.libvirtConf['mdns_name_status'] = "activated"

# UNIX socket access controls

	def on_radiobutton_unix_sock_group_enable_toggled(self, widget, data=None):
		if widget.get_active() == False:
			# disable selected
			self.unix_sock_group_entry.set_sensitive(False)
			self.libvirtConf['unix_sock_group_status'] = "commented"
		else:
			# enable selected
			self.unix_sock_group_entry.set_sensitive(True)
			self.libvirtConf['unix_sock_group_status'] = "activated"

	def on_radiobutton_unix_sock_ro_perms_enable_toggled(self, widget, data=None):
		if widget.get_active() == False:
			# disable selected
			self.unix_sock_ro_perms_entry.set_sensitive(False)
			self.libvirtConf['unix_sock_ro_perms_status'] = "commented"
		else:
			# enable selected
			self.unix_sock_ro_perms_entry.set_sensitive(True)
			self.libvirtConf['unix_sock_ro_perms_status'] = "activated"

	def on_radiobutton_unix_sock_rw_perms_enable_toggled(self, widget, data=None):
		if widget.get_active() == False:
			# disable selected
			self.unix_sock_rw_perms_entry.set_sensitive(False)
			self.libvirtConf['unix_sock_rw_perms_status'] = "commented"

		else:
			# enable selected
			self.unix_sock_rw_perms_entry.set_sensitive(True)
			self.libvirtConf['unix_sock_rw_perms_status'] = "activated"


	def on_radiobutton_unix_sock_dir_enable_toggled(self, widget, data=None):
		if widget.get_active() == False:
			# disable selected
			self.unix_sock_dir_entry.set_sensitive(False)
			self.libvirtConf['unix_sock_dir_status'] = "commented"
		else:
			# enable selected
			self.unix_sock_dir_entry.set_sensitive(True)
			self.libvirtConf['unix_sock_dir_status'] = "activated"

# Authentication

	def on_radiobutton_auth_unix_ro_enable_toggled(self, widget, data=None):
		if widget.get_active() == False:
			# disable selected
			self.libvirtConf['auth_unix_ro_status'] = "commented"
			self.auth_unix_ro_entry.set_sensitive(False)
		else:
			# enable selected
			self.libvirtConf['auth_unix_ro_status'] = "activated"
			self.auth_unix_ro_entry.set_sensitive(True)

	def on_radiobutton_auth_unix_rw_enable_toggled(self, widget, data=None):
		if widget.get_active() == False:
			# disable selected
			self.auth_unix_rw_entry.set_sensitive(False)
			self.libvirtConf['auth_unix_rw_status'] = "commented"
		else:
			# enable selected
			self.auth_unix_rw_entry.set_sensitive(True)
			self.libvirtConf['auth_unix_rw_status'] = "activated"

	def on_radiobutton_auth_tcp_enable_toggled(self, widget, data=None):
		if widget.get_active() == False:
			# disable selected
			self.auth_tcp_entry.set_sensitive(False)
			self.libvirtConf['auth_tcp_status'] = "commented"
		else:
			# enable selected
			self.auth_tcp_entry.set_sensitive(True)
			self.libvirtConf['auth_tcp_status'] = "activated"

	def on_radiobutton_auth_tls_enable_toggled(self, widget, data=None):
		if widget.get_active() == False:
			# disable selected
			self.auth_tls_entry.set_sensitive(False)
			self.libvirtConf['auth_tls_status'] = "commented"
		else:
			# enable selected
			self.auth_tls_entry.set_sensitive(True)
			self.libvirtConf['auth_tls_status'] = "activated"

# TLS x509 certificate configuration

	def on_radiobutton_key_file_enable_toggled(self, widget, data=None):
		if widget.get_active() == False:
			# disable selected
			self.key_file_entry.set_sensitive(False)
			self.libvirtConf['key_file_status'] = "commented"
		else:
			# enable selected
			self.key_file_entry.set_sensitive(True)
			self.libvirtConf['key_file_status'] = "activated"

	def on_radiobutton_cert_file_enable_toggled(self, widget, data=None):
		if widget.get_active() == False:
			# disable selected
			self.cert_file_entry.set_sensitive(False)
			self.libvirtConf['cert_file_status'] = "commented"
		else:
			# enable selected
			self.cert_file_entry.set_sensitive(True)
			self.libvirtConf['cert_file_status'] = "activated"

	def on_radiobutton_ca_file_enable_toggled(self, widget, data=None):
		if widget.get_active() == False:
			# disable selected
			self.ca_file_entry.set_sensitive(False)
			self.libvirtConf['ca_file_status'] = "commented"
		else:
			# enable selected
			self.ca_file_entry.set_sensitive(True)
			self.libvirtConf['ca_file_status'] = "activated"

	def on_radiobutton_crl_file_enable_toggled(self, widget, data=None):
		if widget.get_active() == False:
			# disable selected
			self.crl_file_entry.set_sensitive(False)
			self.libvirtConf['crl_file_status'] = "commented"
		else:
			# enable selected
			self.crl_file_entry.set_sensitive(True)
			self.libvirtConf['crl_file_status'] = "activated"

# Authorization controls

	def on_radiobutton_tls_no_verify_certificate_enable_toggled(self, widget, data=None):
		if widget.get_active() == False:
			# disable selected
			self.tls_no_verify_certificate_entry.set_sensitive(False)
			self.libvirtConf['tls_no_verify_certificate_status'] = "commented"
		else:
			# enable selected
			self.tls_no_verify_certificate_entry.set_sensitive(True)
			self.libvirtConf['tls_no_verify_certificate_status'] = "activated"

	def on_radiobutton_tls_allowed_dn_list_enable_toggled(self, widget, data=None):
		if widget.get_active() == False:
			# disable selected
			self.tls_allowed_dn_list_entry.set_sensitive(False)
			self.libvirtConf['tls_allowed_dn_list_status'] = "commented"
		else:
			# enable selected
			self.tls_allowed_dn_list_entry.set_sensitive(True)
			self.libvirtConf['tls_allowed_dn_list_status'] = "activated"

	def on_radiobutton_sasl_allowed_username_list_enable_toggled(self, widget, data=None):
		if widget.get_active() == False:
			# disable selected
			self.sasl_allowed_username_list_entry.set_sensitive(False)
			self.libvirtConf['sasl_allowed_username_list_status'] = "commented"
		else:
			# enable selected
			self.sasl_allowed_username_list_entry.set_sensitive(True)
			self.libvirtConf['sasl_allowed_username_list_status'] = "activated"

# Processing controls

	def on_radiobutton_max_clients_enable_toggled(self, widget, data=None):
		if widget.get_active() == False:
			# disable selected
			self.max_clients_entry.set_sensitive(False)
			self.libvirtConf['max_clients_status'] = "commented"
		else:
			# enable selected
			self.max_clients_entry.set_sensitive(True)
			self.libvirtConf['max_clients_status'] = "activated"

	def on_radiobutton_min_workers_enable_toggled(self, widget, data=None):
		if widget.get_active() == False:
			# disable selected
			self.min_workers_entry.set_sensitive(False)
			self.libvirtConf['min_workers_status'] = "commented"
		else:
			# enable selected
			self.min_workers_entry.set_sensitive(True)
			self.libvirtConf['min_workers_status'] = "activated"

	def on_radiobutton_max_workers_enable_toggled(self, widget, data=None):		
		if widget.get_active() == False:
			# disable selected
			self.max_workers_entry.set_sensitive(False)
			self.libvirtConf['max_workers_status'] = "commented"
		else:
			# enable selected
			self.max_workers_entry.set_sensitive(True)
			self.libvirtConf['max_workers_status'] = "activated"

	def on_radiobutton_max_requests_enable_toggled(self, widget, data=None):
		if widget.get_active() == False:
			# disable selected
			self.max_requests_entry.set_sensitive(False)
			self.libvirtConf['max_requests_status'] = "commented"
		else:
			# enable selected
			self.max_requests_entry.set_sensitive(True)
			self.libvirtConf['max_requests_status'] = "activated"

	def on_radiobutton_max_client_requests_enable_toggled(self, widget, data=None):
		if widget.get_active() == False:
			# disable selected
			self.max_client_requests_entry.set_sensitive(False)
			self.libvirtConf['max_client_requests_status'] = "commented"
		else:
			# enable selected
			self.max_client_requests_entry.set_sensitive(True)
			self.libvirtConf['max_client_requests_status'] = "activated"

# Logging controls	

	def on_radiobutton_log_level_enable_toggled(self, widget, data=None):
		if widget.get_active() == False:
			# disable selected
			self.log_level_entry.set_sensitive(False)
			self.libvirtConf['log_level_status'] = "commented"
		else:
			# enable selected
			self.log_level_entry.set_sensitive(True)
			self.libvirtConf['log_level_status'] = "activated"

	def on_radiobutton_log_filters_enable_toggled(self, widget, data=None):
		if widget.get_active() == False:
			# disable selected
			self.log_filters_entry.set_sensitive(False)
			self.libvirtConf['log_filters_status'] = "commented"
		else:
			# enable selected
			self.log_filters_entry.set_sensitive(True)
			self.libvirtConf['log_filters_status'] = "activated"

	def on_radiobutton_log_outputs_enable_toggled(self, widget, data=None):	
		if widget.get_active() == False:
			# disable selected
			self.log_outputs_entry.set_sensitive(False)
			self.libvirtConf['log_outputs_status'] = "commented"
		else:
			# enable selected
			self.log_outputs_entry.set_sensitive(True)
			self.libvirtConf['log_outputs_status'] = "activated"

# Auditing

	def on_radiobutton_audit_level_enable_toggled(self, widget, data=None):
		if widget.get_active() == False:
			# disable selected
			self.audit_level_entry.set_sensitive(False)
			self.libvirtConf['audit_level_status'] = "commented"
		else:
			# enable selected
			self.audit_level_entry.set_sensitive(True)
			self.libvirtConf['audit_level_status'] = "activated"

	def on_radiobutton_audit_logging_enable_toggled(self, widget, data=None):
		if widget.get_active() == False:
			# disable selected
			self.audit_logging_entry.set_sensitive(False)
			self.libvirtConf['audit_logging_status'] = "commented"
		else:
			# enable selected
			self.audit_logging_entry.set_sensitive(True)
			self.libvirtConf['audit_logging_status'] = "activated"

# UUID of the host

	def on_radiobutton_host_uuid_enable_toggled(self, widget, data=None): 
		if widget.get_active() == False:
			# disable selected
			self.host_uuid_entry.set_sensitive(False)
			self.libvirtConf['host_uuid_status'] = "commented"
		else:
			# enable selected
			self.host_uuid_entry.set_sensitive(True)
			self.libvirtConf['host_uuid_status'] = "activated"

# Miscellaneous

	def on_radiobutton_save_image_format_enable_toggled(self, widget, data=None):
		if widget.get_active() == False:
			# disable selected
			self.save_image_format_entry.set_sensitive(False)
			self.libvirtConf['save_image_format_status'] = "commented"
		else:
			# enable selected
			self.save_image_format_entry.set_sensitive(True)
			self.libvirtConf['save_image_format_status'] = "activated"

############################ END CHECKBOX #####################################
