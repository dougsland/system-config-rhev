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

def loadLibvirtPage(self):

	# libvirt - listen_addr - glade
	self.radiobutton_listen_addr_disable = self.builder.get_object("radiobutton_listen_addr_disable")
	self.radiobutton_listen_addr_enable  = self.builder.get_object("radiobutton_listen_addr_enable")
	self.listen_addr_entry = self.builder.get_object("listen_addr_entry")

	# libvirt - listen_tls - glade
	self.radiobutton_listen_tls_disable = self.builder.get_object("radiobutton_listen_tls_disable")
	self.radiobutton_listen_tls_enable  = self.builder.get_object("radiobutton_listen_tls_enable")
	self.listen_tls_entry = self.builder.get_object("listen_tls_entry")

	# libvirt - unix_sock_group	
	self.radiobutton_unix_sock_group_disable = self.builder.get_object("radiobutton_unix_sock_group_disable")
	self.radiobutton_unix_sock_group_enable  = self.builder.get_object("radiobutton_unix_sock_group_enable")
	self.unix_sock_group_entry  = self.builder.get_object("unix_sock_group_entry")

	# libvirt - unix_sock_rw_perms
	self.radiobutton_unix_sock_rw_perms_disable = self.builder.get_object("radiobutton_unix_sock_rw_perms_disable")
	self.radiobutton_unix_sock_rw_perms_enable  = self.builder.get_object("radiobutton_unix_sock_rw_perms_enable")
	self.unix_sock_rw_perms_entry  = self.builder.get_object("unix_sock_rw_perms_entry")

	# libvirt - auth_unix_rw
	self.radiobutton_auth_unix_rw_disable = self.builder.get_object("radiobutton_auth_unix_rw_disable")
	self.radiobutton_auth_unix_rw_enable  = self.builder.get_object("radiobutton_auth_unix_rw_enable")
	self.auth_unix_rw_entry  = self.builder.get_object("auth_unix_rw_entry")

	# libvirt - save_image_format
	self.radiobutton_save_image_format_disable = self.builder.get_object("radiobutton_save_image_format_disable")
	self.radiobutton_save_image_format_enable  = self.builder.get_object("radiobutton_save_image_format_enable")
	self.save_image_format_entry  = self.builder.get_object("save_image_format_entry")
	
	# libvirt - log_outputs
	self.radiobutton_log_outputs_disable = self.builder.get_object("radiobutton_log_outputs_disable")
	self.radiobutton_log_outputs_enable  = self.builder.get_object("radiobutton_log_outputs_enable")
	self.log_outputs_entry  = self.builder.get_object("log_outputs_entry")
	
	# libvirt - log_filters
	self.radiobutton_log_filters_disable = self.builder.get_object("radiobutton_log_filters_disable")
	self.radiobutton_log_filters_enable  = self.builder.get_object("radiobutton_log_filters_enable")
	self.log_filters_entry  = self.builder.get_object("log_filters_entry")

	# libvirt - auth_tcp
	self.radiobutton_auth_tcp_disable = self.builder.get_object("radiobutton_auth_tcp_disable")
	self.radiobutton_auth_tcp_enable  = self.builder.get_object("radiobutton_auth_tcp_enable")
	self.auth_tcp_entry  = self.builder.get_object("auth_tcp_entry")

	# libvirt - listen_tcp
	self.radiobutton_listen_tcp_disable = self.builder.get_object("radiobutton_listen_tcp_disable")
	self.radiobutton_listen_tcp_enable  = self.builder.get_object("radiobutton_listen_tcp_enable")
	self.listen_tcp_entry  = self.builder.get_object("listen_tcp_entry")

	# libvirt - tcp_port
	self.radiobutton_tcp_port_disable = self.builder.get_object("radiobutton_tcp_port_disable")
	self.radiobutton_tcp_port_enable  = self.builder.get_object("radiobutton_tcp_port_enable")
	self.tcp_port_entry  = self.builder.get_object("tcp_port_entry")

	# libvirt - tls_port
	self.radiobutton_tls_port_disable = self.builder.get_object("radiobutton_tls_port_disable")
	self.radiobutton_tls_port_enable  = self.builder.get_object("radiobutton_tls_port_enable")
	self.tls_port_entry  = self.builder.get_object("tls_port_entry")

	# libvirt - mdns_name
	self.radiobutton_mdns_name_disable = self.builder.get_object("radiobutton_mdns_name_disable")
	self.radiobutton_mdns_name_enable  = self.builder.get_object("radiobutton_mdns_name_enable")
	self.mdns_name_entry  = self.builder.get_object("mdns_name_entry")

	# libvirt - mdns_adv
	self.radiobutton_mdns_adv_disable = self.builder.get_object("radiobutton_mdns_adv_disable")
	self.radiobutton_mdns_adv_enable  = self.builder.get_object("radiobutton_mdns_adv_enable")
	self.mdns_adv_entry  = self.builder.get_object("mdns_adv_entry")

	# libvirt - unix_sock_ro_perms
	self.radiobutton_unix_sock_ro_perms_disable = self.builder.get_object("radiobutton_unix_sock_ro_perms_disable")
	self.radiobutton_unix_sock_ro_perms_enable  = self.builder.get_object("radiobutton_unix_sock_ro_perms_enable")
	self.unix_sock_ro_perms_entry  = self.builder.get_object("unix_sock_ro_perms_entry")

	# libvirt - unix_sock_dir
	self.radiobutton_unix_sock_dir_disable = self.builder.get_object("radiobutton_unix_sock_dir_disable")
	self.radiobutton_unix_sock_dir_enable  = self.builder.get_object("radiobutton_unix_sock_dir_enable")
	self.unix_sock_dir_entry  = self.builder.get_object("unix_sock_dir_entry")

	# libvirt - auth_unix_ro
	self.radiobutton_auth_unix_ro_disable = self.builder.get_object("radiobutton_auth_unix_ro_disable")
	self.radiobutton_auth_unix_ro_enable  = self.builder.get_object("radiobutton_auth_unix_ro_enable")
	self.auth_unix_ro_entry  = self.builder.get_object("auth_unix_ro_entry")

	# libvirt - auth_unix_rw
	self.radiobutton_auth_unix_rw_disable = self.builder.get_object("radiobutton_auth_unix_rw_disable")
	self.radiobutton_auth_unix_rw_enable  = self.builder.get_object("radiobutton_auth_unix_rw_enable")
	self.auth_unix_rw_entry  = self.builder.get_object("auth_unix_rw_entry")

	# libvirt - auth_tls
	self.radiobutton_auth_tls_disable = self.builder.get_object("radiobutton_auth_tls_disable")
	self.radiobutton_auth_tls_enable  = self.builder.get_object("radiobutton_auth_tls_enable")
	self.auth_tls_entry  = self.builder.get_object("auth_tls_entry")

	# libvirt - key_file
	self.radiobutton_key_file_disable = self.builder.get_object("radiobutton_key_file_disable")
	self.radiobutton_key_file_enable  = self.builder.get_object("radiobutton_key_file_enable")
	self.key_file_entry  = self.builder.get_object("key_file_entry")

	# libvirt - cert_file
	self.radiobutton_cert_file_disable = self.builder.get_object("radiobutton_cert_file_disable")
	self.radiobutton_cert_file_enable  = self.builder.get_object("radiobutton_cert_file_enable")
	self.cert_file_entry  = self.builder.get_object("cert_file_entry")

	# libvirt - ca_file
	self.radiobutton_ca_file_disable = self.builder.get_object("radiobutton_ca_file_disable")
	self.radiobutton_ca_file_enable  = self.builder.get_object("radiobutton_ca_file_enable")
	self.ca_file_entry  = self.builder.get_object("ca_file_entry")

	# libvirt - crl_file
	self.radiobutton_crl_file_disable = self.builder.get_object("radiobutton_crl_file_disable")
	self.radiobutton_crl_file_enable  = self.builder.get_object("radiobutton_crl_file_enable")
	self.crl_file_entry  = self.builder.get_object("crl_file_entry")

	# libvirt - tls_no_verify_certificate
	self.radiobutton_tls_no_verify_certificate_disable = self.builder.get_object("radiobutton_tls_no_verify_certificate_disable")
	self.radiobutton_tls_no_verify_certificate_enable  = self.builder.get_object("radiobutton_tls_no_verify_certificate_enable")
	self.tls_no_verify_certificate_entry  = self.builder.get_object("tls_no_verify_certificate_entry")

	# libvirt - tls_allowed_dn_list
	self.radiobutton_tls_allowed_dn_list_disable = self.builder.get_object("radiobutton_tls_allowed_dn_list_disable")
	self.radiobutton_tls_allowed_dn_list_enable  = self.builder.get_object("radiobutton_tls_allowed_dn_list_enable")
	self.tls_allowed_dn_list_entry  = self.builder.get_object("tls_allowed_dn_list_entry")

	# libvirt - sasl_allowed_username_list
	self.radiobutton_sasl_allowed_username_list_disable = self.builder.get_object("radiobutton_sasl_allowed_username_list_disable")
	self.radiobutton_sasl_allowed_username_list_enable  = self.builder.get_object("radiobutton_sasl_allowed_username_list_enable")
	self.sasl_allowed_username_list_entry  = self.builder.get_object("sasl_allowed_username_list_entry")

	# libvirt - max_clients
	self.radiobutton_max_clients_disable = self.builder.get_object("radiobutton_max_clients_disable")
	self.radiobutton_max_clients_enable  = self.builder.get_object("radiobutton_max_clients_enable")
	self.max_clients_entry  = self.builder.get_object("max_clients_entry")

	# libvirt - min_workers
	self.radiobutton_min_workers_disable = self.builder.get_object("radiobutton_min_workers_disable")
	self.radiobutton_min_workers_enable  = self.builder.get_object("radiobutton_min_workers_enable")
	self.min_workers_entry  = self.builder.get_object("min_workers_entry")

	# libvirt - max_workers
	self.radiobutton_max_workers_disable = self.builder.get_object("radiobutton_max_workers_disable")
	self.radiobutton_max_workers_enable  = self.builder.get_object("radiobutton_max_workers_enable")
	self.max_workers_entry  = self.builder.get_object("max_workers_entry")

	# libvirt - max_requests
	self.radiobutton_max_requests_disable = self.builder.get_object("radiobutton_max_requests_disable")
	self.radiobutton_max_requests_enable  = self.builder.get_object("radiobutton_max_requests_enable")
	self.max_requests_entry  = self.builder.get_object("max_requests_entry")

	# libvirt - max_client_requests
	self.radiobutton_max_client_requests_disable = self.builder.get_object("radiobutton_max_client_requests_disable")
	self.radiobutton_max_client_requests_enable  = self.builder.get_object("radiobutton_max_client_requests_enable")
	self.max_client_requests_entry  = self.builder.get_object("max_client_requests_entry")

	# libvirt - log_level
	self.radiobutton_log_level_disable = self.builder.get_object("radiobutton_log_level_disable")
	self.radiobutton_log_level_enable  = self.builder.get_object("radiobutton_log_level_enable")
	self.log_level_entry  = self.builder.get_object("log_level_entry")

	# libvirt - audit_logging
	self.radiobutton_audit_logging_disable = self.builder.get_object("radiobutton_audit_logging_disable")
	self.radiobutton_audit_logging_enable  = self.builder.get_object("radiobutton_audit_logging_enable")
	self.audit_logging_entry  = self.builder.get_object("audit_logging_entry")

	# libvirt - audit_level
	self.radiobutton_audit_level_disable = self.builder.get_object("radiobutton_audit_level_disable")
	self.radiobutton_audit_level_enable  = self.builder.get_object("radiobutton_audit_level_enable")
	self.audit_level_entry  = self.builder.get_object("audit_level_entry")

	# libvirt - host_uuids
	self.radiobutton_host_uuid_disable = self.builder.get_object("radiobutton_host_uuid_disable")
	self.radiobutton_host_uuid_enable  = self.builder.get_object("radiobutton_host_uuid_enable")
	self.host_uuid_entry  = self.builder.get_object("host_uuid_entry")

def setLibvirtPage(self, libvirt):
	# Setting log_outputs
	if (libvirt.has_key('log_outputs') == False) and \
			(libvirt.has_key('logs_output_status') == False):
		self.log_outputs_entry.set_sensitive(False)
		self.radiobutton_log_outputs_disable.set_active(True)
	else:
		self.log_outputs_entry.set_text(libvirt['log_outputs'])
		if libvirt['log_outputs_status'] == "commented":
			self.log_outputs_entry.set_sensitive(False)
			self.radiobutton_log_outputs_disable.set_active(True)

	# Setting save_image_format
	if (libvirt.has_key('save_image_format') == False) and \
			(libvirt.has_key('save_image_format_status') == False):
		self.save_image_format_entry.set_sensitive(False)
		self.radiobutton_save_image_format_disable.set_active(True)
	else:
		self.save_image_format_entry.set_text(libvirt['save_image_format'])
		if libvirt['save_image_format_status'] == "commented":
			self.save_image_format_entry.set_sensitive(False)
			self.radiobutton_save_image_format_disable.set_active(True)

	# Setting auth_unix_rw
	if (libvirt.has_key('auth_unix_rw') == False) and \
			(libvirt.has_key('auth_unix_rw_status') == False):
		self.auth_unix_rw_entry.set_sensitive(False)
		self.radiobutton_auth_unix_rw_disable.set_active(True)
	else:
		self.auth_unix_rw_entry.set_text(libvirt['auth_unix_rw'])
		if libvirt['auth_unix_rw_status'] == "commented":
			self.auth_unix_rw_entry.set_sensitive(False)
			self.radiobutton_auth_unix_rw_disable.set_active(True)

	# Setting unix_sock_rw_perms
	if (libvirt.has_key('unix_sock_rw_perms') == False) and \
			(libvirt.has_key('unix_sock_rw_perms_status') == False):
		self.unix_sock_rw_perms_entry.set_sensitive(False)
		self.radiobutton_unix_sock_rw_perms_disable.set_active(True)
	else:
		self.unix_sock_rw_perms_entry.set_text(libvirt['unix_sock_rw_perms'])
		if libvirt['unix_sock_rw_perms_status'] == "commented":
			self.unix_sock_rw_perms_entry.set_sensitive(False)
			self.radiobutton_unix_sock_rw_perms_disable.set_active(True)

	# Setting listen_addr
	if (libvirt.has_key('listen_addr') == False) and \
			(libvirt.has_key('listen_addr_status') == False):
		self.listen_addr_entry.set_sensitive(False)
		self.radiobutton_listen_addr_disable.set_active(True)
	else:
		self.listen_addr_entry.set_text(libvirt['listen_addr'])
		if libvirt['listen_addr_status'] == "commented":
			self.listen_addr_entry.set_sensitive(False)
			self.radiobutton_listen_addr_disable.set_active(True)

	# Setting listen_tls
	if (libvirt.has_key('listen_tls') == False) and \
			(libvirt.has_key('listen_tls_status') == False):
		self.listen_tls_entry.set_sensitive(False)
		self.radiobutton_listen_tls_disable.set_active(True)
	else:
		self.listen_tls_entry.set_text(libvirt['listen_tls'])
		if libvirt['listen_tls_status'] == "commented":
			self.listen_tls_entry.set_sensitive(False)
			self.radiobutton_listen_tls_disable.set_active(True)
			
	# Setting unix_sock_group
	if (libvirt.has_key('unix_sock_group') == False) and \
			(libvirt.has_key('unix_sock_group_status') == False):
		self.unix_sock_group_entry.set_sensitive(False)
		self.radiobutton_unix_sock_group_disable.set_active(True)
	else:
		self.unix_sock_group_entry.set_text(libvirt['unix_sock_group'])
		if libvirt['unix_sock_group_status'] == "commented":
			self.unix_sock_group_entry.set_sensitive(False)
			self.radiobutton_unix_sock_group_disable.set_active(True)

	# Setting log_filters
	if (libvirt.has_key('log_filters') == False) and \
			(libvirt.has_key('log_filters_status') == False):
		self.log_filters_entry.set_sensitive(False)
		self.radiobutton_log_filters_disable.set_active(True)
	else:
		self.log_filters_entry.set_text(libvirt['log_filters'])
		if libvirt['log_filters_status'] == "commented":
			self.log_filters_entry.set_sensitive(False)
			self.radiobutton_log_filters_disable.set_active(True)

	# Setting auth_tcp
	if (libvirt.has_key('auth_tcp') == False) and \
			(libvirt.has_key('auth_tcp_status') == False):
		self.auth_tcp_entry.set_sensitive(False)
		self.radiobutton_auth_tcp_disable.set_active(True)
	else:
		self.auth_tcp_entry.set_text(libvirt['auth_tcp'])
		if libvirt['auth_tcp_status'] == "commented":
			self.auth_tcp_entry.set_sensitive(False)
			self.radiobutton_auth_tcp_disable.set_active(True)

	# Setting listen_tcp
	if (libvirt.has_key('listen_tcp') == False) and \
			(libvirt.has_key('listen_tcp_status') == False):
		self.listen_tcp_entry.set_sensitive(False)
		self.radiobutton_listen_tcp_disable.set_active(True)
	else:
		self.listen_tcp_entry.set_text(libvirt['listen_tcp'])
		if libvirt['listen_tcp_status'] == "commented":
			self.listen_tcp_entry.set_sensitive(False)
			self.radiobutton_listen_tcp_disable.set_active(True)

	# Setting tcp_port
	if (libvirt.has_key('tcp_port') == False) and \
			(libvirt.has_key('tcp_port_status') == False):
		self.tcp_port_entry.set_sensitive(False)
		self.radiobutton_tcp_port_disable.set_active(True)
	else:
		self.tcp_port_entry.set_text(libvirt['tcp_port'])
		if libvirt['tcp_port_status'] == "commented":
			self.tcp_port_entry.set_sensitive(False)
			self.radiobutton_tcp_port_disable.set_active(True)

	# Setting tls_port
	if (libvirt.has_key('tls_port') == False) and \
			(libvirt.has_key('tls_port_status') == False):
		self.tls_port_entry.set_sensitive(False)
		self.radiobutton_tls_port_disable.set_active(True)
	else:
		self.tls_port_entry.set_text(libvirt['tls_port'])
		if libvirt['tls_port_status'] == "commented":
			self.tls_port_entry.set_sensitive(False)
			self.radiobutton_tls_port_disable.set_active(True)

	# Setting mdns_adv
	if (libvirt.has_key('mdns_adv') == False) and \
			(libvirt.has_key('mdns_adv_status') == False):
		self.mdns_adv_entry.set_sensitive(False)
		self.radiobutton_mdns_adv_disable.set_active(True)
	else:
		self.mdns_adv_entry.set_text(libvirt['mdns_adv'])
		if libvirt['mdns_adv_status'] == "commented":
			self.mdns_adv_entry.set_sensitive(False)
			self.radiobutton_mdns_adv_disable.set_active(True)

	# Setting mdns_name
	if (libvirt.has_key('mdns_name') == False) and \
			(libvirt.has_key('mdns_name_status') == False):
		self.mdns_name_entry.set_sensitive(False)
		self.radiobutton_mdns_name_disable.set_active(True)
	else:
		self.mdns_name_entry.set_text(libvirt['mdns_name'])
		if libvirt['mdns_name_status'] == "commented":
			self.mdns_name_entry.set_sensitive(False)
			self.radiobutton_mdns_name_disable.set_active(True)

	# Setting unix_sock_dir
	if (libvirt.has_key('unix_sock_dir') == False) and \
			(libvirt.has_key('unix_sock_dir_status') == False):
		self.unix_sock_dir_entry.set_sensitive(False)
		self.radiobutton_unix_sock_dir_disable.set_active(True)
	else:
		self.unix_sock_dir_entry.set_text(libvirt['unix_sock_dir'])
		if libvirt['unix_sock_dir_status'] == "commented":
			self.unix_sock_dir_entry.set_sensitive(False)
			self.radiobutton_unix_sock_dir_disable.set_active(True)

	# Setting unix_sock_ro_perms
	if (libvirt.has_key('unix_sock_ro_perms') == False) and \
			(libvirt.has_key('unix_sock_ro_perms_status') == False):
		self.unix_sock_ro_perms_entry.set_sensitive(False)
		self.radiobutton_unix_sock_ro_perms_disable.set_active(True)
	else:
		self.unix_sock_ro_perms_entry.set_text(libvirt['unix_sock_ro_perms'])
		if libvirt['unix_sock_ro_perms_status'] == "commented":
			self.unix_sock_ro_perms_entry.set_sensitive(False)
			self.radiobutton_unix_sock_ro_perms_disable.set_active(True)

	# Setting auth_unix_ro
	if (libvirt.has_key('auth_unix_ro') == False) and \
			(libvirt.has_key('auth_unix_ro_status') == False):
		self.auth_unix_ro_entry.set_sensitive(False)
		self.radiobutton_auth_unix_ro_disable.set_active(True)
	else:
		self.auth_unix_ro_entry.set_text(libvirt['auth_unix_ro'])
		if libvirt['auth_unix_ro_status'] == "commented":
			self.auth_unix_ro_entry.set_sensitive(False)
			self.radiobutton_auth_unix_ro_disable.set_active(True)

	# Setting auth_unix_rw
	if (libvirt.has_key('auth_unix_rw') == False) and \
			(libvirt.has_key('auth_unix_rw_status') == False):
		self.auth_unix_rw_entry.set_sensitive(False)
		self.radiobutton_auth_unix_rw_disable.set_active(True)
	else:
		self.auth_unix_rw_entry.set_text(libvirt['auth_unix_rw'])
		if libvirt['auth_unix_rw_status'] == "commented":
			self.auth_unix_rw_entry.set_sensitive(False)
			self.radiobutton_auth_unix_rw_disable.set_active(True)

	# Setting auth_tls
	if (libvirt.has_key('auth_tls') == False) and \
			(libvirt.has_key('auth_tls_status') == False):
		self.auth_tls_entry.set_sensitive(False)
		self.radiobutton_auth_tls_disable.set_active(True)
	else:
		self.auth_tls_entry.set_text(libvirt['auth_tls'])
		if libvirt['auth_tls_status'] == "commented":
			self.auth_tls_entry.set_sensitive(False)
			self.radiobutton_auth_tls_disable.set_active(True)

	# Setting key_file
	if (libvirt.has_key('key_file') == False) and \
			(libvirt.has_key('key_file_status') == False):
		self.key_file_entry.set_sensitive(False)
		self.radiobutton_key_file_disable.set_active(True)
	else:
		self.key_file_entry.set_text(libvirt['key_file'])
		if libvirt['key_file_status'] == "commented":
			self.key_file_entry.set_sensitive(False)
			self.radiobutton_key_file_disable.set_active(True)

	# Setting cert_file
	if (libvirt.has_key('cert_file') == False) and \
			(libvirt.has_key('cert_file_status') == False):
		self.cert_file_entry.set_sensitive(False)
		self.radiobutton_cert_file_disable.set_active(True)
	else:
		self.cert_file_entry.set_text(libvirt['cert_file'])
		if libvirt['cert_file_status'] == "commented":
			self.cert_file_entry.set_sensitive(False)
			self.radiobutton_cert_file_disable.set_active(True)

	# Setting ca_file
	if (libvirt.has_key('ca_file') == False) and \
			(libvirt.has_key('ca_file_status') == False):
		self.ca_file_entry.set_sensitive(False)
		self.radiobutton_ca_file_disable.set_active(True)
	else:
		self.ca_file_entry.set_text(libvirt['ca_file'])
		if libvirt['ca_file_status'] == "commented":
			self.ca_file_entry.set_sensitive(False)
			self.radiobutton_ca_file_disable.set_active(True)

	# Setting crl_file
	if (libvirt.has_key('crl_file') == False) and \
			(libvirt.has_key('crl_file_status') == False):
		self.crl_file_entry.set_sensitive(False)
		self.radiobutton_crl_file_disable.set_active(True)
	else:
		self.crl_file_entry.set_text(libvirt['crl_file'])
		if libvirt['crl_file_status'] == "commented":
			self.crl_file_entry.set_sensitive(False)
			self.radiobutton_crl_file_disable.set_active(True)

	# Setting tls_no_verify_certificate
	if (libvirt.has_key('tls_no_verify_certificate') == False) and \
			(libvirt.has_key('tls_no_verify_certificate_status') == False):
		self.tls_no_verify_certificate_entry.set_sensitive(False)
		self.radiobutton_tls_no_verify_certificate_disable.set_active(True)
	else:
		self.tls_no_verify_certificate_entry.set_text(libvirt['tls_no_verify_certificate'])
		if libvirt['tls_no_verify_certificate_status'] == "commented":
			self.tls_no_verify_certificate_entry.set_sensitive(False)
			self.radiobutton_tls_no_verify_certificate_disable.set_active(True)

	# Setting tls_allowed_dn_list
	if (libvirt.has_key('tls_allowed_dn_list') == False) and \
			(libvirt.has_key('tls_allowed_dn_list_status') == False):
		self.tls_allowed_dn_list_entry.set_sensitive(False)
		self.radiobutton_tls_allowed_dn_list_disable.set_active(True)
	else:
		self.tls_allowed_dn_list_entry.set_text(libvirt['tls_allowed_dn_list'])
		if libvirt['tls_allowed_dn_list_status'] == "commented":
			self.tls_allowed_dn_list_entry.set_sensitive(False)
			self.radiobutton_tls_allowed_dn_list_disable.set_active(True)

	# Setting sasl_allowed_username_list
	if (libvirt.has_key('sasl_allowed_username_list') == False) and \
			(libvirt.has_key('sasl_allowed_username_list_status') == False):
		self.sasl_allowed_username_list_entry.set_sensitive(False)
		self.radiobutton_sasl_allowed_username_list_disable.set_active(True)
	else:
		self.sasl_allowed_username_list_entry.set_text(libvirt['sasl_allowed_username_list'])
		if libvirt['sasl_allowed_username_list_status'] == "commented":
			self.sasl_allowed_username_list_entry.set_sensitive(False)
			self.radiobutton_sasl_allowed_username_list_disable.set_active(True)

	# Setting max_clients
	if (libvirt.has_key('max_clients') == False) and \
			(libvirt.has_key('max_clients_status') == False):
		self.max_clients_entry.set_sensitive(False)
		self.radiobutton_max_clients_disable.set_active(True)
	else:
		self.max_clients_entry.set_text(libvirt['max_clients'])
		if libvirt['max_clients_status'] == "commented":
			self.max_clients_entry.set_sensitive(False)
			self.radiobutton_max_clients_disable.set_active(True)

	# Setting min_workers
	if (libvirt.has_key('min_workers') == False) and \
			(libvirt.has_key('min_workers_status') == False):
		self.min_workers_entry.set_sensitive(False)
		self.radiobutton_min_workers_disable.set_active(True)
	else:
		self.min_workers_entry.set_text(libvirt['min_workers'])
		if libvirt['min_workers_status'] == "commented":
			self.min_workers_entry.set_sensitive(False)
			self.radiobutton_min_workers_disable.set_active(True)

	# Setting max_workers
	if (libvirt.has_key('max_workers') == False) and \
			(libvirt.has_key('max_workers_status') == False):
		self.max_workers_entry.set_sensitive(False)
		self.radiobutton_max_workers_disable.set_active(True)
	else:
		self.max_workers_entry.set_text(libvirt['max_workers'])
		if libvirt['max_workers_status'] == "commented":
			self.max_workers_entry.set_sensitive(False)
			self.radiobutton_max_workers_disable.set_active(True)

	# Setting max_requests
	if (libvirt.has_key('max_requests') == False) and \
			(libvirt.has_key('max_requests_status') == False):
		self.max_requests_entry.set_sensitive(False)
		self.radiobutton_max_requests_disable.set_active(True)
	else:
		self.max_requests_entry.set_text(libvirt['max_requests'])
		if libvirt['max_requests_status'] == "commented":
			self.max_requests_entry.set_sensitive(False)
			self.radiobutton_max_requests_disable.set_active(True)

	# Setting max_client_requests
	if (libvirt.has_key('max_client_requests') == False) and \
			(libvirt.has_key('max_client_requests_status') == False):
		self.max_client_requests_entry.set_sensitive(False)
		self.radiobutton_max_client_requests_disable.set_active(True)
	else:
		self.max_client_requests_entry.set_text(libvirt['max_client_requests'])
		if libvirt['max_client_requests_status'] == "commented":
			self.max_client_requests_entry.set_sensitive(False)
			self.radiobutton_max_client_requests_disable.set_active(True)

	# Setting log_level
	if (libvirt.has_key('log_level') == False) and \
			(libvirt.has_key('log_level_status') == False):
		self.log_level_entry.set_sensitive(False)
		self.radiobutton_log_level_disable.set_active(True)
	else:
		self.log_level_entry.set_text(libvirt['log_level'])
		if libvirt['log_level_status'] == "commented":
			self.log_level_entry.set_sensitive(False)
			self.radiobutton_log_level_disable.set_active(True)

	# Setting audit_logging
	if (libvirt.has_key('audit_logging') == False) and \
			(libvirt.has_key('audit_logging_status') == False):
		self.audit_logging_entry.set_sensitive(False)
		self.radiobutton_audit_logging_disable.set_active(True)
	else:
		self.audit_logging_entry.set_text(libvirt['audit_logging'])
		if libvirt['audit_logging_status'] == "commented":
			self.audit_logging_entry.set_sensitive(False)
			self.radiobutton_audit_logging_disable.set_active(True)

	# Setting audit_level
	if (libvirt.has_key('audit_level') == False) and \
			(libvirt.has_key('audit_level_status') == False):
		self.audit_level_entry.set_sensitive(False)
		self.radiobutton_audit_level_disable.set_active(True)
	else:
		self.audit_level_entry.set_text(libvirt['audit_level'])
		if libvirt['audit_level_status'] == "commented":
			self.audit_level_entry.set_sensitive(False)
			self.radiobutton_audit_level_disable.set_active(True)

	# host_uuids
	if (libvirt.has_key('host_uuid') == False) and \
			(libvirt.has_key('host_uuid_status') == False):
		self.host_uuid_entry.set_sensitive(False)
		self.radiobutton_host_uuid_disable.set_active(True)
	else:
		self.host_uuid_entry.set_text(libvirt['host_uuid'])
		if libvirt['host_uuid_status'] == "commented":
			self.host_uuid_entry.set_sensitive(False)
			self.radiobutton_host_uuid_disable.set_active(True)
