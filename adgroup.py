from __future__ import (absolute_import, division, print_function)
__metaclass__ = type

DOCUMENTATION = r"""
    name: adgroup
    plugin_type: inventory
    author:
        - Matthew Howle <matthew@howle.org>
    short_description: Active Directory inventory source
    requirements:
        - python >= 2.7
        - ldap3
    optional:
        - gssapi
    description:
        - Read inventory from Active Directory group memberships.
        - Uses ad.(yml|yaml) YAML configuration file to configure the inventory plugin.
        - If no configuration value is assigned for the server or base, it will auto-detect.
        - If no username is defined, Kerberos + GSSAPI will be used to connect to the server.
    options:
        plugin:
            description: Marks this as an instance of the 'adgroup' plugin.
            required: true
            choices: ['adgroup']
        server:
            description: The Active Directory server name.  If null, auto-detected by dnspython
            required: false
            type: str
            default: null
        port:
            description: Active Directory port. Using port 636 automatically enables SSL.
            required: false
            type: int
            default: 389
        base:
            description: Starting point for the search. If null, the default naming context will be used.
            required: false
            type: str
            default: null
        scope:
            description: Scope of the search
            required: false
            default: subtree
            choices: ['base', 'level', 'subtree']
        username:
            description: Username to bind as. It can be the distinguishedname of the user, or "SHORTDOMAIN\user".  If defined, the connection will use a simple bind. Otherwise, Kerberos+GSSAPI will be used.
            required: false
            type: str
            default: null
        password:
            description: Username's password. Must be defined if *username* is also defined.
            required: false
            type: str
            default: null
        root group:
            description: Active Directory group that contains all other groups as members.  If not a distinguished name, it will be searched under *base* using *scope* as the search scope.
            required: false
            type: str
            default: ansible-roles
        group marker:
            description: Marker that will be removed from group name (e.g. 'ansible-role-http' becomes 'http')
            required: false
            type: str
            default: ansible-role-
        var attribute:
            description: LDAP attribute to load as YAML for group/host-specific variables.
            required: false
            type: str
            default: null
"""

EXAMPLES = r"""
# Minimal example. 'server' and 'base' will be detected.
# kerberos/gssapi will be used to connect.
plugin: adgroup

# Example with all values assigned
plugin: adgroup
server: dc.example.com
port: 636
base: OU=Groups,DC=example,DC=com
username: EXAMPLE\ExampleUser  # or distinguishedname
password: "SecurePassword"
root group: ansible-roles
group_marker: ansible-roles-
import vars: yes
var attribute: info
"""
import socket
import struct

from ansible.errors import AnsibleError
from ansible.plugins.inventory import BaseInventoryPlugin

import yaml

from ldap3 import BASE, Connection, DSA, LEVEL, SASL, Server, SUBTREE
from ldap3.core.exceptions import LDAPSocketOpenError, LDAPAttributeError

try:
    import dns.resolver as dns_resolver
except ImportError:
    dns_resolver = None

SCOPES = {
    'base': BASE,
    'level': LEVEL,
    'subtree': SUBTREE
}

class InventoryModule(BaseInventoryPlugin):
    NAME = 'adgroup'

    def __init__(self):
        super(InventoryModule, self).__init__()
        self._connection = None

    def verify_file(self, path):
        if super(InventoryModule, self).verify_file(path):
            exts = ('.yaml', '.yml')
            return any((path.endswith(ext) for ext in exts))
        return False

    def parse(self, inventory, loader, path, cache=True):
        super(InventoryModule, self).parse(inventory, loader, path)
        self.config_data = self._read_config_data(path)
        self._create_client()
        self._build_inventory()

    def _get_option(self, option):
        value = self.get_option(option)

        if value:
            if option == "scope":
                return SCOPES.get(value)
            return value

        # attempt to auto-detect option
        if option == "server":
            value = self._find_closest_dc()
            if value:
                self.set_option("server", value)
            else:
                value = self._get_domain()
                if value:
                    self.set_option("server", value)
                else:
                    raise AnsibleError("Server name could not be determined")
        return value

    def _get_connection_args(self):
        username = self._get_option("username")
        password = self._get_option("password")

        if username:
            if password:
                return {"user": username, "password": password}
            else:
                raise AnsibleError("Username defined without a password")
        return {"authentication": SASL, "sasl_mechanism": "GSSAPI"}

    def _create_client(self):
        if self._connection:
            return self._connection

        server = self._get_option("server")
        port = self._get_option("port")
        base = self._get_option("base")

        if server:
            sargs = {"use_ssl": True} if port == 636 else {}
            ldap_server = Server(server, port=port, get_info=DSA, **sargs)
            cargs = self._get_connection_args()

            self._connection = Connection(ldap_server, **cargs)
            self._connection.open()
            self._connection.start_tls()
            self._connection.bind()

            if base is None:
                result = self._connection.search(search_base="",
                        search_filter="(dnsHostName=%s)" % server,
                        search_scope=BASE, attributes=["defaultNamingContext"])
                if result:
                    base = (self._connection.server
                               .info.other["defaultNamingContext"][0])
                    self.set_option("base", base)
        else:
            raise AnsibleError("Server name could not be determined")

    def _get_domain(self):
        fqdn = socket.getfqnd()
        return fqdn[fqdn.find(".")+1:] if "." in fqdn else None


    def _find_closest_dc(self):
        from multiprocessing.pool import ThreadPool as Pool
        def ldap_ping(args):
            server, cargs = args
            try:
                with Connection(Server(server, get_info=DSA), **cargs) as connection:
                    result = connection.search(search_base="",
                            search_filter="(&(NtVer=\\06\\00\\00\\00)(AAC=\\00\\00\\00\\00))",
                            search_scope=BASE, attributes=["netlogon"])
                    if result:
                        if "netlogon" in connection.entries[0]:
                            data = connection.entries[0].netlogon.value
                            flags = struct.unpack("<i", data[4:8])[0]
                            if flags & 0x00000080:  # DS_CLOSEST_FLAG
                                return server
            except LDAPSocketOpenError:
                return None
            return None
        # === ldap_ping

        if dns_resolver is None:
            return self._get_domain()

        ldap_servers = []

        for server in dns_resolver.query("_ldap._tcp", "SRV"):
            ldap_servers.append(server)

        if ldap_servers:
            ldap_servers.sort(key=lambda x: (x.priority, x.weight))

            cargs = self._get_connection_args()
            pool = Pool(processes=len(ldap_servers))
            results = pool.map(ldap_ping,
                    [(str(server.target)[:-1], cargs) for server in ldap_servers])
            pool.close()

            closest = ([server for server in results if server] or (None,))[0]

            if closest is None:
                return str(ldap_servers[0].target)[:-1]
            return closest

    def _set_variables(self, entity, values):
        if isinstance(values, dict):
            for k, v in values.items():
                self.inventory.set_variable(entity, k, v)

    def _build_inventory(self):
        if self._connection is None:
            self._create_client()

        base = self._get_option("base")
        root_group_name = self._get_option("root group")
        scope = self._get_option("scope")

        var_attribute = self._get_option("var attribute")
        import_vars = var_attribute is not None

        xattrib = [var_attribute] if import_vars else []

        if any([root_group_name.lower().startswith(v) for v in ("cn=", "ou=")]):
            result = self._connection.search(
                search_base=root_group_name,
                search_filter="(objectClass=group)",
                search_scope=BASE, attributes=["member"] + xattrib)
        else:
            result =  self._connection.search(
                search_base=base,
                search_filter="(&(objectClass=group)(sAMAccountName=%s))" % root_group_name,
                search_scope=scope, attributes=["member"] + xattrib)

        if not result:
            return

        root_group = self._connection.entries[0]

        if "member" not in root_group:
            return

        if import_vars and var_attribute in root_group:
            try:
                raw_info = self._connection.entries[0].info.value
                if raw_info:
                    info = yaml.safe_load(raw_info)
                    self._set_variables("all", info)
            except yaml.scanner.ScannerError:
                pass

        members = root_group.member.values

        for member in members:
            result = self._connection.search(
                    search_base=member,
                    search_filter="(objectClass=*)",
                    search_scope=BASE,
                    attributes=["objectClass", "member", "name", "sAMAccountName"] + xattrib)

            if result:
                entry = self._connection.entries[0]

                if "computer" in entry.objectClass:
                    # Computer in root group; treat as "all"
                    host_name = entry.sAMAccountName.value.lower()
                    is_group = False
                elif "member" not in self._connection.entries[0]:
                    continue
                else:
                    is_group = True
                    users = entry.member.values
                    group_name = entry.sAMAccountName.value.lower()
                    group_marker = self._get_option("group marker")

                    if group_marker:
                        group_name = group_name.replace(group_marker, "")

                    self.inventory.add_group(group_name)

                if import_vars and var_attribute in entry:
                    try:
                        raw_info = entry.info.value
                        if raw_info:
                            info = yaml.safe_load(raw_info)
                            if is_group:
                                self._set_variables(group_name, info)
                            else:
                                self._set_variables(host_name, info)
                    except (yaml.scanner.ScannerError, LDAPAttributeError):
                        pass

                if is_group:
                    for user in users:
                        result = self._connection.search(
                                search_base=user,
                                search_filter="(objectClass=computer)",
                                search_scope=BASE,
                                attributes=["info", "member", "name", "objectClass"] + xattrib)

                        if result:
                            host_name = self._connection.entries[0].name.value.lower()
                            try:
                                raw_info = entry.info.value
                                if raw_info:
                                    info = yaml.safe_load(raw_info)
                                    self._set_variables(host_name, info)
                            except (yaml.scanner.ScannerError, LDAPAttributeError):
                                pass

                            self.inventory.add_host(host_name, group=group_name)
                            self.inventory.add_host(host_name, group="all")
                else:
                    host_name = entry.name.value
                    self.inventory.add_host(host_name, group="all")
