from __future__ import (absolute_import, division, print_function)
__metaclass__ = type

DOCUMENTATION = r"""
    name: ad
    plugin_type: inventory
    author:
        - Matthew Howle <matthew@howle.org>
    short_description: ActiveDirectory inventory source
    requirements:
        - python >= 2.7
        - ldap3
    optional:
        - gssapi
    description:
        - Read inventory from ActiveDirectory group memberships.
        - Uses ad.(yml|yaml) YAML configuration file to configure the inventory plugin.
        - If no configuration value is assigned for the server or base ou, it will auto-detect.
        - If no username is defined, Kerberos + GSSAPI will be used to connect to the server.
    options:
        plugin:
            description: Marks this as an instance of the 'ad' plugin.
            required: true
            choices: ['ad']
        server:
            description: The ActiveDirectory server name.
            required: false
            type: str
            default: null
        port:
            description: ActiveDirectory port. Using port 636 automatically enables SSL.
            required: false
            type: int
            default: 389
        base ou:
            description: Base OU to search for group.
            required: false
            type: str
            default: null
        username:
            description: Username to bind as. It can be the distinguishedname of the user, or "SHORTDOMAIN\user".  If username is defined, the connection will use a simple bind. Otherwise, Kerberos+GSSAPI will be used.
            required: false
            type: str
            default: null
        password:
            description: Username's password. Must be defined if username is also defined.
            required: false
            type: str
            default: null
        root group:
            description: The Ansible group that contains all other groups.
            required: false
            type: str
            default: ansible-roles
        group prefix:
            description: The Ansible group prefix that will be removed from group name.
            required: false
            type: str
            default: ansible-role-
        import vars:
            description: Import variables from an attribute of the groups and hosts object. See "var attribute".
            required: false
            type: bool
            default: true
        var attribute:
            description: The attribute to load YAML for group/host-specific variables if "import vars" is enabled.
            required: false
            type: str
            default: info
"""

EXAMPLES = r"""
# Minimal example. 'server' and 'base ou' will be detected.
# kerberos/gssapi will be used to connect.
plugin: ad

# Example with all values assigned
plugin: ad
server: dc.example.com
port: 636
base ou: OU=Groups,DC=example,DC=com
username: EXAMPLE\ExampleUser  # or distinguishedname
password: "SecurePassword"
root group: ansible-roles
group_prefix: ansible-roles-
import vars: yes
var attribute: info
"""
import socket
import struct

from ansible.errors import AnsibleError
from ansible.plugins.inventory import BaseInventoryPlugin

import yaml

from ldap3 import BASE, Connection, DSA, SASL, Server, SUBTREE
from ldap3.core.exceptions import LDAPSocketOpenError

try:
    import dns.resolver as dns_resolver
except ImportError:
    dns_resolver = None


class InventoryModule(BaseInventoryPlugin):
    NAME = 'ad'

    def __init__(self):
        super(InventoryModule, self).__init__()
        self._connection = None

    def verify_file(self, path):
        if super(InventoryModule, self).verify_file(path):
            filenames = ('ad.yaml', 'ad.yml')
            return any((path.endswith(filename) for filename in filenames))
        return False

    def parse(self, inventory, loader, path, cache=True):
        super(InventoryModule, self).parse(inventory, loader, path)
        self.config_data = self._read_config_data(path)
        self._create_client()
        self._build_inventory()

    def _get_option(self, option):
        value = self.get_option(option)
        
        if value:
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
        base_ou = self._get_option("base ou")
        
        if server:
            sargs = {"use_ssl": True} if port == 636 else {}
            ldap_server = Server(server, port=port, get_info=DSA, **sargs)
            cargs = self._get_connection_args()

            self._connection = Connection(ldap_server, **cargs)
            self._connection.open()
            self._connection.start_tls()
            self._connection.bind()

            if base_ou is None:
                result = self._connection.search(search_base="",
                        search_filter="(dnsHostName=%s)" % server,
                        search_scope=BASE, attributes=["defaultNamingContext"])
                if result:
                    base_ou = (self._connection.server
                               .info.other["defaultNamingContext"][0])
                    self.set_option("base ou", base_ou)
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

        base_ou=self._get_option("base ou")
        root_group = self._get_option("root group")
        
        import_vars = self._get_option("import vars")
        var_attrib = self._get_option("var attribute")

        xattrib = [var_attrib] or []
        
        result =  self._connection.search(
                search_base=base_ou,
                search_filter="(sAMAccountName=%s)" % root_group,
                search_scope=SUBTREE, attributes=["member"] + xattrib)

        if not result:
            return

        if import_vars and "info" in self._connection.entries[0]:
            try:
                raw_info = self._connection.entries[0].info.value
                if raw_info:
                    info = yaml.safe_load(raw_info)
                    self._set_variables("all", info)
            except yaml.scanner.ScannerError:
                pass

        #TODO: Recursively resolve group memberships
        gmembers = self._connection.entries[0].member.values

        for gmember in gmembers:
            result = self._connection.search(
                    search_base=gmember,
                    search_filter="(objectClass=*)",
                    search_scope=BASE,
                    attributes=["member", "sAMAccountName"] + xattrib)

            if result:
                if "member" not in self._connection.entries[0]:
                    continue

                users = self._connection.entries[0].member.values
                group_name = self._connection.entries[0].sAMAccountName.value.lower()
                group_prefix = self._get_option("group prefix")

                if group_prefix:
                    group_name = group_name.replace(group_prefix, "")
                
                self.inventory.add_group(group_name)
                if import_vars and "info" in self._connection.entries[0]:
                    try:
                        raw_info = self._connection.entries[0].info.value
                        if raw_info:
                            info = yaml.safe_load(raw_info)
                            self._set_variables(group_name, info)
                    except yaml.scanner.ScannerError:
                        pass

                for user in users:
                    # TODO: Create groups based on certain
                    # object attributes (e.g. location, os)
                    result = self._connection.search(
                            search_base=user,
                            search_filter="(objectClass=computer)",
                            search_scope=BASE,
                            attributes=["name"] + xattrib)

                    if result:
                        host_name = self._connection.entries[0].name.value.lower()
                        self.inventory.add_host(host_name, group=group_name)
                        self.inventory.add_host(host_name, group="all")
