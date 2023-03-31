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
        - Read inventory from Active Directory
        - Uses ad.(yml|yaml) YAML configuration file to configure the inventory plugin.
        - If no configuration value is assigned for the server or base, it will auto-detect.
        - If no username is defined, Kerberos + GSSAPI will be used to connect to the server.
    options:
        plugin:
            description: Marks this as an instance of the 'ad' plugin.
            required: true
            choices: ['ad']
        server:
            description: Active Directory server name or list of server names.
            required: false
            default: null
        port:
            description: ActiveDirectory port. Using port 636 automatically enables SSL.
            required: false
            type: int
            default: 389
        ssl:
            description: Use SSL when connecting
            required: false
            type: bool
            default: false
        starttls:
            description: Use STARTTLS when connecting
            required: false
            type: bool
            default: true
        base:
            description: Starting point for the search. if null, the default naming context will be used.
            required: false
            type: str
            default: null
        scope:
            description: Scope of the search.
            required: false
            default: subtree
            choices: ['base', 'level', 'subtree']
        username:
            description: Username to bind as. It can be the distinguishedname of the user, or "SHORTDOMAIN\user".  If null, the connection will use a simple bind. Otherwise, Kerberos+GSSAPI will be used.
            required: false
            type: str
            default: null
        password:
            description: Username's password. Must be defined if username is also defined.
            required: false
            type: str
            default: null
        hostname var:
            description: LDAP attribute to use as the inventory hostname
            required: false
            type: str
            default: 'name'
        filter:
            description: LDAP query filter. Note "objectClass=computer" is automatically appended.
            required: false
            type: str
            default: ''
        ansible group:
            description: Ansible group name to assign objects to
            required: false
            type: str
        var attribute:
            description: LDAP attribute to load as YAML for host-specific Ansible variables
            required: false
            type: str
            default: null
        use ad groups:
            description: Add AD group memberships as Ansible host groups.
            required: false
            type: bool
            default: true
"""

EXAMPLES = r"""
# Minimal example. 'server' and 'base' will be detected.
# kerberos/gssapi will be used to connect.
plugin: ad

# Example with all values assigned
plugin: ad
server: dc.example.com
port: 636
base: OU=Groups,DC=example,DC=com
username: EXAMPLE\ExampleUser  # or distinguishedname
password: "SecurePassword"
filter: "(operatingSystem=Debian GNU/Linux)"
ansible group: Debian
var attribute: info
"""
import socket
import struct

from ansible.errors import AnsibleError
from ansible.plugins.inventory import BaseInventoryPlugin
from ansible.parsing.yaml.objects import AnsibleSequence

import yaml

from ldap3 import BASE, Connection, DSA, LEVEL, SASL, Server, SUBTREE
from ldap3.core.exceptions import LDAPSocketOpenError
from ldap3.utils.dn import parse_dn

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

    def get_option(self, option):
        value = super(InventoryModule, self).get_option(option)

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
        username = self.get_option("username")
        password = self.get_option("password")

        if username:
            if password:
                return {"user": username, "password": password}
            else:
                raise AnsibleError("Username defined without a password")
        return {"authentication": SASL, "sasl_mechanism": "GSSAPI"}

    def _create_client(self):
        if self._connection:
            return self._connection

        servers = self.get_option("server")

        if servers is None:
            raise AnsibleError("Server name could not be determined")

        if not isinstance(servers, AnsibleSequence):
            servers = [servers]

        port = self.get_option("port")
        base = self.get_option("base")
        use_starttls = self.get_option("starttls")
        use_ssl = self.get_option("ssl")

        for server in servers:
            sargs = {"use_ssl": True} if port == 636 or use_ssl else {}
            ldap_server = Server(server, port=port, get_info=DSA, **sargs)
            cargs = self._get_connection_args()

            self._connection = Connection(ldap_server, **cargs)
            try:
                self._connection.open()
            except LDAPSocketOpenError:
                continue

            if use_starttls:
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
            break

    def _get_domain(self):
        fqdn = socket.getfqdn()
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

        base = self.get_option("base")
        user_filter = self.get_option("filter")
        scope = self.get_option("scope")
        hostname_var = self.get_option("hostname var")
        ansible_group = self.get_option("ansible group")
        use_ad_groups = self.get_option("use ad groups")

        var_attribute = self.get_option("var attribute")
        import_vars = var_attribute is not None

        xattrib = [var_attribute] if import_vars else []

        if use_ad_groups:
            xattrib.append("memberOf")

        qfilter = "(&(objectClass=computer)%s)" % user_filter

        if ansible_group:
            self.inventory.add_group(ansible_group)

        results = self._connection.search(
                search_base=base,
                search_filter=qfilter,
                search_scope=scope,
                attributes=[hostname_var] + xattrib)

        if results:
            for entry in self._connection.entries:
                info = None
                if import_vars and var_attribute in entry:
                    try:
                        raw_info = entry.info.value
                        if raw_info:
                            info = yaml.safe_load(raw_info)
                    except yaml.scanner.ScannerError:
                        pass

                host_name = getattr(entry, hostname_var).value.lower()

                if info:
                    self._set_variables(host_name, info)

                if ansible_group:
                    self.inventory.add_host(host_name, group=ansible_group)

                if use_ad_groups:
                    for group_dn in entry.memberOf.values:
                        group_dn_parts = parse_dn(group_dn)
                        group_cn = group_dn_parts[0][1]
                        group = self.inventory.add_group(group_cn)
                        self.inventory.add_host(host_name, group=group)

                self.inventory.add_host(host_name, group="all")
