
# ansible-ad-inventory

Active Directory dynamic inventory plugins for Ansible

  * `ad`: Inventory based on LDAP filter

## Installation
See [Ansible Documentation](https://docs.ansible.com/ansible/latest/dev_guide/developing_locally.html#adding-a-plugin-locally) on installing plugins.

Requirements are `ldap3`.
For Kerberos authentication, `gssapi` is required.
For LDAP server auto-detection, `dnspython` is required. 

## Usage
See `ansible-doc -t inventory ad` for more details.

If `server` is not set, a DNS lookup for LDAP servers (provided `dnspython` is installed) and an LDAP ping are performed to find the closest server.

## Configuration
Common configuration

| Attribute | Type | Required | Choices/Default | Description |
|--|--|--|--|--|
| server | `str` | No if `dnspython` is installed; Yes otherwise. | `null` | Active Directory server name |
| port | `int` | No | `389` | Active Directory Port; using port 636 enables SSL |
| base | `str` | No | `null` | Starting port of the search. If `null`, the default naming context will be used. |
| scope | `str` | No |choices: `['base', 'level', subtree']`; default: `subtree` | Scope of the search |
| username | `str` | No | `null` | Username to bind as. It can the distinguished name of the user, or "SHORTDOMAIN\user".  If `null`, Kerberos + GSSAPI authentication will be used.
| password | `str` | No | `null` | Username's password. Must be defined if username is also defined. |


### ad
The `ad` plugin uses the LDAP filter to populate Ansible inventory.

| Attribute | Type | Required | Choices/Default | Description |
|--|--|--|--|--|
| plugin | `str`| Yes | choices: `['ad']`; default: `ad` |  Marks this as an instance of the 'ad' plugin |
| filter | `str` | No | `''` | LDAP query filter. `objectClass=computer` is automatically appended. | 
| ansible group | `str` | No | N/A | Ansible group name to assign hosts to |
| var attribute | `str` | No | `null` | LDAP attribute to load as YAML for host-specific Ansible variables. |

