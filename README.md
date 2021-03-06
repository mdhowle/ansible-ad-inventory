
# ansible-ad-inventory

Active Directory dynamic inventory plugins for Ansible

## Installation

To install locally,

```
mkdir -p ~/.ansible/plugins/inventory
cd ~/.ansible/plugins/inventory
git clone https://github.com/mdhowle/ansible-ad-inventory ad
```

See [Ansible Documentation](https://docs.ansible.com/ansible/latest/dev_guide/developing_locally.html#adding-a-plugin-locally) on installing plugins.

Requirement is `ldap3`

Optionally,
  - `gssapi` for Kerberos authentication
  - `dnspython` for LDAP server auto-detection

## Usage
See `ansible-doc -t inventory ad` for more details.

Create a file named `ad.yml` with the contents:

```yaml
plugin: ad
server: dc.example.com
port: 636
base: DC=example,DC=com
username: EXAMPLE\ExampleUser  # or distinguishedname
password: hunter2
filter: "(operatingSystem=Debian GNU/Linux)"
ansible group: Debian
```

Run `ansible-playbook -i ad.yml playbook.yml`


## Configuration
| Attribute | Type | Required | Choices/Default | Description |
|--|--|--|--|--|
| plugin | `str`| Yes | choices: `['ad']`; default: `ad` |  Marks this as an instance of the 'ad' plugin |
| server | `str` | Yes, unless `dnspython` is installed. | `null` | Active Directory server name |
| port | `int` | No | `389` | LDAP Server Port; using port 636 enables SSL |
| base | `str` | No | `null` | Starting port of the search. If `null`, the default naming context will be used. |
| filter | `str` | No | `''` | LDAP query filter. `objectClass=computer` is automatically appended. | 
| scope | `str` | No | choices: `['base', 'level', subtree']`; default: `subtree` | Scope of the search |
| username | `str` | No | `null` | Username to bind as. It can the distinguished name of the user, or "SHORTDOMAIN\user".  If `null`, Kerberos + GSSAPI authentication will be used.
| password | `str` | No | `null` | Username's password. Must be defined if username is also defined. |
| ansible group | `str` | No | N/A | Ansible group name to assign hosts to |
| var attribute | `str` | No | `null` | LDAP attribute to load as YAML for host-specific Ansible variables. |
