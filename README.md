# ansible-ad-inventory

Active Directory dynamic inventory plugin for Ansible

## Installation
See [Ansible Documentation](https://docs.ansible.com/ansible/latest/dev_guide/developing_locally.html#adding-a-plugin-locally) on installing plugins.

Requirements are `ldap3`.
For Kerberos authentication, `gssapi` is required.
For LDAP server auto-detection, `dnspython` is required. 

## Usage
See `ansible-doc -t inventory ad` for more details.

If `server` is not set, a DNS lookup for LDAP servers and an LDAP ping are performed to find the closest server.

Create an `ad.yml` with the contents:

```
plugin: ad
server: ad.example.com
port: 636
base ou: DC=example,DC=com
username: EXAMPLE\user
password: hunter2
root group: ansible-roles
group prefix: ansible-role-
import vars: true
var attribute: info
```

Finally, run `ansible-playbook -i ad.yml playbook.yml`
