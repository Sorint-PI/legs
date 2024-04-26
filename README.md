# LEGS (LDAP Extended Giga Sync)

Sync LDAP passwords across different Identity Providers by intercepting password modify operations.

## Getting started

Clone the project:
```
git clone 'https://github.com/Sorint-PI/legs'
```
Create a python virtual environment:
```
cd legs
python -m venv venv
```
Install the required dependencies:
```
venv/bin/pip install -r requirements.txt
```
Copy the default template:
```
cp docs/config-template.py legs/config.py
```
Make sure the INTERCEPT_TO_STDOUT_DEBUG_MODE variable is set to True (this will let you see password changes without writing any changes to allow troubleshooting):
```
INTERCEPT_TO_STDOUT_DEBUG_MODE = True
```
Launch the script to check if any password changes are detected:
```
venv/bin/python legs/main.py
```
If you try to reset your password (for example with an external password reset web service) and the password update passes through the local LDAP server, your password will be printed on screen.

Proceed to the [Deployment.md](docs/Deployment.md) document for more information on how to continue the deployment.

## How it works

[See docs/HOWITWORKS.md](docs/HOWITWORKS.md)

## Features
- ✅ Sync password changes between 2 providers by intercepting password changes from the network
- ✅ Passwords are not stored on-disk nor logged unless the logging level is set to DEBUG
- ❌(WIP) Intercept passwords with SSL encryption/TLS deciphering for LDAPS
- ❌(WIP) Intercept passwords by acting as a password policy filter
- ❌(WIP) As password policy filter, define various policies and actions to run in an actions.py customizable file
- ❌(WIP) Two-way sync of passwords (source is synchronized with destination and vice-versa, passwords are propagated to all the LDAP servers where LEGS is installed)

### Tested identity providers
- ✅ FreeIPA (389 Directory Server)
- ✅ OpenLDAP
- ❌ (WIP) Apache Directory Server https://github.com/apache/directory-server
- ❌ (WIP) LLDAP https://github.com/lldap/lldap
- ❌ (WIP) Active Directory
- ❌ (WIP) Zentyal (OpenLDAP)
- ❌ (WIP) GLAuth https://github.com/glauth/glauth
- ❌ (WIP) OpenDJ https://github.com/OpenIdentityPlatform/OpenDJ / Wren:DS https://github.com/WrenSecurity/wrends
- ❌ (WIP) Univention Corporate Server https://github.com/univention/univention-corporate-server

If a provider is listed as "✅" it was tested as source as well as destination of the writes.

### Tested password reset portals / self service password (SSP) portals
- ✅ Keycloak password reset
- ❌ (WIP) ltb-project/self-service-password https://github.com/ltb-project/self-service-password
- ❌ (WIP) bartekrutkowski/ldapass https://github.com/bartekrutkowski/ldapass
- ❌ (WIP) larrabee/freeipa-password-reset https://github.com/larrabee/freeipa-password-reset

### Tested password modify operations
- ✅ LDAP Modify (RFC 1823) (using LDAP and not LDAPS)
- ❌ (WIP) Extended LDAP Modify (RFC 3062) (using LDAPS)

Let us know of any non-standard password reset operations in the Issues.

## Running tests
[See tests/README.md](tests/README.md)

## Troubleshooting

Should you find any problems, feel free to open an Issue! Feedback is always welcome.

## Similar projects

For the sake of completeness here is a list of projects with purposes similar to LEGS:
- [Manage Engine Password Synchronizer](https://www.manageengine.com/products/self-service-password/help/admin-guide/Application/sync/password-synchronizer-openldap.html)
- [ForgeRock Password Sync Plugin](https://backstage.forgerock.com/docs/idm/7/pwd-plugin-guide/)
- [IBM Password Synchronization Plug-in](https://www.ibm.com/docs/en/SSCQGF_7.1.1/com.ibm.IBMDI.doc_7.1.1/pluginsguide.pdf)
- [Oracle Password Filter for Microsoft Active Directory](https://docs.oracle.com/middleware/11119/dip/administer/odip_adpasswordsync.htm)
- [Red Hat Password Sync Service for Active Directory](https://access.redhat.com/documentation/it-it/red_hat_enterprise_linux/6/html/identity_management_guide/pass-sync)
- [Google G Suite Password Sync](https://support.google.com/a/answer/2611842?hl=en)
