###########################################################
# General configuration variables
###########################################################

# LOG_LEVEL
# Possible values: DEBUG,FATAL,WARN,INFO
LOG_LEVEL = "DEBUG"
# DRY_RUN
# Make the program work as normal BUT writes or destructive operations will be IGNORED
DRY_RUN = True
# INTERCEPT_TO_STDOUT_DEBUG_MODE
# The program will ONLY intercept passwords and write them to stdout, no other actions will be taken.
# Passwords will NOT be logged to disk.
INTERCEPT_TO_STDOUT_DEBUG_MODE = True
# INTERFACE_NAME
# The interface the program will listen on.
INTERFACE_NAME = "eth0"


###########################################################
# LDAP source server configuration
###########################################################

# LDAP server hostname
LDAP_SOURCE_SERVER_HOST=""
# Login user for the LDAP server
LDAP_SOURCE_SERVER_LOGIN_DN=""
# LDAP server password
LDAP_SOURCE_SERVER_LOGIN_PASS=""
# LDAP users base DN
LDAP_SOURCE_BASE_DN = ''
# LDAP search filter. The last replace will remove newlines.
LDAP_SOURCE_SEARCH_FILTER="""
(|(memberOf=cn=group-1,ou=Groups,o=organizazion,dc=company,dc=it)
(memberOf=cn=group-2,ou=Groups,o=organizazion,dc=company,dc=it)
(memberOf=cn=group-3,ou=Groups,o=organizazion,dc=company,dc=it)
(memberOf=cn=group-4,ou=Groups,o=organizazion,dc=company,dc=it))
""".replace('\r', '').replace('\n', '')


###########################################################
# LDAP destination server configuration
###########################################################
# LDAP server hostname
LDAP_DESTINATION_SERVER_HOST=""
# Login user for the LDAP server
LDAP_DESTINATION_SERVER_LOGIN_DN=""
# LDAP server password
LDAP_DESTINATION_SERVER_LOGIN_PASS=""
# LDAP users DN prefix
LDAP_DESTINATION_BASE_DN_PREFIX = ''
# LDAP users base DN
LDAP_DESTINATION_BASE_DN = ''
# LDAP search filter. The last replace will remove newlines.
LDAP_DESTINATION_SEARCH_FILTER="""
(|(memberOf=cn=group-1,ou=Groups,o=organizazion,dc=company,dc=it)
(memberOf=cn=group-2,ou=Groups,o=organizazion,dc=company,dc=it)
(memberOf=cn=group-3,ou=Groups,o=organizazion,dc=company,dc=it)
(memberOf=cn=group-4,ou=Groups,o=organizazion,dc=company,dc=it))
""".replace('\r', '').replace('\n', '')
