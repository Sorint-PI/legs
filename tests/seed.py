import subprocess
import requests
from keycloak_seeding import keycloak_get_auth_token


def keycloak_create_realm():
    global keycloak_realm_id

    auth_token = keycloak_get_auth_token()

    headers = {
        "authorization": "Bearer " + auth_token,
    }

    json_data = {"realm": keycloak_realm_name, "enabled": True}

    response_post = requests.post(
        "http://localhost:8080/admin/realms", headers=headers, json=json_data
    )
    response_get = requests.get(
        "http://localhost:8080/admin/realms/" + keycloak_realm_name, headers=headers
    )

    keycloak_realm_id = response_get.json()["id"]
    return keycloak_realm_id


def keycloak_create_realm_ldap_federation():
    global keycloak_realm_name
    global keycloak_realm_id
    auth_token = keycloak_get_auth_token()

    headers = {"authorization": "Bearer " + auth_token}

    json_data = {
        "config": {
            "enabled": [
                "true",
            ],
            "vendor": [
                "other",
            ],
            "connectionUrl": [
                ldap_url,
            ],
            "connectionTimeout": [
                "",
            ],
            "bindDn": [
                ldap_bind_dn,
            ],
            "bindCredential": [
                ldap_bind_password,
            ],
            "startTls": [
                "false",
            ],
            "useTruststoreSpi": [
                "ldapsOnly",
            ],
            "connectionPooling": [
                "false",
            ],
            "authType": [
                "simple",
            ],
            "usersDn": [
                ldap_users_base_dn,
            ],
            "usernameLDAPAttribute": [
                "uid",
            ],
            "rdnLDAPAttribute": [
                "uid",
            ],
            "uuidLDAPAttribute": [
                "entryUUID",
            ],
            "userObjectClasses": [
                "inetOrgPerson, organizationalPerson",
            ],
            "customUserSearchFilter": [
                "",
            ],
            "readTimeout": [
                "",
            ],
            "editMode": [
                ldap_federation_edit_mode,
            ],
            "searchScope": [
                "",
            ],
            "pagination": [
                "false",
            ],
            "batchSizeForSync": [
                "",
            ],
            "importEnabled": [
                "true",
            ],
            "syncRegistrations": [
                "true",
            ],
            "allowKerberosAuthentication": [
                "false",
            ],
            "useKerberosForPasswordAuthentication": [
                "false",
            ],
            "cachePolicy": [
                "DEFAULT",
            ],
            "usePasswordModifyExtendedOp": [
                "false",
            ],
            "validatePasswordPolicy": [
                "false",
            ],
            "trustEmail": [
                "false",
            ],
            "changedSyncPeriod": [
                "-1",
            ],
            "fullSyncPeriod": [
                "-1",
            ],
        },
        "providerId": "ldap",
        "providerType": "org.keycloak.storage.UserStorageProvider",
        "parentId": keycloak_realm_id,
        "name": "ldap",
    }

    response = requests.post(
        "http://localhost:8080/admin/realms/" + keycloak_realm_name + "/components",
        headers=headers,
        json=json_data,
    )


def seed_keycloak():
    # keycloak_config_credentials_command = ["podman exec -it tests_integration-tests-keycloak-server-container_1 /opt/keycloak/bin/kcadm.sh config credentials --server http://localhost:8080 --realm master --user admin --password admin"]
    # keycloak_create_realm_command = ["podman exec -it tests_integration-tests-keycloak-server-container_1 /opt/keycloak/bin/kcadm.sh create realms -s realm=testing -s enabled=true -o"]
    # print(
    #        subprocess.run(keycloak_config_credentials_command, stdout=subprocess.PIPE,shell=True).stdout.decode('utf-8')
    #     )
    # print(
    #        subprocess.run(keycloak_create_realm_command, stdout=subprocess.PIPE,shell=True).stdout.decode('utf-8')
    #     )

    global keycloak_realm_id

    keycloak_realm_id = keycloak_create_realm()
    keycloak_create_realm_ldap_federation()


# Seed data - LDAP
ldap_url = "ldap://integration-tests-freeipa-server-container:389"
ldap_bind_dn = "cn=Directory Manager"
ldap_bind_password = "directorymanager"
ldap_federation_edit_mode = "WRITABLE"
ldap_users_base_dn = "cn=users,cn=accounts,dc=example,dc=test"

# Seed data - Keycloak
keycloak_realm_name = "testing"
keycloak_realm_id = ""  # will be set upon programmatic realm creation

# Per federazione da CLI
# "keycloak cli create federation"
# https://keycloak.discourse.group/t/configure-user-federation-via-rest-api/3478
# https://www.keycloak.org/docs/latest/server_admin/
# https://www.keycloak.org/docs/latest/server_admin/#admin-cli
# https://stackoverflow.com/questions/44490456/add-provider-to-user-federation-in-redhat-sso-keycloak-using-cli
# https://gist.github.com/luciddreamz/83a888eedd9274b4045a3ab8af064faa

seed_keycloak()
