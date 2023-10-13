import requests

def keycloak_get_auth_token():
    r = requests.post('http://localhost:8080/realms/master/protocol/openid-connect/token',data={'username': 'admin','password': 'admin','grant_type': 'password','client_id': 'admin-cli'})
    return r.json()['access_token']

def keycloak_get_user_id_by_user_name(username,realm):
    auth_token = keycloak_get_auth_token()
    headers = {
        'authorization': 'Bearer ' + auth_token
    }
    
    params = {
        'briefRepresentation': 'true',
        'first': '0',
        'max': '11',
        'search': username,
    }
    
    response = requests.get('http://localhost:8080/admin/realms/'+realm+'/ui-ext/brute-force-user', params=params, headers=headers)
    return response.json()[0]['id']

def keycloak_reset_password_for_user(username,password,realm):

    auth_token = keycloak_get_auth_token()
    userid = keycloak_get_user_id_by_user_name(username,realm)

    headers = {
        'authorization': 'Bearer '+auth_token
    }

    json_data = {
        'temporary': True,
        'type': 'password',
        'value': password,
    }

    response = requests.put(
        'http://localhost:8080/admin/realms/'+realm+'/users/'+userid+'/reset-password',
        headers=headers,
        json=json_data,
    )

    return

