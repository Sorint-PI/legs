from scapy.all import *
import requests

def keycloak_reset_password_for_user(userid,password):
    r = requests.post('http://localhost:8080/realms/master/protocol/openid-connect/token',data={'username': 'admin','password': 'admin','grant_type': 'password','client_id': 'admin-cli'})

    auth_token = r.json()['access_token']

    headers = {
    #    'Accept': 'application/json, text/plain, */*',
    #    'Accept-Language': 'en-US,en;q=0.5',
        'authorization': 'Bearer '+auth_token,
    #    'content-type': 'application/json',
    #    'Origin': 'http://localhost:8080',
    #    'DNT': '1',
    #    'Connection': 'keep-alive',
    #    'Sec-Fetch-Dest': 'empty',
    #    'Sec-Fetch-Mode': 'cors',
    #    'Sec-Fetch-Site': 'same-origin',
    }

    json_data = {
        'temporary': True,
        'type': 'password',
        'value': password,
    }

    response = requests.put(
        'http://localhost:8080/admin/realms/master/users/'+userid+'/reset-password',
        headers=headers,
        json=json_data,
    )

    return

def contains(small, big):
    for i in range(len(big)-len(small)+1):
        for j in range(len(small)):
            if big[i+j] != small[j]:
                break
        else:
            return i, i+len(small)
    return False

def extract_passwords_from_packets(packets):
    # integer representation of the "userpassword" string
    actualStringUserPassword = [117, 115, 101, 114, 112, 97, 115, 115, 119, 111, 114, 100]

    userPasswordTypeString = "userpassword".encode("utf-8")
    userPasswordTypeStringAsIntegers = []
    for char in "userpassword".encode("utf-8"):
      userPasswordTypeStringAsIntegers.append(char)

    extracted_passwords = []

    for packet in packets:
      packet_as_integers = []

      packet_has_third_layer = False
      try:
          len(packet[3])
          packet_has_third_layer = True
      except IndexError:
          packet_has_third_layer = False


      if packet_has_third_layer:
          for byte in raw(packet[3]):
              packet_as_integers.append(byte)

          password_type_exists_at_positions = contains(userPasswordTypeStringAsIntegers,packet_as_integers)
          if password_type_exists_at_positions is not False:
            # We get the length of the password, which can be found at user password type + 3 bytes and is only 1 byte big
            pass_length = packet_as_integers[password_type_exists_at_positions[1]+3]
            # Read from found user password type + 4 bytes
            extracted_pass = packet_as_integers[password_type_exists_at_positions[1]+4:password_type_exists_at_positions[1]+4+pass_length]
            extracted_passwords.append(extracted_pass)
    return extracted_passwords


def test_from_pcap_file():

    scapy_cap = rdpcap('tests/fixtures/test_ass_keycloak_normale.pcap')
    packets = []
    for packet in scapy_cap:
      packets.append(packet)

    #rawBinaryPass = raw(packets[5][3])
    #capturedPassAsIntegers = []
    #for byte in bytes(packets[5][3]):
    #  capturedPassAsIntegers.append(byte)

    passwords = extract_passwords_from_packets(packets)

    myPassAsString = "PQLWEJPVJASPDLJPALJSD"
    myPassAsIntegers = []
    for char in myPassAsString.encode('utf-8'):
      myPassAsIntegers.append(char)


    assert contains(myPassAsIntegers,passwords[0])


# Dato un interceptor, ed una richiesta di modifica password, printa la password e l'utente della richiesta a schermo
# nome alternativo: test_check_if_password_is_decoded_correctly
def test_intercept():
    testpassword = "123456789"
    #testuser = 'testuser1'
    testuser = '1bef31ca-4058-4218-92ea-17361b409433'

    #t = AsyncSniffer(iface="veth2",filter="port 389")
    t = AsyncSniffer(iface="veth2")
    t.start()


    #print("Attendendo di lanciare la modifica passy")
    keycloak_reset_password_for_user(testuser,testpassword)

    results = t.stop()
    found_passwords = extract_passwords_from_packets(results)
    decoded_found_password = bytes(found_passwords[0]).decode('utf-8')

    assert testpassword == decoded_found_password

# FATTO Creare funzione di modifica password che lancia una modifica
# FATTO Creare funzione di intercept che intercetta in maniera asincrona e chiami la lettura subito dopo la funzione sopra
# Controlla che l'utente e la password dati siano stati letti correttamente dall'interceptor


def test_answer():
    assert 3 == 3
