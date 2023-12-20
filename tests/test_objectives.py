import os
import sys
SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
sys.path.append(os.path.dirname(SCRIPT_DIR))
from context import legs

from legs import main
from legs import ldap_utils

from scapy.all import *
import requests
import ldap3
from keycloak_seeding import keycloak_get_auth_token
from keycloak_seeding import keycloak_reset_password_for_user
from keycloak_seeding import keycloak_get_user_id_by_user_name
import threading

import pytest
import time
import pickle


config = {}


test_passwords = [
        "test1234ABCD"
        "1",
        "2",
        "3",
        "4",
        "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$"
        ]


@pytest.fixture(params=test_passwords)
def test_password(request):
    return str(request.param)

@pytest.fixture
def source_ldap_server():
    ldap_server = ldap3.Server('ldap://localhost:4389', use_ssl=False, get_info=ldap3.ALL)
    return ldap_server

@pytest.fixture
def source_ldap_server_connection(source_ldap_server):
    server_bind_dn = 'cn=Directory Manager'
    server_bind_password = 'directorymanager'
    ldap_destination_connection = ldap3.Connection(source_ldap_server, server_bind_dn, server_bind_password, auto_bind=True)
    return ldap_destination_connection

@pytest.fixture
def destination_ldap_server():
    ldap_server = ldap3.Server('ldap://localhost:5389', use_ssl=False, get_info=ldap3.ALL)
    return ldap_server

@pytest.fixture
def destination_ldap_server_connection(destination_ldap_server):
    server_bind_dn = 'cn=admin,dc=example,dc=org'
    server_bind_password = 'admin'
    ldap_destination_connection = ldap3.Connection(destination_ldap_server, server_bind_dn, server_bind_password, auto_bind=True)
    return ldap_destination_connection


def tests_working():
    assert True == True

def test_ldap_source_server_bind():
    # TODO
    #ldap_source_server, ldap_source_connection = main.establish_ldap_source_server_connection()
    #assert ldap_source_server
    #assert ldap_source_connection
    pass

def test_ldap_destination_server_bind():
    ldap_destination_server,ldap_destination_connection = main.establish_ldap_destination_server_connection()
    assert ldap_destination_server
    assert ldap_destination_connection

def test_from_pcap_file():

    scapy_cap = rdpcap('tests/fixtures/test_password_reset_keycloak_capture.pcap')
    packets = []
    for packet in scapy_cap:
      packets.append(packet)

    #rawBinaryPass = raw(packets[5][3])
    #capturedPassAsIntegers = []
    #for byte in bytes(packets[5][3]):
    #  capturedPassAsIntegers.append(byte)

    passwords = ldap_utils.extract_passwords_from_packets(packets)

    myPassAsString = "PzAvSbJ$Dn'z'yLP'$Aq#t#Wy#uJ\"EQ"
    myPassAsIntegers = []
    for char in myPassAsString.encode('utf-8'):
      myPassAsIntegers.append(char)

    assert ldap_utils.contains(myPassAsIntegers,passwords[0])

def test_from_pickle_file():

    packets = []
    with open('tests/fixtures/packet-test-pickle.pkl', 'rb') as pickle_file:
        packet = pickle.load(pickle_file)
        packets.append(packet)

    passwords = ldap_utils.extract_passwords_from_packets(packets)

    testpassword = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$"
    myPassAsIntegers = []
    for char in testpassword.encode('utf-8'):
      myPassAsIntegers.append(char)

    assert ldap_utils.contains(myPassAsIntegers,passwords[0])

# Dato un interceptor, ed una richiesta di modifica password, printa la password e l'utente della richiesta a schermo
# nome alternativo: test_check_if_password_is_decoded_correctly
def test_intercept_password():
    testpassword = "123456789"
    testuser = 'testuser1'
    #testuser = '1bef31ca-4058-4218-92ea-17361b409433'
    realm = 'testing'

    #t = AsyncSniffer(iface="veth2",filter="port 389")
    t = AsyncSniffer(iface="veth2")
    t.start()

    keycloak_reset_password_for_user(testuser,testpassword,realm)

    results = t.stop()
    found_passwords = ldap_utils.extract_passwords_from_packets(results)
    decoded_found_password = bytes(found_passwords[0]).decode('utf-8')

    assert testpassword == decoded_found_password

def test_intercept_user_uid():
    testpassword = "123456789"
    testuser = 'testuser1'
    #testuser = '1bef31ca-4058-4218-92ea-17361b409433'
    realm = 'testing'

    #t = AsyncSniffer(iface="veth2",filter="port 389")
    t = AsyncSniffer(iface="veth2")
    t.start()

    keycloak_reset_password_for_user(testuser,testpassword,realm)

    results = t.stop()
    found_uids = ldap_utils.extract_users_uids_from_packets(results)
    decoded_found_uid = bytes(found_uids[0]).decode('utf-8')

    assert testuser == decoded_found_uid

def test_ldap_write_password_for_user(destination_ldap_server, destination_ldap_server_connection):
    server_bind_dn = 'cn=admin,dc=example,dc=org'
    server_users_bind_dn = 'ou=people,dc=example,dc=org'
    server_bind_password = 'admin'

    testpassword = "wariooooo"
    test_second_password = "waaaaluiiiigiiii"
    testuser = 'testuser1'
    first_bind_successful = False
    second_bind_successful = False
    testuser_dn = "uid="+testuser+","+server_users_bind_dn

    # write the given password
    main.write_ldap_password_for_user(destination_ldap_server_connection,testuser_dn,testpassword)
    # bind to test wether the password actually works from LDAP
    conn = ldap3.Connection(destination_ldap_server,testuser_dn,testpassword)
    if conn.bind():
      first_bind_successful = True

    # re-write the given password to test wether it actually changes
    main.write_ldap_password_for_user(destination_ldap_server_connection,testuser_dn,test_second_password)
    # re-bind to test wether the password actually works from LDAP
    conn_second = ldap3.Connection(destination_ldap_server,testuser_dn,test_second_password)
    if conn_second.bind():
      second_bind_successful = True

    assert first_bind_successful and second_bind_successful

def test_async_password_intercepting_and_writing(source_ldap_server, source_ldap_server_connection, destination_ldap_server, destination_ldap_server_connection,test_password):
    testuser = 'testuser1'
    keycloak_realm = 'testing'
    source_server_users_bind_dn = 'cn=users,cn=accounts,dc=example,dc=test'
    #destination_server_users_bind_dn = ',ou=people,dc=example,dc=org'
    destination_server_users_bind_dn = ',ou=people,dc=example,dc=org'
    source_server_testuser_dn = "uid="+testuser+","+source_server_users_bind_dn
    destination_server_testuser_dn = "uid="+testuser+destination_server_users_bind_dn
    interface_name = "veth2"

    first_test_password = test_password
    second_test_password = "CCCCCCCCCCCCCC"

    queue_passwords_to_update = Queue(maxsize=1000)



    stop_flag = [False]
    #start_async_interception(stop_flag, queue_passwords_to_update, destination_ldap_server_connection)
    password_intercept_thread = threading.Thread(target = main.start_async_interception,
                                                 args =(queue_passwords_to_update,
                                                        destination_ldap_server_connection,
                                                        interface_name 
                                                        ),
                                                 kwargs={'stop_flag':stop_flag,
                                                         'destination_ldap_server_users_dn_prefix':"uid=",
                                                         'destination_ldap_server_users_dn_suffix':destination_server_users_bind_dn,
                                                         }
                                                 )
    password_intercept_thread.start()

    first_bind_on_source_successful = False
    first_bind_on_destination_succesful = False
    second_bind_on_source_successful = False
    second_bind_on_destination_succesful = False

    keycloak_reset_password_for_user(testuser,first_test_password,keycloak_realm)

    # Test the bind on the source LDAP server
    conn = ldap3.Connection(source_ldap_server,source_server_testuser_dn,first_test_password)
    if conn.bind():
      first_bind_on_source_successful = True
    # Test the bind on the destination LDAP server
    conn = ldap3.Connection(destination_ldap_server,destination_server_testuser_dn,first_test_password)
    if conn.bind():
      first_bind_on_destination_succesful = True

    keycloak_reset_password_for_user(testuser,second_test_password,keycloak_realm)

    # Test the bind on the source LDAP server
    conn = ldap3.Connection(source_ldap_server,source_server_testuser_dn,second_test_password)
    if conn.bind():
      second_bind_on_source_successful = True
    # Test the bind on the destination LDAP server
    conn = ldap3.Connection(destination_ldap_server,destination_server_testuser_dn,second_test_password)
    if conn.bind():
      second_bind_on_destination_succesful = True


    stop_flag[0] = True
    password_intercept_thread.join()


    assert first_bind_on_source_successful
    assert first_bind_on_destination_succesful
    assert second_bind_on_source_successful
    assert second_bind_on_destination_succesful


def test_main(source_ldap_server, source_ldap_server_connection, destination_ldap_server, destination_ldap_server_connection,test_password):
    first_bind_on_source_successful = False
    first_bind_on_destination_succesful = False
    second_bind_on_source_successful = False
    second_bind_on_destination_succesful = False

    testuser = 'testuser1'
    keycloak_realm = 'testing'
    interface_name = "veth2"

    source_server_users_bind_dn = 'cn=users,cn=accounts,dc=example,dc=test'
    source_server_testuser_dn = "uid="+testuser+","+source_server_users_bind_dn
    destination_server_users_bind_dn = ',ou=people,dc=example,dc=org'
    destination_server_testuser_dn = "uid="+testuser+destination_server_users_bind_dn
    first_test_password = test_password
    second_test_password = "CCCCCCCCCCCCCC"


    stop_flag = [False]
    intercepting_thread = threading.Thread(target=main.main, args=(), kwargs={"stop_flag":stop_flag})
    intercepting_thread.start()
    #main.main()

    if not intercepting_thread.is_alive():
        raise Exception("Thread not running")


    keycloak_reset_password_for_user(testuser,first_test_password,keycloak_realm)

    # Test the bind on the source LDAP server
    conn = ldap3.Connection(source_ldap_server,source_server_testuser_dn,first_test_password)
    if conn.bind():
      first_bind_on_source_successful = True
    # Test the bind on the destination LDAP server
    conn = ldap3.Connection(destination_ldap_server,destination_server_testuser_dn,first_test_password)
    if conn.bind():
      first_bind_on_destination_succesful = True

    keycloak_reset_password_for_user(testuser,second_test_password,keycloak_realm)

    # Test the bind on the source LDAP server
    conn = ldap3.Connection(source_ldap_server,source_server_testuser_dn,second_test_password)
    if conn.bind():
      second_bind_on_source_successful = True
    # Test the bind on the destination LDAP server
    conn = ldap3.Connection(destination_ldap_server,destination_server_testuser_dn,second_test_password)
    if conn.bind():
      second_bind_on_destination_succesful = True


    stop_flag[0] = True
    print("Joining thread")
    intercepting_thread.join()

    assert first_bind_on_source_successful
    assert first_bind_on_destination_succesful
    assert second_bind_on_source_successful
    assert second_bind_on_destination_succesful

