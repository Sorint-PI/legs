import sys
import os
SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
sys.path.append(os.path.dirname(SCRIPT_DIR))

import legs.ldap_utils as ldap_utils
from scapy.all import *
import time
import legs.config as config
import traceback
import ldap3
from ldap3.utils.hashed import hashed



import logging
from logging.handlers import RotatingFileHandler
rotatingLogFileHandler = RotatingFileHandler('sync.log', maxBytes=254288000, backupCount=1)
logging.basicConfig(
        format='%(asctime)s %(levelname)s: %(message)s',
        datefmt='%Y-%m-%d %H:%M:%S',
        handlers=[
          rotatingLogFileHandler,
          logging.StreamHandler()
        ],
        level=getattr(logging,config.LOG_LEVEL)
        )


queue_passwords_to_update = None


ldap_destination_server = None
ldap_destination_connection = None
def try_ldap_bind(ldap_server,ldap_connection):
    """
    Tests wether or not binding/logging into the LDAP server works
    Returns an exception if not possible
    """
    ldap_server = ldap3.Server(config.LDAP_DESTINATION_SERVER_HOST, get_info=ldap3.ALL)
    ldap_connection = ldap3.Connection(ldap_server, config.LDAP_DESTINATION_SERVER_LOGIN_DN, config.LDAP_DESTINATION_SERVER_LOGIN_PASS, auto_bind=True)
    ldap_connection.bind()
    if not ldap_connection.bound :
        error_string = "Cannot establish connection to the destination LDAP server"
        logging.fatal(error_string)
        raise ConnectionError(error_string)

def create_async_sniffer(function_to_parse_packets_with, interface, *args, **kwargs):

    queue_passwords_to_update = kwargs.get('queue_passwords_to_update', False)

    if queue_passwords_to_update:
        sniffer = AsyncSniffer(iface=interface,prn=function_to_parse_packets_with(queue_passwords_to_update), store=False, filter="port 389")
        return sniffer
    else:
        sniffer = AsyncSniffer(iface=interface,prn=function_to_parse_packets_with, store=False, filter="port 389")
        return sniffer

def write_ldap_password_for_user(connection, user_dn, password):
    # create modification
    # write to user
    logging.debug("Updating password for user: '"+user_dn+"' with password: '"+password+"'")
    #connection.modify('uid=testuser1,ou=people,dc=example,dc=org', {'unicodePwd': [(ldap3.MODIFY_REPLACE, [password])]})
    #connection.extend.microsoft.modify_password('uid=testuser1,ou=people,dc=example,dc=org', password)
    hashed_password = hashed(ldap3.HASHED_SALTED_SHA, password)
    # TODO: If user doesn't exist, log an error
    connection.modify(user_dn, {'userPassword': [(ldap3.MODIFY_REPLACE,[hashed_password])]})


def start_async_interception(queue_passwords_to_update, ldap_destination_connection, interface, *args, **kwargs):
    # TODO What if we receive too many packets to handle?
    # The best thing would be to save all the packets in an array and, if we start consuming more than a limited amount of memory, we start throwing errors and discarding packets.

    # We use an array to "Pass by reference", otherwise basic types don't change outside this function and we can't stop the thread from the outside
    stopping = kwargs.get('stop_flag', [False])
    destination_ldap_server_users_dn_prefix = kwargs.get('destination_ldap_server_users_dn_prefix', False)
    destination_ldap_server_users_dn_suffix = kwargs.get('destination_ldap_server_users_dn_suffix', False)

    #packet_sniffer = create_async_sniffer(add_password_and_user_to_global_queue_from_ldap_packet,queue_passwords_to_update=queue_passwords_to_update)
    packet_sniffer = create_async_sniffer(wrapper_add_password_and_user_to_global_queue_from_ldap_packet, interface, queue_passwords_to_update=queue_passwords_to_update)
    packet_sniffer.start()

    while not stopping[0]:
      try:
        user, password = queue_passwords_to_update.get(timeout=5)
        #user,password = queue_passwords_to_update.get(block=True)
        if user != None and password != None:
          user_dn = destination_ldap_server_users_dn_prefix + user + destination_ldap_server_users_dn_suffix
          write_ldap_password_for_user(ldap_destination_connection, user_dn, password)
        if stopping[0]:
          break
      except Empty:
        logging.debug(traceback.format_exc())

def get_user_and_password_from_ldap_packet(packet):
    """
    Given an LDAP packet, returns a tuple of 2 elements
    [0] is the user
    [1] is the password
    Returs a tuple of None,None if no password was found
    """
    found_passwords = ldap_utils.extract_passwords_from_packets(packet)
    if len(found_passwords) > 0:
      found_users = ldap_utils.extract_users_uids_from_packets(packet)

      decoded_found_password = bytes(found_passwords[0]).decode('utf-8')
      decoded_found_user = bytes(found_users[0]).decode('utf-8')
      return decoded_found_user,decoded_found_password
    else:
      return None,None


def show_password_and_user_from_ldap_packet(packet):
    user, password = get_user_and_password_from_ldap_packet(packet)
    if user != None and password != None:
      print("Read password: '" + password + "' for user '"+user+"'")


def wrapper_add_password_and_user_to_global_queue_from_ldap_packet(queue_passwords_to_update):
    """
    We need a "Mother"/"Wrapper" function to be able to pass in the queue to the packet processing function
    """
    def add_password_and_user_to_global_queue_from_ldap_packet(packet):
        user_password_tuple = get_user_and_password_from_ldap_packet(packet)
    
        try:
          queue_passwords_to_update.put(user_password_tuple)
        except queue.Full:
          logging.debug(traceback.format_exc())
    return add_password_and_user_to_global_queue_from_ldap_packet


def show_only_passwords_debug_mode():
    #t = AsyncSniffer(iface="veth2",prn=lambda x: x.summary(), store=False, filter="port 389")
    #t = AsyncSniffer(iface="veth2",prn=show_password_and_user_from_ldap_packet, store=False, filter="port 389")
    t = create_async_sniffer(show_password_and_user_from_ldap_packet, config.INTERFACE_NAME)
    t.start()

    # Only show passwords for 60 seconds and then quit
    time.sleep(60)
    #results = t.stop()


def show_help():
    help_string = """
    Help string
    Short description
    Show usage
    """
    print(help_string)

def main():
    global queue_passwords_to_update
    global ldap_destination_connection
    queue_passwords_to_update = Queue(maxsize=1000)

    # TODO
    # Create a function handle_options that reads all environment variables, command line parameters and conf file properties and puts all of them in a dictionary.
    # Then, we can load this dictionary into the config module at runtime, so that we can also run tests on specific config variables. All the configuration should be a KEY->VALUE dictionary.
    # This way, the main function is completely re-testable, it only calls the configuration function and another function to actually run the program


    if config.INTERCEPT_TO_STDOUT_DEBUG_MODE:
      show_only_passwords_debug_mode()
    else:
      if config.INTERFACE_NAME:
        try_ldap_bind()
        start_async_interception(queue_passwords_to_update,ldap_destination_connection, config.INTERFACE_NAME,
                                 destination_ldap_server_users_dn_prefix=config.LDAP_DESTINATION_BASE_DN_PREFIX,
                                 destination_ldap_server_users_dn_suffix=config.LDAP_DESTINATION_BASE_DN
                                 )
    show_help()

if __name__ == "__main__":
    main()

