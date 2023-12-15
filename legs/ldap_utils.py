from scapy.all import *
import ldap3.protocol.rfc4511 as rfc4511
from pyasn1.codec.native.encoder import encode
from pyasn1.codec.der.decoder import decode


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

          packet_contains_password = contains(userPasswordTypeStringAsIntegers,packet_as_integers)
          if packet_contains_password :
            to_decode = bytes(packet[3])
            decoded, rest_of_substrate = decode(to_decode, asn1Spec=rfc4511.LDAPMessage())
            decoded_as_dictionary = encode(decoded)
            
            
            userpassword_type_to_check = encode(decoded)['protocolOp']['modifyRequest']['changes'][0]['modification']['type']
            check = []
            for char in userpassword_type_to_check:
              check.append(char)
            if check == userPasswordTypeStringAsIntegers:
                found_password_as_bytes = encode(decoded)['protocolOp']['modifyRequest']['changes'][0]['modification']['vals'][0]
                found_password_as_integers = []
                for char in found_password_as_bytes:
                  found_password_as_integers.append(char)
                extracted_passwords.append(found_password_as_integers)


    return extracted_passwords



def extract_users_uids_from_packets(packets):
    userUIDTypeString = "uid=".encode("utf-8")
    userUIDTypeStringAsIntegers = []
    CommaStringAsIntegers = []
    for char in "uid=".encode("utf-8"):
      userUIDTypeStringAsIntegers.append(char)

    for char in ",".encode("utf-8"):
      CommaStringAsIntegers.append(char)

    userPasswordTypeString = "userpassword".encode("utf-8")
    userPasswordTypeStringAsIntegers = []
    for char in "userpassword".encode("utf-8"):
      userPasswordTypeStringAsIntegers.append(char)

    extracted_uids = []

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
          uid_type_exists_at_positions = contains(userUIDTypeStringAsIntegers,packet_as_integers)
          comma_exists_at_positions = contains(CommaStringAsIntegers,packet_as_integers)

          if uid_type_exists_at_positions is not False and password_type_exists_at_positions is not False:
              # We get the text between uid= and ",", take this as reference -> uid=<userUID>,cn=users...
              found_uid = packet_as_integers[uid_type_exists_at_positions[1]:comma_exists_at_positions[0]]
              extracted_uids.append(found_uid)
    return extracted_uids

