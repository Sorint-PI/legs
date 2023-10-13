from scapy.all import *

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

