#!/usr/bin/env python3

####################################################
#                                                  #
#           Code made by @BE1807                   #
#     (40e219a80dfa2239c096e18bca46fd15) :)        #
#						   #
####################################################
import optparse
import hashlib
import os.path
import time
import sys
	
parser = optparse.OptionParser("./%prog -H <hash> -w <wordlist> -t <hash type>", version = "%prog 1.0")
parser.add_option("-H", "--hash", dest="hash", type="string", default="", help="Your hash that you want to crack")
parser.add_option("-w", "--wordlist", dest="wordlist", type="string", default="/usr/share/wordlists/rockyou.txt", help="The wordlist that is going to do the job (default: \"/usr/share/wordlists/rockyou.txt\")")
parser.add_option("-t", "--type", dest="num", type="int", default=0, help="Type of the hash that you want to crack")
parser.add_option("-v", "--verbose", dest="verbose", action="store_true", default=False, help="Turn on verbosity mode")
parser.add_option("--list", dest="list_types", action="store_true", default=False, help="Display all the hash types and exit")
(options, args) = parser.parse_args()

user_hash = options.hash
wordlist = options.wordlist
hash_type = options.num
verbose = options.verbose
list_types = options.list_types
line = "-" * 110

list_menu = """Usage: {} -H <hash> -w <wordlist> -t <hash type>

Hash types:
1	MD5
2	SHA1
3	SHA-224
4	SHA-256
5	SHA-384
6	SHA-512
"""


if len(sys.argv) == 0:
	print("No user input")
	sys.exit()
if list_types == True:
	print(list_menu .format(str(sys.argv[0])))
	sys.exit()
if user_hash == "":
	print("[-] No hash provided to crack! Use \"-h\" or \"--help\" to display the help menu!")
	sys.exit()
else:
	print(line)
	print("Hash: \"{}\"" .format(str(user_hash)))
		
if hash_type == 0:
	print("[-] No hash type provided! Exiting...")
	sys.exit()
elif hash_type > 6:
	print("[-] Invalid hash type! Please check it out!")
	sys.exit()
else:
	if hash_type == 1:
		print("Hash type: \"MD5\"")
	elif hash_type == 2:
		print("Hash type: \"SHA-1\"")
	elif hash_type == 3:
		print("Hash type: \"SHA-224\"")
	elif hash_type == 4:
		print("Hash type: \"SHA-256\"")
	elif hash_type == 5:
		print("Hash type: \"SHA-384\"")
	elif hash_type == 6:
		print("Hash type: \"SHA-512\"")
	else:
		print("Invalid hash-type! Use \"--list\" to display the all the hash types!")		
		sys.exit()

if wordlist == "":
	print("[-]No wordlist provided! We will use the default!")
	print("Wordlist: \"{}\"" .format(str(wordlist)))
	print(line)
else:
	print("Wordlist: \"{}\"" .format(str(wordlist)))
	print(line)


def checkwordlist():
	if os.path.isfile(wordlist) == True:
		print("[+] Starting password cracking!")
	elif os.path.isfile(wordlist) == False:
		print("[-] \"" + str(wordlist) + "\" does not exist! If you think that it really exists, try checking your spelling!")
		sys.exit()
	else:
		print("[-] Error!")
		sys.exit()

startTime = time.time()


with open(wordlist, "r", encoding="ISO-8859-1") as FileObj:
	password = []
	for line in FileObj:
		password.append(line.replace("\n", ""))	

print("[+] Wordlist loaded! Cracking can begin!")

# MD5 (Message Diggest 5)
def type_1():
	if verbose == True:
		for passwd in password:
			passwd_h = hashlib.md5(passwd.encode())
			passwd_hash = passwd_h.hexdigest()
			print("Trying \"{}\"" .format(str(passwd)))
			if user_hash == passwd_hash:
				print("[+] Hash cracked! Results: " + str(passwd))
				endTime = time.time()
				deltaTime = endTime -startTime
				print("[+] Cracking finished in {}s" .format(str(format(deltaTime, ".2f"))))
				sys.exit()
	elif verbose == False:
		for passwd in password:
			passwd_h = hashlib.md5(passwd.encode())
			passwd_hash = passwd_h.hexdigest()
			if user_hash == passwd_hash:
				print("[+] Hash cracked! Results: " + str(passwd))
				endTime = time.time()
				deltaTime = endTime -startTime
				print("[+] Cracking finished in {}s" .format(str(format(deltaTime, ".2f"))))
				sys.exit()
	else:
		print("[-] Error")
		sys.exit()

# SHA-1 (Secure Hash Algorithm 1)
def type_2():
	if verbose == True:
		for passwd in password:
			passwd_h = hashlib.sha1(passwd.encode())
			passwd_hash = passwd_h.hexdigest()
			print("Trying \"{}\"" .format(str(passwd)))
			if user_hash == passwd_hash:
				print("[+] Hash cracked! Results: " + str(passwd))
				endTime = time.time()
				deltaTime = endTime -startTime
				print("[+] Cracking finished in {}s" .format(str(format(deltaTime, ".2f"))))
				sys.exit()
	elif verbose == False:
		for passwd in password:
			passwd_h = hashlib.sha1(passwd.encode())
			passwd_hash = passwd_h.hexdigest()
			if user_hash == passwd_hash:
				print("[+] Hash cracked! Results: " + str(passwd))
				endTime = time.time()
				deltaTime = endTime -startTime
				print("[+] Cracking finished in {}s" .format(str(format(deltaTime, ".2f"))))
				sys.exit()
	else:
		print("[-] Error")
		sys.exit()

# SHA-2 (Secure Hash Algorithm 2) [SHA-224]
def type_3():
	if verbose == True:
		for passwd in password:
			passwd_h = hashlib.sha224(passwd.encode())
			passwd_hash = passwd_h.hexdigest()
			print("Trying \"{}\"" .format(str(passwd)))
			if user_hash == passwd_hash:
				print("[+] Hash cracked! Results: " + str(passwd))
				endTime = time.time()
				deltaTime = endTime -startTime
				print("[+] Cracking finished in {}s" .format(str(format(deltaTime, ".2f"))))
				sys.exit()	
	elif verbose == False:
		for passwd in password:
			passwd_h = hashlib.sha224(passwd.encode())
			passwd_hash = passwd_h.hexdigest()
			if user_hash == passwd_hash:
				print("[+] Hash cracked! Results: " + str(passwd))
				endTime = time.time()
				deltaTime = endTime -startTime
				print("[+] Cracking finished in {}s" .format(str(format(deltaTime, ".2f"))))
				sys.exit()
	else:
		print("[-] Error")
		sys.exit()


# SHA-2 (Secure Hash Algorithm 2) [SHA-256]
def type_4():
	if verbose == True:
		for passwd in password:
			passwd_h = hashlib.sha256(passwd.encode())
			passwd_hash = passwd_h.hexdigest()
			print("Trying \"{}\"" .format(str(passwd)))
			if user_hash == passwd_hash:
				print("[+] Hash cracked! Results: " + str(passwd))
				endTime = time.time()
				deltaTime = endTime -startTime
				print("[+] Cracking finished in {}s" .format(str(format(deltaTime, ".2f"))))
				sys.exit()
	elif verbose == False:
		for passwd in password:
			passwd_h = hashlib.sha256(passwd.encode())
			passwd_hash = passwd_h.hexdigest()
			if user_hash == passwd_hash:
				print("[+] Hash cracked! Results: " + str(passwd))
				endTime = time.time()
				deltaTime = endTime -startTime
				print("[+] Cracking finished in {}s" .format(str(format(deltaTime, ".2f"))))
				sys.exit()
	else:
		print("[-] Error")
		sys.exit()

# SHA-2 (Secure Hash Algorithm 2) [SHA-384]
def type_5():
	if verbose == True:
		for passwd in password:
			passwd_h = hashlib.sha384(passwd.encode())
			passwd_hash = passwd_h.hexdigest()
			print("Trying \"{}\"" .format(str(passwd)))
			if user_hash == passwd_hash:
				print("[+] Hash cracked! Results: " + str(passwd))
				endTime = time.time()
				deltaTime = endTime -startTime
				print("[+] Cracking finished in {}s" .format(str(format(deltaTime, ".2f"))))
				sys.exit()
	elif verbose == False:
		for passwd in password:
			passwd_h = hashlib.sha384(passwd.encode())
			passwd_hash = passwd_h.hexdigest()
			if user_hash == passwd_hash:
				print("[+] Hash cracked! Results: " + str(passwd))
				endTime = time.time()
				deltaTime = endTime -startTime
				print("[+] Cracking finished in {}s" .format(str(format(deltaTime, ".2f"))))
				sys.exit()
	else:
		print("[-] Error")
		sys.exit()
	
# SHA-2 (Secure Hash Algorithm 2) [SHA-512]
def type_6():
	if verbose == True:
		for passwd in password:
			passwd_h = hashlib.sha512(passwd.encode())
			passwd_hash = passwd_h.hexdigest()
			print("Trying \"{}\"" .format(str(passwd)))
			if user_hash == passwd_hash:
				print("[+] Hash cracked! Results: " + str(passwd))
				endTime = time.time()
				deltaTime = endTime -startTime
				print("[+] Cracking finished in {}s" .format(str(format(deltaTime, ".2f"))))
				sys.exit()
	elif verbose == False:
		for passwd in password:
			passwd_h = hashlib.sha512(passwd.encode())
			passwd_hash = passwd_h.hexdigest()
			if user_hash == passwd_hash:
				print("[+] Hash cracked! Results: " + str(passwd))
				endTime = time.time()
				deltaTime = endTime -startTime
				print("[+] Cracking finished in {}s" .format(str(format(deltaTime, ".2f"))))
				sys.exit()
	else:
		print("[-] Error")
		sys.exit()

try:
	if hash_type == 1:
		type_1()
	elif hash_type == 2:
		type_2()
	elif hash_type == 3:
		type_3()
	elif hash_type == 4:
		type_4()
	elif hash_type == 5:
		type_5()
	elif hash_type == 6:
		type_6()
	else:
		print("Invalid hash-type! Use \"--list\" to display the all the hash types!")		
		sys.exit()

except KeyboardInterrupt:
	print("\n\"Ctrl+C\" detected! Exiting...")
	sys.exit()

except IndexError:
	print("Index Error arrived! Syntax does not make sens to me! Please check that out!")
	sys.exit()
