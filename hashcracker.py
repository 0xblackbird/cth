#!/usr/bin/env python3

####################################################
#                                                  #
#           Code made by @BE1807                   #
#     (40e219a80dfa2239c096e18bca46fd15) :))       #
#						   #
####################################################
from concurrent.futures import wait, FIRST_COMPLETED
from pebble import ProcessPool
from Crypto.Hash import MD4
import fileinput
import optparse
import os.path
import hashlib
import time
import sys
import os
	
parser = optparse.OptionParser("./%prog -H <hash> -w <wordlist> -T <hash type>", version = "%prog 1.6")
parser.add_option("-H", "--hash", dest="hash", type="string", default="", help="Your hash that you want to crack")
parser.add_option("-w", "--wordlist", dest="wordlist", type="string", default="/usr/share/wordlists/rockyou.txt", help="The wordlist that is going to do the job (default: \"/usr/share/wordlists/rockyou.txt\")")
parser.add_option("-T", "--type", dest="num", type="int", default=0, help="Specify the hash type, use \"-L/--list\" for more info (default: \"0\" (md-5))")
parser.add_option("-v", "--verbose", dest="verbose", action="store_true", default=False, help="Turn on verbosity mode (default: \"False\")")
parser.add_option("-L", "--list", dest="list_types", action="store_true", default=False, help="Display all the hash types and exit")
(options, args) = parser.parse_args()

user_hash = options.hash
wordlist = options.wordlist
hash_type = options.num
verbose = options.verbose
list_types = options.list_types
line = "-" * 110
startTime = time.time()

list_menu = """Usage: {} -H <hash> -w <wordlist> -T <hash type>
	
	   Hash types:
     _____________________ 
    |                     |
    |     0    |    MD5   |
    |	  1    |    MD4   |
    |     2    |   SHA1   |
    |     3    | SHA-224  |
    |     4    | SHA-256  |
    |     5    | SHA-384  |
    |     6    | SHA-512  |
    |	  7    | SHA3-224 |
    |	  8    | SHA3-256 |
    |     9    | SHA3-384 |
    |    10    | SHA3-512 |
    |__________|__________|
    
    More comming soon! ;)""" .format(sys.argv[0])



if len(sys.argv) == 0:
	print("[-] Incorrect syntax!")
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
		
if hash_type < 0:
	print("[-] Invalid hash-type! Use \"--list\" to display the all the hash types!")		
	sys.exit()
elif hash_type > 10:
	print("[-] Invalid hash type! Please check it out!")
	sys.exit()
else:
	if hash_type == 0:
		print("Hash type: \"MD5\"")
	elif hash_type == 1:
		print("Hash type: \"MD4\"")
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
	elif hash_type == 7:
		print("Hash type: \"SHA3-224\"")
	elif hash_type == 8:
		print("Hash type: \"SHA3-256\"")
	elif hash_type == 9:
		print("Hash type: \"SHA3-384\"")
	elif hash_type == 10:
		print("Hash type: \"SHA3-512\"")
	else:
		print("[-] Invalid hash-type! Use \"--list\" to display the all the hash types!")		
		sys.exit()

if wordlist == "":
	print("[-] No wordlist provided! We will use the default wordlist!")
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

def readBackwards():
	for line in reversed(list(open(wordlist, "r", encoding="ISO-8859-1"))):
		passwd1 = line.rstrip()
		if hash_type == 0: #MD5
			passwd_h = hashlib.md5(passwd1.encode())
			passwd_hash = passwd_h.hexdigest()
		elif hash_type == 1: #MD4
			passwd_h = MD4.new(passwd1.encode())
			passwd_hash = passwd_h.hexdigest()
		elif hash_type == 2: #SHA1
			passwd_h = hashlib.sha1(passwd1.encode())
			passwd_hash = passwd_h.hexdigest()
		elif hash_type == 3: #SHA-224
			passwd_h = hashlib.sha224(passwd1.encode())
			passwd_hash = passwd_h.hexdigest()
		elif hash_type == 4: #SHA-256
			passwd_h = hashlib.sha256(passwd1.encode())
			passwd_hash = passwd_h.hexdigest()
		elif hash_type == 5: #SHA-384
			passwd_h = hashlib.sha384(passwd1.encode())
			passwd_hash = passwd_h.hexdigest()
		elif hash_type == 6: #SHA-512
			passwd_h = hashlib.sha512(passwd1.encode())
			passwd_hash = passwd_h.hexdigest()
		elif hash_type == 7: #SHA3-224
			passwd_h = hashlib.sha3_224(passwd1.encode())
			passwd_hash = passwd_h.hexdigest()
		elif hash_type == 8: #SHA3-256
			passwd_h = hashlib.sha3_256(passwd1.encode())
			passwd_hash = passwd_h.hexdigest()
		elif hash_type == 9: #SHA3-384
			passwd_h = hashlib.sha3_384(passwd1.encode())
			passwd_hash = passwd_h.hexdigest()
		elif hash_type == 10: #SHA3-512
			passwd_h = hashlib.sha3_512(passwd1.encode())
			passwd_hash = passwd_h.hexdigest()
		else:
			print("[-] Invalid hash type...Exiting!")
			sys.exit()
		if verbose == True:
			print("Trying {}" .format(passwd1))
		if user_hash == passwd_hash:
			hash_cracked = True
			print("[+] Hash cracked while reading backwards! Results: " + str(line))
			endTime = time.time()
			deltaTime = endTime - startTime
			print("[+] Cracking finished in {}s" .format(str(format(deltaTime, ".2f"))))
			sys.exit()
	print("[-] Hash not found! Maybe try an other wordlist.")
	sys.exit()


def readNormal():
	with open(wordlist, "r", encoding="ISO-8859-1") as FileObj:
		for line in FileObj:
			passwd1 = line.replace("\n", "")
			if hash_type == 0: #MD5
				passwd_h = hashlib.md5(passwd1.encode())
				passwd_hash = passwd_h.hexdigest()
			elif hash_type == 1: #MD4
				passwd_h = MD4.new(passwd1.encode())
				passwd_hash = passwd_h.hexdigest()
			elif hash_type == 2: #SHA1
				passwd_h = hashlib.sha1(passwd1.encode())
				passwd_hash = passwd_h.hexdigest()
			elif hash_type == 3: #SHA-224
				passwd_h = hashlib.sha224(passwd1.encode())
				passwd_hash = passwd_h.hexdigest()
			elif hash_type == 4: #SHA-256
				passwd_h = hashlib.sha256(passwd1.encode())
				passwd_hash = passwd_h.hexdigest()
			elif hash_type == 5: #SHA-384
				passwd_h = hashlib.sha384(passwd1.encode())
				passwd_hash = passwd_h.hexdigest()
			elif hash_type == 6: #SHA-512
				passwd_h = hashlib.sha512(passwd1.encode())
				passwd_hash = passwd_h.hexdigest()
			elif hash_type == 7: #SHA3-224
				passwd_h = hashlib.sha3_224(passwd1.encode())
				passwd_hash = passwd_h.hexdigest()
			elif hash_type == 8: #SHA3-256
				passwd_h = hashlib.sha3_256(passwd1.encode())
				passwd_hash = passwd_h.hexdigest()
			elif hash_type == 9: #SHA3-384
				passwd_h = hashlib.sha3_384(passwd1.encode())
				passwd_hash = passwd_h.hexdigest()
			elif hash_type == 10: #SHA3-512
				passwd_h = hashlib.sha3_512(passwd1.encode())
				passwd_hash = passwd_h.hexdigest()
			else:
				print("[-] Invalid hash type...Exiting!")
				sys.exit()
			if verbose == True:
				print("Trying {}" .format(passwd1))
			if user_hash == passwd_hash:
				hash_cracked = True
				print("[+] Hash cracked while reading normal! Results: " + str(line))
				endTime = time.time()
				deltaTime = endTime - startTime
				print("[+] Cracking finished in {}s" .format(str(format(deltaTime, ".2f"))))
				sys.exit()
		print("[-] Hash not found! Maybe try an other wordlist.")
		sys.exit()

try:
	if __name__ == "__main__":
		startTime = time.time()
		with ProcessPool(max_workers=2) as pool:
			f1 = pool.schedule(readNormal)
			f2 = pool.schedule(readBackwards)
			done, not_done = wait((f1, f2), return_when=FIRST_COMPLETED)
			for f in not_done:
				f.cancel()

except KeyboardInterrupt:
	print("\n[-] \"Ctrl+^C\" detected! Exiting...")
	sys.exit()

except IndexError:
	print("[-] Index Error arrived! Syntax does not make sens to me! Please check that out!")
	sys.exit()
