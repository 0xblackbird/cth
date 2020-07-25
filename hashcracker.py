#!/usr/bin/env python3

####################################################
#                                                  #
#           Code made by @BE1807                   #
#     (40e219a80dfa2239c096e18bca46fd15) :)        #
#						   #
####################################################
from concurrent.futures import wait, FIRST_COMPLETED
from pebble import ProcessPool
from Crypto.Hash import MD2
from Crypto.Hash import MD4
from Crypto.Hash import HMAC
import fileinput
import optparse
import os.path
import hashlib
import time
import sys
import os
	
parser = optparse.OptionParser("./%prog -H <hash> -w <wordlist> -T <hash type>", version = "%prog 1.7")
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

class color:
   PURPLE = '\033[1;35;48m'
   CYAN = '\033[1;36;48m'
   BLUE = '\033[1;34;48m'
   GREEN = '\033[1;32;48m'
   YELLOW = '\033[1;33;48m'
   RED = '\033[1;31;48m'
   BLACK = '\033[1;30;48m'
   END = '\033[1;37;0m'

list_menu = """Usage: {} -H <hash> -w <wordlist> -T <hash type>
	
	   Hash types:
     _____________________
    |          |          |
    |     0    |    MD5   |
    |     1    |    MD4   |
    |     2    |    MD2   |
    |     3    |   SHA1   |
    |     4    |  SHA-224 |
    |     5    |  SHA-256 |
    |     6    |  SHA-384 |
    |     7    |  SHA-512 |
    |     8    | SHA3-224 |
    |     9    | SHA3-256 |
    |    10    | SHA3-384 |
    |    11    | SHA3-512 |
    |__________|__________|
    
    More comming soon! ;)""" .format(sys.argv[0])



if len(sys.argv) == 0:
	print(color.RED + "[-] Incorrect syntax!" + color.END)
	sys.exit()
if list_types == True:
	print(list_menu .format(str(sys.argv[0])))
	sys.exit()
if user_hash == "":
	print(color.RED + "[-] No hash provided to crack! Use \"-h\" or \"--help\" to display the help menu!" + color.END)
	sys.exit()
else:	
	print(color.GREEN + line + color.END)
	print(color.BLACK + "Hash: \"{}\"" .format(str(user_hash)) + color.END)
		
if hash_type < 0:
	print(color.RED + "[-] Invalid hash-type! Use \"--list\" to display the all the hash types!" + color.END)		
	sys.exit()
elif hash_type > 10:
	print(color.RED + "[-] Invalid hash type! Please check it out!" + color.RED)
	sys.exit()
else:
	if hash_type == 0:
		print(color.BLACK + "Hash type: \"MD5\"" + color.END)
	elif hash_type == 1:
		print(color.BLACK + "Hash type: \"MD4\"" + color.END)
	elif hash_type == 2:
		print(color.BLACK + "Hash type: \"MD2\"" + color.END)
	elif hash_type == 3:
		print(color.BLACK + "Hash type: \"SHA-1\"" + color.END)
	elif hash_type == 4:
		print(color.BLACK + "Hash type: \"SHA-224\"" + color.END)
	elif hash_type == 5:
		print(color.BLACK + "Hash type: \"SHA-256\"" + color.END)
	elif hash_type == 6:
		print(color.BLACK + "Hash type: \"SHA-384\"" + color.END)
	elif hash_type == 7:
		print(color.BLACK + "Hash type: \"SHA-512\"" + color.END)
	elif hash_type == 8:
		print(color.BLACK + "Hash type: \"SHA3-224\"" + color.END)
	elif hash_type == 9:
		print(color.BLACK + "Hash type: \"SHA3-256\"" + color.END)
	elif hash_type == 10:
		print(color.BLACK + "Hash type: \"SHA3-384\"" + color.END)
	elif hash_type == 11:
		print(color.BLACK + "Hash type: \"SHA3-512\"" + color.END)
	else:
		print(color.RED + "[-] Invalid hash-type! Use \"--list\" to display the all the hash types!" + color.END)		
		sys.exit()

if wordlist == "":
	print(color.RED + "[-] No wordlist provided! Hashcracker will use the default wordlist (rockyou.txt)!" + color.END)
	print(color.BLACK + "Wordlist: \"{}\"" .format(str(wordlist)) + color.END)
	print(color.GREEN + line + color.END)
else:
	print(color.BLACK + "Wordlist: \"{}\"" .format(str(wordlist)) + color.END)
	print(color.GREEN + line + color.END)

def checkwordlist():
	if os.path.isfile(wordlist) == True:
		print(color.YELLOW + "[+] Starting password cracking!" + color.END)
	elif os.path.isfile(wordlist) == False:
		print(color.RED + "[-] \"{}\" does not exist! If you think that it really exists, try checking it once more!" .format(str(wordlist)) + color.END)
		sys.exit()
	else:
		print(color.RED + "[-] Error!" + color.END)
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
		elif hash_type == 2: #MD2
			passwd_h = MD2.new(passwd1.encode())
			passwd_hash = passwd_h.hexdigest()
		elif hash_type == 3: #SHA1
			passwd_h = hashlib.sha1(passwd1.encode())
			passwd_hash = passwd_h.hexdigest()
		elif hash_type == 4: #SHA-224
			passwd_h = hashlib.sha224(passwd1.encode())
			passwd_hash = passwd_h.hexdigest()
		elif hash_type == 5: #SHA-256
			passwd_h = hashlib.sha256(passwd1.encode())
			passwd_hash = passwd_h.hexdigest()
		elif hash_type == 6: #SHA-384
			passwd_h = hashlib.sha384(passwd1.encode())
			passwd_hash = passwd_h.hexdigest()
		elif hash_type == 7: #SHA-512
			passwd_h = hashlib.sha512(passwd1.encode())
			passwd_hash = passwd_h.hexdigest()
		elif hash_type == 8: #SHA3-224
			passwd_h = hashlib.sha3_224(passwd1.encode())
			passwd_hash = passwd_h.hexdigest()
		elif hash_type == 9: #SHA3-256
			passwd_h = hashlib.sha3_256(passwd1.encode())
			passwd_hash = passwd_h.hexdigest()
		elif hash_type == 10: #SHA3-384
			passwd_h = hashlib.sha3_384(passwd1.encode())
			passwd_hash = passwd_h.hexdigest()
		elif hash_type == 11: #SHA3-512
			passwd_h = hashlib.sha3_512(passwd1.encode())
			passwd_hash = passwd_h.hexdigest()
		else:
			print(color.RED + "[-] Invalid hash type...Exiting!" + color.END)
			sys.exit()
		if verbose == True:
			print(color.BLACK + "Trying {}" .format(str(repr(passwd1))) + color.END)
		if user_hash == passwd_hash:
			hash_cracked = True
			print(color.GREEN + "[+] Hash cracked! Results: " + str(line) + color.END)
			endTime = time.time()
			deltaTime = endTime - startTime
			sys.stdout.write("\033[F")
			print(color.GREEN + "[+] Cracking finished in {}s" .format(str(format(deltaTime, ".3f"))) + color.END)
			sys.exit()
	print(color.RED + "[-] Hash not found! Maybe try an other wordlist." + color.END)
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
			elif hash_type == 2: #MD2
				passwd_h = MD2.new(passwd1.encode())
				passwd_hash = passwd_h.hexdigest()
			elif hash_type == 3: #SHA1
				passwd_h = hashlib.sha1(passwd1.encode())
				passwd_hash = passwd_h.hexdigest()
			elif hash_type == 4: #SHA-224
				passwd_h = hashlib.sha224(passwd1.encode())
				passwd_hash = passwd_h.hexdigest()
			elif hash_type == 5: #SHA-256
				passwd_h = hashlib.sha256(passwd1.encode())
				passwd_hash = passwd_h.hexdigest()
			elif hash_type == 6: #SHA-384
				passwd_h = hashlib.sha384(passwd1.encode())
				passwd_hash = passwd_h.hexdigest()
			elif hash_type == 7: #SHA-512
				passwd_h = hashlib.sha512(passwd1.encode())
				passwd_hash = passwd_h.hexdigest()
			elif hash_type == 8: #SHA3-224
				passwd_h = hashlib.sha3_224(passwd1.encode())
				passwd_hash = passwd_h.hexdigest()
			elif hash_type == 9: #SHA3-256
				passwd_h = hashlib.sha3_256(passwd1.encode())
				passwd_hash = passwd_h.hexdigest()
			elif hash_type == 10: #SHA3-384
				passwd_h = hashlib.sha3_384(passwd1.encode())
				passwd_hash = passwd_h.hexdigest()
			elif hash_type == 11: #SHA3-512
				passwd_h = hashlib.sha3_512(passwd1.encode())
				passwd_hash = passwd_h.hexdigest()
			else:
				print(color.RED + "[-] Invalid hash type...Exiting!" + color.END)
				sys.exit()
			if verbose == True:
				print(color.BLACK + "Trying {}" .format(str(repr(passwd1))) + color.END)
			if user_hash == passwd_hash:
				hash_cracked = True
				print(color.GREEN + "[+] Hash cracked! Results: " + str(line) + color.END)
				endTime = time.time()
				deltaTime = endTime - startTime
				sys.stdout.write("\033[F")
				print(color.GREEN + "[+] Cracking finished in {}s" .format(str(format(deltaTime, ".3f"))) + color.END)
				sys.exit()
		print(color.RED + "[-] Hash not found! Maybe try an other wordlist." + color.END)
		sys.exit()

try:
	if __name__ == "__main__":
		startTime = time.time()
		checkwordlist()
		with ProcessPool(max_workers=2) as pool:
			f1 = pool.schedule(readNormal)
			f2 = pool.schedule(readBackwards)
			done, not_done = wait((f1, f2), return_when=FIRST_COMPLETED)
			for f in not_done:
				f.cancel()

except KeyboardInterrupt:
	print(color.RED + "\n[-] \"Ctrl+^C\" detected! Exiting..." + color.END)
	sys.exit()

except IndexError:
	print(color.RED + "[-] Index Error: syntax does not make sens to me! Please check that out!" + color.END)
	sys.exit()
except SyntaxError:
	print(color.RED + "[-] \nSyntax error!" + color.END)
	sys.exit()
