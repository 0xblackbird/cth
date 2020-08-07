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
from random import uniform
import fileinput
import whirlpool
import argparse
import binascii
import os.path
import hashlib
import time
import json
import sys
import os

parser = argparse.ArgumentParser(prog="cth.py", usage="./%(prog)s -H <HASH> [OPTIONS] -T <NUM> -w <WORDLIST>", description="Ultra fast hashcracking tool written in Python3", epilog="Thank you for using this tool! Please take a moment and give some feedback on the tool: @BE1807V or be1807v@protonmail.com")
parser.add_argument("-H", "-hash", default="", help="Your hash that you want to crack")
parser.add_argument("-w", "-wordlist", default="/usr/share/wordlists/rockyou.txt", help="The wordlist that is going to do the job (default: \"/usr/share/wordlists/rockyou.txt\")")
parser.add_argument("-T", "-type", type=int, default=0, help="Specify the hash type, use \"-L/-list\" for more info (default: \"0\" (md-5))")
parser.add_argument("-o", "-output", action="store_true", default=False, help="Output the result in a text file (default: \"False\")")
parser.add_argument("-oJ", "-output-json", action="store_true", default=False, help="Output the result in JSON format (default: \"False\")")
parser.add_argument("-I", "-interactive", action="store_true", default=False, help="Go through steps instead of typing all the flags manually")
parser.add_argument("-v", "-verbose", action="store_true", default=False, help="Turn on verbosity mode (default: \"False\")")
parser.add_argument("-L", "-list", action="store_true", default=False, help="Display all the hash types and exit")
parser.add_argument("-V", "-version", action="version", version="%(prog)s 2.0")
args = parser.parse_args()

user_hash = args.H
wordlist = args.w
hash_type = args.T
verbose = args.v
output = args.o
output_json = args.oJ
list_types = args.L
interactive = args.I
line = "-" * 110
startTime = time.time()

class color:
	PURPLE = '\033[1;35;48m'
	CYAN = '\033[1;36;48m'
	BLUE = '\033[1;34;48m'
	ORANGE = '\033[1;38;48m'
	GREEN = '\033[1;32;48m'
	YELLOW = '\033[1;33;48m'
	RED = '\033[1;31;48m'
	BLACK = '\033[1;30;48m'
	BLINK = '\033[1;6;48m'
	END = '\033[1;37;0m'
   
def typeText(text, delay):
	for i in text:
		print(i, end = "")
		sys.stdout.flush()
		time.sleep(uniform(0, delay))
	print("")

print(color.RED + """
   _____ _______ _    _ 
  / ____|__   __| |  | |
 | |       | |  | |__| |
 | |       | |  |  __  |
 | |____   | |  | |  | |
  \_____|  |_|  |_|  |_|
                        
""")
sys.stdout.write("\033[F")
typeText("CRACK THE HASH", 0.035)
print(color.CYAN)
sys.stdout.write("\033[F")
typeText("@BE1807V", 0.035)

if interactive == True:
	question = "Please provide the hash that you want to crack: \n"
	print(color.BLUE)
	for i in question:
		print(i, end = "")
		sys.stdout.flush()
		time.sleep(0.025)
	user_hash = str(input(color.BLUE + ">>> " + color.RED))
	if user_hash == "":
		print(color.RED + "[-] No hash provided! Goodbye." + color.END)
		sys.exit()
	sys.stdout.write("\033[F")


	question = "What type is the hash you provided? \n"
	print(color.BLUE)
	for i in question:
		print(i, end = "")
		sys.stdout.flush()
		time.sleep(0.025)
	hash_type = int(input(color.BLUE + ">>> " + color.RED))
	sys.stdout.write("\033[F")
	if hash_type == "":
		hash_type = 0

	question = "What wordlist do you want to use? Leave blank to use the default wordlist: \n"
	print(color.BLUE)
	for i in question:
		print(i, end = "")
		sys.stdout.flush()
		time.sleep(0.025)
	wordlist = str(input(color.BLUE + ">>> " + color.RED))
	sys.stdout.write("\033[F")

list_menu = color.ORANGE + """Usage: ./cth.py -H <HASH> [OPTIONS] -T <NUM> -w <WORDLIST>

	   Hash types:
     ______________________
    |          |           |
    |     0    |    MD5    |
    |     1    |    MD4    |
    |     2    |    MD2    |
    |     3    |   SHA1    |
    |     4    |  SHA-224  |
    |     5    |  SHA-256  |
    |     6    |  SHA-384  |
    |     7    |  SHA-512  |
    |     8    |  SHA3-224 |
    |     9    |  SHA3-256 |
    |    10    |  SHA3-384 |
    |    11    |  SHA3-512 |
    |    12    |  BLAKE2s  |
    |    13    |  BLAKE2b  |
    |    14    |   NTLM    |
    |    15    | Whirlpool |
    |__________|___________|

    More comming soon! ;)""" + color.END

if len(sys.argv) == 0:
	print(color.RED + "[-] Incorrect syntax!" + color.END)
	sys.exit()
if list_types == True:
	print(list_menu)
	sys.exit()
if user_hash == "":
	print(color.BLINK + color.RED + "[-] No hash provided to crack! Use \"-h\" or \"--help\" to display the help menu!" + color.END)
	sys.exit()
else:
	print(color.BLACK + line + color.END)
	print(color.CYAN + "Hash: " + color.RED + "\"" + str(user_hash) + "\"" + color.END)

if hash_type < 0:
	print(color.RED + "[-] Invalid hash-type! Use \"-list\" to display the all the hash types!" + color.END)		
	sys.exit()
else:
	if hash_type == 0:
		print(color.CYAN + "Hash type: " + color.RED + "\"MD5\"" + color.END)
	elif hash_type == 1:
		print(color.CYAN + "Hash type: " + color.RED + "\"MD4\"" + color.END)
	elif hash_type == 2:
		print(color.CYAN + "Hash type: " + color.RED + "\"MD2\"" + color.END)
	elif hash_type == 3:
		print(color.CYAN + "Hash type: " + color.RED + "\"SHA-1\"" + color.END)
	elif hash_type == 4:
		print(color.CYAN + "Hash type: " + color.RED + "\"SHA-224\"" + color.END)
	elif hash_type == 5:
		print(color.CYAN + "Hash type: " + color.RED + "\"SHA-256\"" + color.END)
	elif hash_type == 6:
		print(color.CYAN + "Hash type: " + color.RED + "\"SHA-384\"" + color.END)
	elif hash_type == 7:
		print(color.CYAN + "Hash type: " + color.RED + "\"SHA-512\"" + color.END)
	elif hash_type == 8:
		print(color.CYAN + "Hash type: " + color.RED + "\"SHA3-224\"" + color.END)
	elif hash_type == 9:
		print(color.CYAN + "Hash type: " + color.RED + "\"SHA3-256\"" + color.END)
	elif hash_type == 10:
		print(color.CYAN + "Hash type: " + color.RED + "\"SHA3-384\"" + color.END)
	elif hash_type == 11:
		print(color.CYAN + "Hash type: " + color.RED + "\"SHA3-512\"" + color.END)
	elif hash_type == 12:
		print(color.CYAN + "Hash type: " + color.RED + "\"BLAKE2s\"" + color.END)
	elif hash_type == 13:
		print(color.CYAN + "Hash type: " + color.RED + "\"BLAKE2b\"" + color.END)
	elif hash_type == 14:
		print(color.CYAN + "Hash type: " + color.RED + "\"NTLM\"" + color.END)
	elif hash_type == 15:
		print(color.CYAN + "Hash type: " + color.RED + "\"Whirlpool\"" + color.END)
	else:
		print(color.RED + "[-] Invalid hash-type! Use \"-list\" to display the all the hash types!" + color.END)		
		sys.exit()


if wordlist == "":
	wordlist = "/usr/share/wordlists/rockyou.txt"
	print(color.CYAN + "Wordlist: " + color.RED + "\"" + str(wordlist) + "\"" + color.END)
	print(color.BLACK + line + color.END)
else:
	print(color.CYAN + "Wordlist: " + color.RED + "\"" + str(wordlist) + "\"" + color.END)
	print(color.BLACK + line + color.END)

def checkwordlist():
	if os.path.isfile(wordlist) == True:
		print(color.ORANGE + "[+] Starting password cracking!" + color.END)
	elif os.path.isfile(wordlist) == False:
		print(color.RED + "[-] \"{}\" does not exist! If you think that it really exists, try checking your spelling!" .format(str(wordlist)) + color.END)
		sys.exit()
	else:
		print(color.RED + "[-] Error!" + color.END)
		sys.exit()

def readBackwards():
	for line in reversed(list(open(wordlist, "r", encoding="ISO-8859-1"))):
		passwd1 = line.rstrip()
		if hash_type == 0: #MD5
			passwd_hash = hashlib.md5(passwd1.encode()).hexdigest()
		elif hash_type == 1: #MD4
			passwd_hash = MD4.new(passwd1.encode()).hexdigest()
		elif hash_type == 2: #MD2
			passwd_h = MD2.new(passwd1.encode()).hexdigest()
		elif hash_type == 3: #SHA1
			passwd_h = hashlib.sha1(passwd1.encode()).hexdigest()
		elif hash_type == 4: #SHA-224
			passwd_h = hashlib.sha224(passwd1.encode()).hexdigest()
		elif hash_type == 5: #SHA-256
			passwd_h = hashlib.sha256(passwd1.encode()).hexdigest()
		elif hash_type == 6: #SHA-384
			passwd_h = hashlib.sha384(passwd1.encode()).hexdigest()
		elif hash_type == 7: #SHA-512
			passwd_h = hashlib.sha512(passwd1.encode()).hexdigest()
		elif hash_type == 8: #SHA3-224
			passwd_h = hashlib.sha3_224(passwd1.encode()).hexdigest()
		elif hash_type == 9: #SHA3-256
			passwd_h = hashlib.sha3_256(passwd1.encode()).hexdigest()
		elif hash_type == 10: #SHA3-384
			passwd_h = hashlib.sha3_384(passwd1.encode()).hexdigest()
		elif hash_type == 11: #SHA3-512
			passwd_h = hashlib.sha3_512(passwd1.encode()).hexdigest()
		elif hash_type == 12: #BLAKE2s
			passwd_h = hashlib.blake2s(passwd1.encode()).hexdigest()
		elif hash_type == 13: #BLAKE2b
			passwd_h = hashlib.blake2b(passwd1.encode()).hexdigest()
		elif hash_type == 14: #NTLM
			passwd_hash = hashlib.new('md4', passwd1.encode('utf-16le')).hexdigest()
		elif hash_type == 15: #Whirlpool
			passwd_hash = whirlpool.new(passwd1.encode()).hexdigest()
		else:
			print(color.RED + "[-] Invalid hash type...Exiting!" + color.END)
			sys.exit()
		if verbose == True:
			print(color.BLACK + "Trying {}" .format(str(repr(passwd1))) + color.END)
		if user_hash == passwd_hash:
			hash_cracked = True
			print(color.GREEN + "[+] Hash cracked! Results: " + color.RED + str(line) + color.END)
			endTime = time.time()
			deltaTime = endTime - startTime
			sys.stdout.write("\033[F")
			print(color.GREEN + "[+] Cracking finished in " + color.RED + str(format(deltaTime, ".3f")) + color.END + color.GREEN + "s" + color.END)
			if output == True:
				print("[+] Hash cracked! Results: " + str(line) + "[+] Cracking finished in " + str(format(deltaTime, ".3f")) + "s", file=open("results.txt", "a"))
				print(color.ORANGE + "Results saved successfully in ./results.txt!" + color.END)
			if output_json == True:
				results = {
					"Hash": str(user_hash),
					"Cracked hash": str(line).replace("\n",""),
					"Time":format(deltaTime, ".3f")
				}
				results_json = json.dumps(results, indent=2)
				print(results_json, file=open("results.json", "w"))
				print(color.ORANGE + "Results saved successfully in ./results.json!" + color.END)
			sys.exit()
	print(color.RED + "[-] Hash not found! Maybe another wordlist would help." + color.END)
	sys.exit()


def readNormal():
	with open(wordlist, "r", encoding="ISO-8859-1") as FileObj:
		for line in FileObj:
			passwd1 = line.replace("\n", "")
			if hash_type == 0: #MD5
				passwd_hash = hashlib.md5(passwd1.encode()).hexdigest()
			elif hash_type == 1: #MD4
				passwd_hash = MD4.new(passwd1.encode()).hexdigest()
			elif hash_type == 2: #MD2
				passwd_h = MD2.new(passwd1.encode()).hexdigest()
			elif hash_type == 3: #SHA1
				passwd_h = hashlib.sha1(passwd1.encode()).hexdigest()
			elif hash_type == 4: #SHA-224
				passwd_h = hashlib.sha224(passwd1.encode()).hexdigest()
			elif hash_type == 5: #SHA-256
				passwd_h = hashlib.sha256(passwd1.encode()).hexdigest()
			elif hash_type == 6: #SHA-384
				passwd_h = hashlib.sha384(passwd1.encode()).hexdigest()
			elif hash_type == 7: #SHA-512
				passwd_h = hashlib.sha512(passwd1.encode()).hexdigest()
			elif hash_type == 8: #SHA3-224
				passwd_h = hashlib.sha3_224(passwd1.encode()).hexdigest()
			elif hash_type == 9: #SHA3-256
				passwd_h = hashlib.sha3_256(passwd1.encode()).hexdigest()
			elif hash_type == 10: #SHA3-384
				passwd_h = hashlib.sha3_384(passwd1.encode()).hexdigest()
			elif hash_type == 11: #SHA3-512
				passwd_h = hashlib.sha3_512(passwd1.encode()).hexdigest()
			elif hash_type == 12: #BLAKE2s
				passwd_h = hashlib.blake2s(passwd1.encode()).hexdigest()
			elif hash_type == 13: #BLAKE2b
				passwd_h = hashlib.blake2b(passwd1.encode()).hexdigest()
			elif hash_type == 14: #NTLM
				passwd_hash = hashlib.new('md4', passwd1.encode('utf-16le')).hexdigest()
			elif hash_type == 15: #Whirlpool
				passwd_hash = whirlpool.new(passwd1.encode()).hexdigest()
			else:
				print(color.RED + "[-] Invalid hash type...Exiting!" + color.END)
				sys.exit()
			if verbose == True:
				print(color.BLACK + "Trying {}" .format(str(repr(passwd1))) + color.END)
			if user_hash == passwd_hash:
				hash_cracked = True
				print(color.GREEN + "[+] Hash cracked! Results: " + color.RED + str(line) + color.END)
				endTime = time.time()
				deltaTime = endTime - startTime
				sys.stdout.write("\033[F")
				print(color.GREEN + "[+] Cracking finished in " + color.RED + str(format(deltaTime, ".3f")) + color.END + color.GREEN + "s" + color.END)
				if output == True:
					print("[+] Hash cracked! Results: " + str(line) + "[+] Cracking finished in " + str(format(deltaTime, ".3f")) + "s", file=open("results.txt", "a"))
					print(color.ORANGE + "Results saved successfully in ./results.txt!" + color.END)
				if output_json == True:
					results = {
						"Hash": str(user_hash),
						"Cracked hash": str(line).replace("\n",""),
						"Time": format(deltaTime, ".3f")
					}
					results_json = json.dumps(results, indent=2)
					print(results_json, file=open("results.json", "w"))
					print(color.ORANGE + "Results saved successfully in ./results.json!" + color.END)
				sys.exit()
		print(color.RED + "[-] Hash not found! Maybe another wordlist would help." + color.END)
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
	print(color.RED + " \n[-] Index Error: syntax does not make sens to me! Please check that out!" + color.END)
	sys.exit()
except SyntaxError:
	print(color.RED + " \n[-] Syntax error! Please kindly check what you executed." + color.END)
	sys.exit()
except TypeError:
	print(color.RED + " \n[-] Wrong value type given! Please kindly check what values you gave in." + color.END)
