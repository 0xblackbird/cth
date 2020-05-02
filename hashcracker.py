#!/bin/python3

####################################################
#                                                  #
#           Code made by @BE1807                   #
#     (40e219a80dfa2239c096e18bca46fd15) :)        #
#						   #
####################################################
import hashlib
import time
import sys
import os.path

menu = """MD5 Password Cracker brought to you by @BE1807V!
Go follow me on Twitter!

Syntax:

-H, --help		Display this help menu
-h, --hash		Your md5 hash that you want to crack
-w, --wordlist		The wordlist that is going to do the job (remember: the bigger the wordlist the more time it will take!)

Example:

python3 hashcracker.py --hash 1a79a4d60de6718e8e5b326e338ae533 --wordlist /usr/share/wordlists/rockyou.txt"""

try:
	if len(sys.argv) < 1:
		print("Incorrect syntax!")
		print(menu)
	elif len(sys.argv) == 1:
		print(menu)
	elif len(sys.argv) == 2:
		if sys.argv[1] == "-H" or sys.argv[1] == "--help":
			print(menu)
		else:
			print("Incorrect syntax! Use \"-h\" or \"--help\" to display the help menu!")
			sys.exit()
	elif len(sys.argv) > 2:
		if sys.argv[1] == "-w" or sys.argv[1] == "--wordlist":
			wordlist = sys.argv[2]
			if os.path.isfile(wordlist) == True:
				print("Wordlist: \"{}\"" .format(str(wordlist)))
				if sys.argv[3] == "-h" or sys.argv[3] == "--hash":
					startTime = time.time()
					user_hash = sys.argv[4]
					print("Hash: \"{}\"" .format(str(user_hash)))
					
					with open(wordlist, "r", encoding="ISO-8859-1") as FileObj:
						password = []
						for line in FileObj:
							password.append(line.replace("\n", ""))
					
					print("Everything is set up! Cracking can begin...")
					
					for passwd in password:
						passwd_h = hashlib.md5(passwd.encode())
						passwd_hash = passwd_h.hexdigest()
						if user_hash == passwd_hash:
							print("Hash cracked! Results: " + str(passwd))
							endTime = time.time()
							deltaTime = endTime -startTime
							print("Cracking finished in {}s" .format(str(format(deltaTime, ".2f"))))
							sys.exit()
				else:
					print("Incorrect syntax! Use \"-H\" or \"--help\" to display the help menu!")
					sys.exit()
			elif os.path.isfile(wordlist) == False:
				print("\"" + str(wordlist) + "\" does not exist! If you think that it really exists, try checking your spelling!")
				sys.exit()
			else:
				print("Error!")
				sys.exit()
		elif sys.argv[1] == "-h" or sys.argv[1] == "--hash":
			user_hash = sys.argv[2]
			if sys.argv[3] == "-w" or sys.argv[3] == "--wordlist":
				wordlist = sys.argv[4]
				print("Hash: \"{}\"" .format(str(user_hash)))
				print("Wordlist: \"{}\"" .format(str(wordlist)))
				if os.path.isfile(wordlist) == True:
					startTime = time.time()
										
					with open(wordlist, "r", encoding="ISO-8859-1") as FileObj:
						password = []
						for line in FileObj:
							password.append(line.replace("\n", ""))
							
					print("Everything is set up! Cracking can begin...")
					
					for passwd in password:
						passwd_h = hashlib.md5(passwd.encode())
						passwd_hash = passwd_h.hexdigest()
						if user_hash == passwd_hash:
							print("Hash cracked! Results: " + str(passwd))
							endTime = time.time()
							deltaTime = endTime -startTime
							print("Cracking finished in {}s" .format(str(format(deltaTime, ".2f"))))
							sys.exit()
				elif os.path.isfile(wordlist) == False:
					print("\"" + str(wordlist) + "\" does not exist! If you think that it really exists, try checking your spelling!")
					sys.exit()
				else:
					print("Error!")
					sys.exit()
			else:
				print("Incorrect syntax! Use \"-H\" or \"--help\" to display the help menu!")	
		else:
			print("Incorrect syntax! Use \"-H\" or \"--help\" to display the help menu!")
			sys.exit()
	else:
		print("Incorrect syntax! Use \"-H\" or \"--help\" to display the help menu!")
		sys.exit()	
except KeyboardInterrupt:
	print("\n\"Ctrl+C\" detected! Exiting...")
	sys.exit()


except IndexError:
	print("Index Error arrived! Syntax does not make sens to me! Please check that out!")
	sys.exit()
