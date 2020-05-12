# Hash Cracker
An easy hash cracker written in python3

# Update
- Added 5 more hash types (SHA-1, SHA-224, SHA-256, SHA-384, SHA-512)
- Added verbose mode
- Cleaned up the code

# Description
A hash cracker that is written in python3! The cracker currently supports only a limited amount of hash types (more hash types will eventually follow!) I hope you enjoy it! 

**I like to hear feedback! Hit me up on Twitter! [@BE1807V](https://twitter.com/be1807v)**


# Installation
**`$ git clone https://github.com/be1807v/Hash-Cracker.git`**

**`$ cd Hash-Cracker/`**

**`$ pip install -r requirement.txt`**

**`$ chmod +x hashcracker.py`**

# Usage

```
Usage: ./hashcracker.py -H <hash> -w <wordlist> -t <hash type>

Options:
  --version             show program's version number and exit
  -h, --help            show this help message and exit
  -H HASH, --hash=HASH  Your hash that you want to crack
  -w WORDLIST, --wordlist=WORDLIST
                        The wordlist that is going to do the job (default:
                        "/usr/share/wordlists/rockyou.txt")
  -t NUM, --type=NUM    Type of the hash that you want to crack
  -v, --verbose         Turn on verbosity mode
  --list                Display all the hash types and exit
```
