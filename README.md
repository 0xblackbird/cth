# Hash Cracker
A powerfull hash cracker written in python3!

# Update [v1.3]
- The `-T/--type` flag has now the default value of `0`, so no need to specify the type when cracking MD-5 hashes!
- Added an output message when the hash is not found
- Cleaned up the code

# Description
A hash cracker that is written in python3! The cracker currently supports only a limited amount of hash types (more hash types will eventually follow!). The cracking speed depends on your hardware or on the wordlist, you can choose. I hope you enjoy it! 

**I like to hear feedback! Hit me up on Twitter! [@BE1807V](https://twitter.com/be1807v)**


# Installation
**`$ git clone https://github.com/be1807v/Hash-Cracker.git`**

**`$ cd Hash-Cracker/`**

**`$ pip install -r requirement.txt`**

**`$ chmod +x hashcracker.py`**

# Usage

```
Usage: ./hashcracker.py -H <hash> -w <wordlist> -T <hash type>

Options:
  --version             show program's version number and exit
  -h, --help            show this help message and exit
  -H HASH, --hash=HASH  Your hash that you want to crack
  -w WORDLIST, --wordlist=WORDLIST
                        The wordlist that is going to do the job (default:
                        "/usr/share/wordlists/rockyou.txt")
  -T NUM, --type=NUM    Specify the hash type, use "-L/--list" for more info
                        (default: "0" (md-5))
  -v, --verbose         Turn on verbosity mode (default: "False")
  -L, --list            Display all the hash types and exit
```
