# Hash Cracker
A powerfull hash cracker written in python3!

# Update [v1.7]
- Added a new hashtype! MD-2
- Colors are added to the output!
- Fixed some bugs.

# Description
A powerfull hash cracker that is written in python3! The cracker currently supports only a limited amount of hash types (more hash types will eventually follow!). The cracking speed depends on your hardware or on the wordlist, you can choose. I hope you enjoy it! Feedback on the tool is appreciated! Also, feel free to contribute and make a pull request! That's why I choosed for Open Source :)!

**I like to hear feedback! Hit me up on Twitter! [@BE1807V](https://twitter.com/be1807v)**

# Todo
- [ ] Add hash detection
- [ ] Add more hashtypes to crack
- [X] Colored output
- [X] Add multiprocessing

# Installation
**`$ git clone https://github.com/be1807v/Hash-Cracker.git hashcracker`**

**`$ cd hashcracker/`**

**`$ pip install -r requirements.txt`**

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

# Examples
MD5 hash cracking:
![Example 0](https://github.com/be1807v/Hash-Cracker/blob/master/examples/example.png)

MD4 hash cracking:
![Example 1](https://github.com/be1807v/Hash-Cracker/blob/master/examples/example-1.png)

SHA1 hash cracking:
![Example 2](https://github.com/be1807v/Hash-Cracker/blob/master/examples/example-2.png)

SHA-512 hash cracking:
![Example 3](https://github.com/be1807v/Hash-Cracker/blob/master/examples/example-3.png)

SHA3-384 hash cracking:
![Example 4](https://github.com/be1807v/Hash-Cracker/blob/master/examples/example-4.png)
