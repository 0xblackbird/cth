# Crack The Hash
Ultra fast hashcracking tool written in Python3

# Update [v2.1]
- New flag has been added (-u/-update) to update your current version of the script

# Description
A powerfull hash cracker that is written in python3! The cracker currently supports only a limited amount of hash types (more hash types will eventually follow!). The cracking speed depends on your hardware or on the wordlist, you can choose. I hope you enjoy it! Feedback on the tool is appreciated! Also, feel free to contribute and make a pull request! That's why I choosed for Open Source :)!

**I like to hear feedback! Hit me up on Twitter! [@BE1807V](https://twitter.com/be1807v)**

# Todo
- [ ] Add hash detection
- [ ] Add more hashtypes to crack
- [ ] Cracking multiple hashes at the same time
- [ ] Using GPU for cracking hashes
- [ ] Using CPU to crack hashes

# Installation
**`$ git clone https://github.com/be1807v/cth.git cth`**

**`$ cd cth/`**

**`$ pip install -r requirements.txt`**

**`$ chmod +x cth.py`**

# Usage

```
usage: ./cth.py -H <HASH> [OPTIONS] -T <NUM> -w <WORDLIST>

optional arguments:
  -h, --help         show this help message and exit
  -H H, -hash H      Your hash that you want to crack
  -w W, -wordlist W  The wordlist that is going to do the job (default: "/usr/share/wordlists/rockyou.txt")
  -T T, -type T      Specify the hash type, use "-L/-list" for more info (default: "0" (md-5))
  -o, -output        Output the result in a text file (default: "False")
  -oJ, -output-json  Output the result in JSON format (default: "False")
  -I, -interactive   Go through steps instead of typing all the flags manually
  -v, -verbose       Turn on verbosity mode (default: "False")
  -L, -list          Display all the hash types and exit
  -u, -update        Update the script
  -V, -version       show program's version number and exit

```

# Examples
MD5 hash cracking:
![Example 0](https://github.com/be1807v/cth/blob/master/examples/example.png)

SHA3-512 hash cracking:
![Example 1](https://github.com/be1807v/cth/blob/master/examples/example-1.png)

BLAKE2s hash cracking:
![Example 2](https://github.com/be1807v/cth/blob/master/examples/example-2.png)

NTLM hash cracking:
![Example 3](https://github.com/be1807v/cth/blob/master/examples/example-3.png)
