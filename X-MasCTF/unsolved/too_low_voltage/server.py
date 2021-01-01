import os
import sys
from hashlib import sha256
from text import *
from chall import *
from PoW import *
import binascii

def is_hex(msg):
	for c in msg:
		if not c in "0123456789abcdef":
			return False
	return True

#if not PoW(5):
#    exit()

action_cnt = 64
cipher = chall(1024)
pubkey, privkey = cipher.get_key()
n, e = pubkey

print (intro.format(action_cnt, hex(n)[2:], hex(e)[2:]))

for i in range(action_cnt):
	print (menu)
	x = input()
	if not x in ["1", "2", "3"]:
		print (invalid_input)
		exit()

	if x == "1":
		print (get_msg)
		msg = input()
		if not is_hex(msg):
			print (invalid_input)
			exit()

		msg = int(msg, 16)
		sgn = hex(cipher.sign(msg, privkey))[2:]
		print (show_signature.format(sgn))
	elif x == "2":
		msg = binascii.hexlify(os.urandom(64))
		print (show_forgery.format(msg), "\n")
		msg = int(msg, 16)
		
		sgn = input()
		if not is_hex(sgn):
			print (invalid_input)
			exit()
		
		sgn = int(sgn, 16)
		if(cipher.verify(msg, pubkey, sgn)):
			print (win.format(FLAG))
			exit()
		else:
			print (bad_input)
			exit()
	else:
		print (goodbye)
		exit()

sys.stdout.flush()
