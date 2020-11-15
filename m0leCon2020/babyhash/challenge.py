from Crypto.Util.number import getPrime, isPrime, bytes_to_long
from os import urandom
from binascii import unhexlify
# from secret import flag
flag = "asdf"

header = """CryptoLog.INC

--------------------------------------------------
Welcome, user!
Please login with valid credentials, checked by our crypto-evoluted system.
--------------------------------------------------


"""

def not_so_funny_check(x, p):
	s = bin(p-1)[::-1].index('1')
	for z in range(2, p):
		if p - 1 == pow(z, (p - 1) // 2, p):
			break
	print('z =', z)
	print('s =', s)
	c = pow(z, (p - 1) // 2 ** s, p)
	r = pow(x, ((p - 1) // 2 ** s + 1) // 2, p)
	t = pow(x, (p - 1) // 2 ** s, p)
	m = s
	t2 = 0
	while (t - 1) // p != (t - 1) / p:
		t2 = (t * t) % p
		i = 0
		for i in range(1, m):
			if (t2 - 1) // p == (t2 - 1) / p:
				break
			t2 = (t2 * t2) % p
		b = pow(c, 1 << (m - i - 1), p)
		r = (r * b) % p
		c = (b * b) % p
		t = (t * c) % p
		m = i
	return r

def funny_check(x, p):
	try:
		not_so_funny_check(x, p)
	except Exception as e:
		print(e)
		return True
	return False

p = 43401284375631863165968499011197727448907264840342630537012422089599453290392542589198227993829403166459913232354777490444915201356560807401141203961578150815557853865678753463969663318864902106651761912058979552119867603661163587639785030788676120329044248495611269533429749805119341551183130515359738240737511058829539566547367223386189286492001611298474857947463007621758421914760578235374029873653721324392107800911728989887542225179963985432894355552676403863014228425990320221892545963512002645771206151750279770286101983884882943294435823971377082846859794746562204984002166172161020302386671098808858635655367

while True:
	x = bytes_to_long(urandom(32))
	x = x % p
	if funny_check(x, p):
		break

while True:
	y = bytes_to_long(urandom(32))
	y = y % p
	if funny_check(y, p):
		break

a = bytes_to_long(b'admin')
b = bytes_to_long(b'password')
print(x)
print(y)
print(a, b)

server_hash = (pow(x, a, p) * pow(y, b, p)) % p

print(header)

try:
	print('Username:')
	username = input()
	assert len(username) <= 512
	username = unhexlify(username)
	print('Password:')
	password = input()
	assert len(password) <= 512
	password = unhexlify(password)
except:
	print("Input too long! I can't keep in memory such long data")
	exit()

if username == b'admin' or password == b'password':
	print("Intrusion detected! Admins can login only from inside our LAN!")
	exit()

user_hash = (pow(x, bytes_to_long(username), p) * pow(y, bytes_to_long(password), p)) % p

if user_hash == server_hash:
	print("Glad to see you, admin!\n\n")
	print(flag)
else:
	print("Wrong credentials.")
