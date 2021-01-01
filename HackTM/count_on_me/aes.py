from Crypto.Cipher import AES
# this is a demo of the encyption / decryption proceess.

a = 'flagflagflagflag'
key = '1111111111111111111111111111111111111111111111111111111111111111'.decode('hex')
iv = '42042042042042042042042042042042'.decode('hex')


#encrypt
aes = AES.new(key,AES.MODE_CBC, iv)
c = aes.encrypt(a).encode("hex")
print(c)

#decrypt
aes = AES.new(key,AES.MODE_CBC, iv)
print(aes.decrypt(c.decode("hex")))