from base64 import b64decode

s = "31 34 33 20 31 35 36 20 31 32 32 20 31 35 32 20 31 34 33 20 31 31 30 20 31 36 34 20 31 35 32 20 31 31 35 20 31 30 37 20 36 35 20 36 32 20 31 31 35 20 36 33 20 31 31 32 20 31 37 32 20 31 31 35 20 31 32 34 20 31 30 32 20 31 36 35 20 31 34 33 20 36 31 20 37 31 20 31 35 30 20 31 34 33 20 31 35 32 20 31 31 36 20 31 34 36 20 31 31 36 20 31 30 36 20 37 31 20 31 35 32 20 31 31 35 20 31 30 34 20 31 30 32 20 31 31 35 20 31 33 30 20 36 32 20 31 31 35 20 36 30 20 31 34 34 20 31 31 30 20 31 31 36 20 37 31"
# s = s.replace("20", ".").replace('31', '*')

nums = [int(n) for n in s.split()]
h2d = [int(str(n), 16) for n in nums]

print(h2d)
s2 = ''.join([chr(c) for c in h2d])

nums2 = [int(c) for c in s2.split()]
print(nums2)
print(''.join([chr(c) for c in nums2]))

d2o = [int(str(n), 8) for n in nums2]
print(d2o)

s3 = ''.join([chr(c) for c in d2o])
print(s3)

print(b64decode(s3))