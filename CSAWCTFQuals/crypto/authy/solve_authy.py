from subprocess import run, PIPE

VERBOSE = False

with open("payload.txt", "w+") as f:
    f.write("""entrynum=7&author=&note= admin=True&a= access_sensitive=True&x= entrynum=7""")

# URL = "http://127.0.0.1:5000"
URL = "crypto.chal.csaw.io:5003"
proc = run(["curl", "-X", "POST", f"{URL}/new", "-d", "@payload.txt", "-v" if VERBOSE else ''], stdout=PIPE)
resp = proc.stdout.decode().strip().split()[2]
identifier, integrity = resp.split(':')

proc = run(["curl", "-X", "POST", f"{URL}/view", "-d", f"id={identifier}&integrity={integrity}", "-v" if VERBOSE else ''], stdout=PIPE)
print(proc.stdout.decode().strip())