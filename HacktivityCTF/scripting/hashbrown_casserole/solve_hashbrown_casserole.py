from pwn import remote
from utils.hashes.finder import get_md5_head, get_sha1_head


r = remote("jh2i.com", 50005)
while True:
    resp = r.recvline().strip().decode()
    print(resp)
    head = resp.split()[-1]

    if "sha1" in resp:
        ans = get_sha1_head(head)
    else:
        assert "md5" in resp
        ans = get_md5_head(head)
    print(ans)
    r.sendline(ans)

    verdict = r.recvline().strip()
    assert verdict == b"Correct.", verdict
