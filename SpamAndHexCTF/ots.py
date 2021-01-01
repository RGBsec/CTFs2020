import hashlib
import hmac
import secrets
from time import sleep

from utils.basics import to_blocks
from binascii import unhexlify
from pwn import remote


class OTS:
    def __init__(self):
        self.key_len = 128
        self.priv_key = secrets.token_bytes(16 * self.key_len)  # 2048 bytes
        self.pub_key = b''.join(
            [self.hash_iter(self.priv_key[16 * i:16 * (i + 1)], 255) for i in range(self.key_len)]).hex()

    def hash_iter(self, msg, n):  # hash msg n times with md5
        assert len(msg) == 16
        for i in range(n):
            msg = hashlib.md5(msg).digest()
        return msg

    def wrap(self, msg):  # pad with nulls, then add md5
        raw = msg.encode('utf-8')
        assert len(raw) <= self.key_len - 16
        raw = raw + b'\x00' * (self.key_len - 16 - len(raw))  # pad up to key_len - 16
        raw = raw + hashlib.md5(raw).digest()

        return raw

    def sign(self, msg):
        raw = self.wrap(msg)
        signature = b''.join(
            [self.hash_iter(self.priv_key[16 * i:16 * (i + 1)], 255 - raw[i]) for i in range(len(raw))]).hex()
        self.verify(msg, signature)
        return signature

    def verify(self, msg, signature):
        raw = self.wrap(msg)
        signature = bytes.fromhex(signature)
        assert len(signature) == self.key_len * 16
        calc_pub_key = b''.join([self.hash_iter(signature[16 * i:16 * (i + 1)], raw[i]) for i in range(len(raw))]).hex()
        print(to_blocks(calc_pub_key, 32))
        assert hmac.compare_digest(self.pub_key, calc_pub_key)


def rep_hash(msg: bytes, n):  # hash msg n times with md5
    for i in range(n):
        msg = hashlib.md5(msg).digest()
    return msg


def pad(msg: bytes):
    assert len(msg) <= 128 - 16
    return msg + b'\x00' * (128 - 16 - len(msg))


def all_less_or_equal(larger: bytes, smaller: bytes) -> bool:
    if len(larger) != len(smaller):
        print(len(larger), len(smaller))
        return False

    for c1, c2 in zip(larger, smaller):
        if c1 < c2:
            return False
    return True


def derive_sig(signed: bytes, my_msg: bytes, given: bytes) -> str or None:
    signed = pad(signed)
    my_orig_msg = my_msg
    my_msg = pad(my_msg)

    signed_hash = hashlib.md5(signed).digest()
    my_hash = hashlib.md5(my_msg).digest()

    if all_less_or_equal(signed_hash, my_hash) is False:
        return None

    signed += signed_hash
    my_msg += my_hash

    blocks = to_blocks(given, 32)
    for idx, c in enumerate(zip(signed, my_msg)):
        blocks[idx] = rep_hash(unhexlify(blocks[idx]), c[0] - c[1]).hex().encode()

    return my_orig_msg, b''.join(blocks)


def solve(signed_msg: bytes, my_msg: bytearray, given: bytes, idx):
    # print(signed_msg)
    # print(my_msg)
    # print(given)
    # print(idx)
    # print(my_msg, idx)
    if idx >= len(my_msg):
        return None
    if idx == 5:
        idx += 4
    ans = derive_sig(signed_msg, my_msg, given)
    if ans is not None:
        return ans

    if my_msg[idx] > 50:
        my_msg[idx] -= 1
        ans = solve(signed_msg, my_msg, given, idx)
        if ans is not None:
            return ans
        my_msg[idx] += 1

    return solve(signed_msg, my_msg, given, idx + 1)


def digit_sum(hex_str: str) -> int:
    return sum([int(d, 16) for d in hex_str])


def main():
    while True:
        sleep(1)
        rem = remote("34.89.64.81", 1337)
        rem.recvuntil("\npub_key = ")
        public_key = rem.recvline().decode().strip()
        signed, signature = rem.recvline().decode().split(' = ')
        signed = signed.strip().strip('signed("').strip('")').strip()

        signed = signed.encode()
        my_msg = bytearray(signed.replace(b'vori', b'flag'))
        signature = signature.strip().encode()
        if sum(hashlib.md5(pad(signed)).digest()) < 2400:
            continue
        print(sum(hashlib.md5(pad(signed)).digest()))
        print(public_key)
        print(signed)
        print(signature)
        msg, answer = solve(signed, my_msg, signature, 0)
        # msg = msg.decode()
        print("sending:", msg)
        rem.sendline(msg)
        print("sending:", answer)
        rem.sendline(answer)
        print(rem.recvall(5).decode())
        break


main()

# original = 'My favorite number is 5449429112059163855.'
# given = '23e36c1972902b2836c21bdec9af44809e23da5a5e60d2f842633912ba5951e96a5dff8bc1c8721e40717999bccbcab7959c2e7d2c2385080f9448933250d39cdcdc070d61b9378795b25f0ed7bbcac65963f7a096fa0c885521b23a5ddfd1419f0b15094ab10b6df4dc03ae427ff31c5d11629b1107cb9a12fb3ce6ebb4cf9a63887762de23d671832a9409ea583b38d95685d6b03d5deaac5cd82b0046c850ebb4e6eeb2fe2497102e8f1c424d6f36fcd90b114e5024150965a6b9699fd3b53c71423a79ea396d8cf939e065c320a43350a043819e4322d98d086d5848c050a77c14cbf4d4c854f8261186171aecab340e3adcb6aa15c71d3ac3650329b06d5da6cbd4acf4b759f98ded42e114a2f9658346e619899d22ea495a7e0c03b1683c0b3aeb52a8e038483d73ae831337cde240d0e767c035d52ae22e376903cf768e540ee5c425601aa6f8aa82323bcd06e646b17fa8c3968f12f66e971fea6612ee34778a8badee7424a2e603475c07abf35ae481f0e17cbad4a9a6e4a547c188a124e5982b540e05aaafa5f9cd3b359a8e96f0b8862cba62e82e053a5ee101e5b9dc97577d6ce805f6a8df7fb99bebcb4c7f68c8772d8e12595199ee432446d4d5017370ab8d650ae49424bfeb83a127e9ebe51d315544aedf404662d1700e71a166cceb5246bc1f10de0e7bd4e47f28b377dd8e73be53918fc1924f4cfd166427ef9def31c084261471718f16c2988d086617b7244cf176d21ecbe18dd6f944c786e86f32e5579b809901faef0195bd572ba98528aff31742ea4878b694d14057dd103ca8238fe667550a751e491393e36e453e5c527710291e139e062ecd6176fd172f9cb7241c816f56279d7dce6affe71c962b76189f26e0ba2a28dd6d21316f49a4f01eaa0a0ee78b574601157dc64ce143fb7c55f2a88dc793b1cbd6c492f97288d596c49296ccf3a704367b757f028c36c0cb899e1d07d6f5514a5689d8db5d86b0067e4e00be03f10c29d4b71c091e384d11c499bb3d7d25b2c83b8c25115a5784aa2b4125507d44354099e63f3482c95a821c5d6906d6dca44478107e44f3041665d11eaaf1a618b6ad9c701fc6effd147fc861a302bd5ec7c6b588f1475f9ff343b19b90da98283bd05a7ba56a2e4430ad65b7d6660a2ec2ed397a18642d2ef6a190dce98cf966582abae42e99402b9ba6202951f655359e461799aaf2ecc3341d5d34553ad9cbd8a5482964f23da8f974ce36a82e66c87f3f74e3d4967f0e061794b0ef94d9f7e3da52e4d356196e8029b709b64c6d429fcd6dd400b6b625ec1061de98c067198d1a6b98cee459332bf68dd61dba970dd29b8d14736d066de00b021ebb9293fccedc93e9fe9297e3f39eb050a7e989d2619916a512285f68a384083c8e5e57756eaaebb0227e0996da69dfbf5015af06d90295100f1a9287afc38fbf8496080dc80c05a075a48c25ac8c85a1849c3e77dea37a26816f36ae77da2382ee30e7c114c08d1842d4a73f378df6b51b4c64361302baf483f283a93dc0a0a0276e494429d1f59f7c1e9691ad2e6f59934560817ff0f13af12692bf481adf8bc57846ca20370608e8afb15456ae348e57d26f9d0620e18ffe0f9dfcd1d296d974f6fcf30243ce146f9810b7c53c1f8d4b1282902a2e5ae3e1892d89f87b3905ca4a0c0e85df900c7811c50e6c37fff2e8c60b952819b6b6c0575f2e43e3574736eb42176cf681232e579d007b211d47df36bedb25ee0ae01bafcae66fd565f1786b02fa28eaf4e12dc739b8d357adb9e91d9f4cccdf37b34d10774bc2ddbfe1a26126f262b29d8d30438f43c266bdc10e84f0f4d9b00386711e506ba68851cdfc78b3113f8de2c0d9bb2b157a1febbef02088dc19b11af06b02b6107a91beec2cfcb943281e7437a3f06bf454d92e7b95fe2dd4ea086ea834742f9840f4449fe8538aa206f1a7d152f3fa3bc903a2ec6ec8602a3ad9faf1b18af080e5a60342973e54415fafb1ae9f8fc3345721d88a5fb834a6c719f5779b9bed041801cf524a1280db0fcd1bd894362def346f3a246e6904e006d6378fab41efbb0d48c2759acb87a9774535577edf4196e8acf6ebafd23aff0c7a63b5b24f87e297d781452a095ee67807edebbcae93720cf5df17573badf9e3148e8c0b6ddeca3ea12c26d62ef4e6ee01c574b281d6b401d3a5ab790bc1d55b898b8da3c7fa80c082a4e08380f43d5e536254a3ccea0527101ec5619d36db28c7fb137d7fe8f1c298cf6993c1114e2dc82deb695a08ae2658e1c01ebac3e2c5dadd7453e7842ce7ac0c2a879f0f74ecf346f1a86ae083e1ba284367579a5db74a34ac221a4affb273225bdf956050277dcc0a39e327168c04e6b2d5d40ed8ea26e50bed72f57507b639029c37d83d69150f6e46f5b42ccab7d9487a1e4878188ae6439bdba738b5d4ee01216ccfba18d85630a70308627eaea91ceeb6de66d7edcb04e2e77970e0baddf7a3b97b9bd9e986dd574e6af1932ca6ebd021657111a2b28dfd61c44bc8c41e072e8649c8eac5724b853ef7244485adfab1d1609059b721cf90b745bedeaca6ea89465a6aa6769b9aada8f1e7cde869e712f95fc679a7990b13e16e429bd57351bd744d2dfcadf386a28ff08eee4e273c892547ab36681966df5bbab0f454d0922bfbb0ef33178fcfdc8d878cd8fb9eca5cd74d9849ec3a6b3122a16511a3ae5323729e0c4cb0c20e6463e7e456a85bfac7581995a0dee4f7d6cc93c4ff583e2845207aaad9bfc57f4a378a422d66d6fd9ebe26be76fbdf9a2b92b497374efdd00e729bc5aa4596ea2b6596009c5ec5db30eb5caee3b7c4e501443c814e1e1fbda60cdb1f2fc66c04f2526a55ad5e772fc3f07cc4e1ff89cf'
# pub = '0ef69a7bac30705af2f5007591f68696ab97622c5fed95c62c2b00143364aed9e8f38c298c33fdf4478276fb618dfd8f08812e6edaac5c857e3e8cc49ee4d6a85d825342417fc10d84f9bdd6a1f63708fc08c5510c1851227d0d1bd9f966dc06c992c85ff3c96d3f313cb9d5efc5d0ef4a8e4b9eaa7ad55a47a11e60f533a290f231d895b903e06d7067c9339061ce672a57783db7f3af24412fcb588a993ae4664265f1eba16f2b5de1f776b806d9539a4f18c4b0382b7d847ab0fe5a49650318536fbde71037411c7cc0f5f1afeeac7826add0894a61adce4f9f170985019fd6447b7083e94ef95761ab81671b7e80fa6d0ea52400084bdf2212b85293990bd4c0232905f322e4ee37bb2b4106187e1891304c986ecaca628b8ed5e7496337b5c99da93ebacbed92020c6d62284231e813d3e15c463c68f6e5663b838b5e7d023ea608f4437aaa10073d7daa9995662d7e2cb8cbb55496a53b8e21cb5a6d2228700a3c5860df775137d28ea82e6884f1e6c2843f44fdb71c640acd1deb4a0866bc40a6ac81d8b2952127a042eaad0de391fbe477b08b3ac899a3a82b14d8e03f7943082332cb2fe5461fddccd95738f71b15c70a22c3af261319b4066875fcf13b9114906e175aea6caf40a9b9d2ad04a3e417b116153804493bbe76d20379ed24e6c797c3e5f4e362e0cd77420dadca903c776dafa92eeabbd91d623dc68dea46da734af95050350c3c6df600d7f699f0cad45e7e6df00051610899a0e9c765b1f5117189bf24df5396874438ba711015c52426c26d2d766c74acff05ba6d723f517de98a7b90e0bc0080508ba592a09910d94233bc84a306ec02332ea21de559d6accfee644a59eaf6e28e1783f78bf04706196aaba2cfd48c81a89e3ee579f2d8b08c1e27c4a3999998c62fd4ad6a97b09fbe897424fde8b310a64987d192f97288d596c49296ccf3a704367b757f028c36c0cb899e1d07d6f5514a5689d8db5d86b0067e4e00be03f10c29d4b71c091e384d11c499bb3d7d25b2c83b8c25115a5784aa2b4125507d44354099e63f3482c95a821c5d6906d6dca44478107e44f3041665d11eaaf1a618b6ad9c701fc6effd147fc861a302bd5ec7c6b588f1475f9ff343b19b90da98283bd05a7ba56a2e4430ad65b7d6660a2ec2ed397a18642d2ef6a190dce98cf966582abae42e99402b9ba6202951f655359e461799aaf2ecc3341d5d34553ad9cbd8a5482964f23da8f974ce36a82e66c87f3f74e3d4967f0e061794b0ef94d9f7e3da52e4d356196e8029b709b64c6d429fcd6dd400b6b625ec1061de98c067198d1a6b98cee459332bf68dd61dba970dd29b8d14736d066de00b021ebb9293fccedc93e9fe9297e3f39eb050a7e989d2619916a512285f68a384083c8e5e57756eaaebb0227e0996da69dfbf5015af06d90295100f1a9287afc38fbf8496080dc80c05a075a48c25ac8c85a1849c3e77dea37a26816f36ae77da2382ee30e7c114c08d1842d4a73f378df6b51b4c64361302baf483f283a93dc0a0a0276e494429d1f59f7c1e9691ad2e6f59934560817ff0f13af12692bf481adf8bc57846ca20370608e8afb15456ae348e57d26f9d0620e18ffe0f9dfcd1d296d974f6fcf30243ce146f9810b7c53c1f8d4b1282902a2e5ae3e1892d89f87b3905ca4a0c0e85df900c7811c50e6c37fff2e8c60b952819b6b6c0575f2e43e3574736eb42176cf681232e579d007b211d47df36bedb25ee0ae01bafcae66fd565f1786b02fa28eaf4e12dc739b8d357adb9e91d9f4cccdf37b34d10774bc2ddbfe1a26126f262b29d8d30438f43c266bdc10e84f0f4d9b00386711e506ba68851cdfc78b3113f8de2c0d9bb2b157a1febbef02088dc19b11af06b02b6107a91beec2cfcb943281e7437a3f06bf454d92e7b95fe2dd4ea086ea834742f9840f4449fe8538aa206f1a7d152f3fa3bc903a2ec6ec8602a3ad9faf1b18af080e5a60342973e54415fafb1ae9f8fc3345721d88a5fb834a6c719f5779b9bed041801cf524a1280db0fcd1bd894362def346f3a246e6904e006d6378fab41efbb0d48c2759acb87a9774535577edf4196e8acf6ebafd23aff0c7a63b5b24f87e297d781452a095ee67807edebbcae93720cf5df17573badf9e3148e8c0b6ddeca3ea12c26d62ef4e6ee01c574b281d6b401d3a5ab790bc1d55b898b8da3c7fa80c082a4e08380f43d5e536254a3ccea0527101ec5619d36db28c7fb137d7fe8f1c298cf6993c1114e2dc82deb695a08ae2658e1c01ebac3e2c5dadd7453e7842ce7ac0c2a879f0f74ecf346f1a86ae083e1ba284367579a5db74a34ac221a4affb273225bdf956050277dcc0a39e327168c04e6b2d5d40ed8ea26e50bed72f57507b639029c37d83d69150f6e46f5b42ccab7d9487a1e4878188ae6439bdba738b5d4ee01216ccfba18d85630a70308627eaea91ceeb6de66d7edcb04e2e77970e0baddf7a3b97b9bd9e986dd574e6af1932ca6ebd021657111a2b28d65b3d5c4a2d44860246e8c2181d2aa1c9af7695255e8def870caad3e66d497453a7a40c21141b3e0292c3c3c308281cfb0b72a8dadc7524c420b2521fc4ef4bf225335a230e658ffa1a98a6d5dbe92782ddebcc1e883a6dc4c8e67002b6cd773da43aca633d385376720c9cf75f8b238928f47e6ff646c7f5352a45e7177234ceb7982c8de0b1f3722c98d2208d8d591910cf3e6a78c953b1b61b1822cf7d1d1f71f440122f280a973d72aec0c078742bc9947e6618df548027c6797702e85852d18f4880e914fa0760b6a1b753008b6fdb748afb8d74b399a9b2b221c6accdbe957d5fed86f7e381ddadf090c4f19ef50ee9ec47a490a6c24a8811bca1aa898'
# msg = original.replace('vori', 'flag')
#
# msg, sig = solve(original.encode(), bytearray(msg.encode()), given.encode(), 0)
# msg = msg.decode()
# sig = sig.decode()
# print(msg, sig)
#
# ots = OTS()
# ots.pub_key = pub
# try:
#     ots.verify(msg, sig)
# except AssertionError:
#     pass
# print(to_blocks(pub, 32))


# SaF{better_stick_with_WOTS+}
