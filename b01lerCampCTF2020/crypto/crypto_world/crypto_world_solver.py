import itertools
from base64 import b64decode
from collections import Counter
from crypto.Cipher import AES
from math import gcd
from sympy import factorint, symbols, Matrix, solve as solve_equations, solveset, Mod, linsolve, Poly, primerange
from sympy.ntheory import discrete_log, nthroot_mod
from sympy.ntheory.modular import crt
from sympy.solvers.diophantine import diophantine


# west
def solve_b():
    x, y = symbols("x, y", integer=True)
    t_0 = 0
    print(*diophantine(123 * x + 179 * y - 1))
    print(179 * t_0 - 16, 11 - 123 * t_0)
    print(*diophantine(5419637592 * x + 8765372543 * y - 1))
    print(8765372543 * t_0 + 784426129, -5419637592 * t_0 - 485011369)

    a = 172329615174258484389026493995284470243013873606078558711314460397670851456942410234121713652719725046736930219457185697597838781645377593188376635674458514137402988415274695055808334695839436438924034168872425182706138637584824074845746669005801723938330993778108851070552409088962751784310957757082836431093300116826362
    b = 28356761906716612873881138710402902897347022365354411652739208693325513167251446458912103549741332079105794174802290037963900303459422464736407225394752372764336652283336292253338385760630286153548854753862316744878470244746596115894407579090226051336510357308468389580782413423780615862345700844128007232811673170490170
    c = 13657769199596610482
    print(*diophantine(a * x + b * y - c))
    print(
        2076236718625626284786056548669081403252544833904150272620011321468023352698988020061877478954752520310301256063072706784500193505113362705334165063487549462926151531407283657215977245889022376851044969477993092232992382813863369202004336646022589496537922628139644127129411273468794581736968001955685 * t_0 - 716740480992306813107503753418846234036640156759836661475354416766574545237010296962263824224509107612115141091065808866650335667339422168844609337650456083904714828583142795906730708621014510898197333708554115609551003952289103814240209709219851287729419355090392174924377596434397802758684489757519,
        4355772766846172289550960484253309708628309981859354451608388213582133495086922647575976048691479746491014530235602502674014803098803037825125357480987981590580196394415483266364546368978087653972266116991312510608494888084750532763692967382260459363590590286778039861513365053641201896497684198556508 - 12617698590143720670105762881622356815112515386462293667169823660898072508624401058886304920052577927970694376976199218570158447390981717458298614991002613921656481585724247919217255094989084155044494751122113059936231590732548449198257256744354283361036611847588757752920903623201677634807208201686341 * t_0)


# west west
def solve_i():
    def factorize(n: int) -> str:
        factors = factorint(n)
        ans = "ans"
        for k, v in factors.items():
            for _ in range(v):
                ans += f' {k}'
        return ans

    print(factorize(48263))
    print(factorize(8477969543906630921459041527576694))
    # print(factorize(71142975216676910225445498956472658317166395374468624230332488059276850400024521063814543607909086075571109949)) takes too long
    third_ans = "ans 3 11 31 29515817 1075612307646757041328543 1810939816479001125535889581 1209600061687323613153983466766686569317548327433"
    print(third_ans)


# west west west
# https://stackoverflow.com/questions/62599169/solving-systems-of-equations-modulo-a-certain-number-with-or-without-numpy
def solve_k():
    def solve_system(a1, b1, c1, a2, b2, c2, m):
        a = Matrix([
            [a1, b1],
            [a2, b2]
        ])
        b = Matrix([c1, c2])

        det = int(a.det())
        if gcd(det, m) == 1:
            ans = pow(det, -1, m) * a.adjugate() @ b % m
            return f"ans {ans[0]} {ans[1]}"
        else:
            raise Exception("aiya big rip")

    print(solve_system(76, 221, 85, 171, 190, 138, 281))
    print(solve_system(8537681, 2471394, 1901941, 4650550, 6247615, 1098848, 8715383))
    A = 21831285386116329336808413851154012866
    B = 134179293514007351709197019177330444915
    C = 330381653200657403372617268197336743779
    D = 122250463455825590287911447642817402561
    E = 380808038683121265859993106659221016535
    F = 167613919641031436550368729835629765957
    G = 348695986646393565943251192097904044414
    H = 154755784779510244395471253499438548399
    I = 19514348735351843258338241386050978799
    x, y, n, k1, k2, k3 = symbols("x, y, n, k1, k2, k3", integer=True)
    print(solve_equations([A * x + B * y + k1 * n - C, D * x + E * y + k2 * n - F, G * x + H * y + k3 * n - I],
                          (x, y, n)))


# wwws
# https://stackoverflow.com/questions/1832617/calculate-discrete-logarithm
def solve_d():
    print(discrete_log(101, 27, 11))
    print(discrete_log(2582957213, 2170396238, 29))
    a = 8711397949111576691212959376786755312511985069545395246877440965077478774468934756001391309042286116978264258298558869771314939991001082398339822258440522123
    b = 3351664603444796351468067743627025603502901539830658952546789142275777455261591099982137670634903607997743639964603135521965024437504489798875078878193244768
    print(discrete_log(a, b, 137))
    ans = 14658987390472498768342532082507022261187961131391088358623369143886050469752862452795575805546939392268731320883921380319174487522895863041104577678 + \
          14769487082776517553111267415678702047139519469841421317894086831961168916046496826847273539252753285236095077460093281021593930027448526699410335000
    assert pow(137, ans, a) == b, pow(137, ans, a)


# wwwss
def solve_C():
    print("ans", nthroot_mod(88, 2, 97))
    print("ans", nthroot_mod(95422207, 2, 1359203501))
    a = 1817525449797280602402956873386237720889680621662448878394577537780771524786955876245638699592180826704996032326091618875207339103593277472500067216389870
    p = 12779849905941677959186610420316494198424452561778642658582451521063175469853171114961122342052464710078864014592127176275630898014968982060325361045608439
    print("ans", nthroot_mod(a, 12, p))


# wwwsss
# see brute_a.cpp


# wwwssse is just a message, no challeges


# wwwsssee
def solve_j():
    from sympy.solvers.diophantine.diophantine import diop_quadratic
    x, y = symbols("x y", integer=True, positive=True)
    print(min(diop_quadratic(x ** 2 + 22 * y ** 2 - 8383),
              key=lambda t: float('inf') if t[0] < 0 or t[1] < 0 else t[0] + t[1]))
    print(min(diop_quadratic(x ** 2 + 608268054 * y ** 2 - 288964812689493391976023993),
              key=lambda t: float('inf') if t[0] < 0 or t[1] < 0 else t[0] + t[1]))

    a = 809575361919189873249985593557526797315607233589
    b = 453911665595804740746927043910783828583622477123414312540919542168796850447209357992143785144169862380534061054229556425568794584043785497763918
    # takes too long print(min(diop_quadratic(x ** 2 + a * y ** 2 - b),
    #          key=lambda t: float('inf') if t[0] < 0 or t[1] < 0 else t[0] + t[1]))


# wwwssseee
def solve_e():
    def num_to_poly(num) -> Poly:
        x = symbols('x')
        poly = Poly(0, x)
        p = 0
        while num > 0:
            if num & 1:
                poly += x ** p
            p += 1
            num >>= 1
        return poly

    def poly_to_num(poly: Poly):
        coefs = poly.all_coeffs()
        num = 0
        for coef in coefs:
            num <<= 1
            num += int(coef) & 1
        return num

    print(poly_to_num(num_to_poly(35).mul(num_to_poly(23))))
    print(poly_to_num(num_to_poly(250062733632176).div(num_to_poly(406399853))[1]))

    a = 62988136202118127274037485756847228824659813916854388288704528975265641038375
    b = 61970982425686765788241036465223359125124685363948286523458864616239704859380
    c = 16032512672834824306563461964216557396271213056568232093692714812022221106419800157218922185040829131491280726002257183375575408421728567246659014589764356633340492085105583082470307172750166547566757359700457224812429817166783751
    pa, pb, pc = num_to_poly(a), num_to_poly(b), num_to_poly(c)
    print("poly calculated")

    y = symbols('y')
    print(solve_equations(pa * y ** 2 + pb * y + pc, y))


# wwwssseeen
def decrypt(ct: bytes, key: bytes):
    out = bytearray()
    for ct_byte, key_byte in zip(ct, key * ((len(ct) + len(key) - 1) // len(key))):
        out.append(ct_byte ^ key_byte)
    return out


def solve_h1():
    s = "PQEMSRoMChsMHUkABx0MDgwbSQAaSR0eDAcdEEQPAB8MSR0BBhwaCAcNRUkPAB8MSQEcBw0bDA1JCAcNSR0eDAUfDEc="
    s = b64decode(s)
    for byte in range(256):
        ct = decrypt(s, bytes([byte]))
        if ct.isascii() and ct.decode().isprintable():
            print(ct)


def solve_h2():
    s = "BfEIGiL6CAE+900cavdJAC6zCBkvv0wLJPBdACn6CBkj60BOOPZPBj76Rxs5v0EALvZPACvrQQEkv0kALr9MBznzQQUvv0ULJL9fBiW/SRwvv1sBav1NCT/2RAsuv0kALr9MCyfwWg8m9lILLr9KF2rrQAtq/EAPOPJbTiX5CB4m+kkdP+1NTiX5CBoi+ggDJfJNAD6zCB0lv0oCI/FMCy6/Shdq+00dI+1NQmrrQA8+v1wGL+YIDSvxRgE+v04BOPpbCy+/XAYvv1gPI/EIDyT7CBo48F0MJvoIGiL+XE4r7U1OKPBdAC6/XAFq+kYdP/oTTivxTE4v7ghOHvdNTiPxXAst+lpOM/BdTj3+Rhpq9ltOe6wIGiW/XAYvvxlfPvcIHiXoTRxk"
    s = b64decode(s)
    likely = [set() for _ in range(4)]
    for start in range(4):
        ctr = Counter()
        cur = set()
        potential = set()
        for i in range(start, len(s), 4):
            cur.add(s[i])
            ctr[s[i]] += 1

        for byte in range(256):
            works = True
            if byte in cur:
                continue
            for ct_byte in cur:
                if not (32 <= ct_byte ^ byte < 127):
                    works = False
                    break
            if works:
                potential.add(byte)
        for i in range(3):
            if ctr.most_common()[i][0] ^ 32 in potential:
                likely[start].add(ctr.most_common()[i][0])

    print(likely)
    for key in itertools.product(*likely):
        key = bytes(key)
        pt = decrypt(s, key)
        if pt.startswith(b'oN\x00THE\x00OTHER\x00HAND'):
            print(pt)
    print(pow(13, 11))


# wwwssseeenn
def solve_h():
    s = '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'
    s = b64decode(s)
    print(len(s))
    for key_len in range(1, len(s) // 2):
        print(key_len)
        likely = [set() for _ in range(key_len)]
        for start in range(key_len):
            ctr = Counter()
            cur = set()
            potential = set()
            for i in range(start, len(s), key_len):
                cur.add(s[i])
                ctr[s[i]] += 1

            for byte in range(256):
                works = True
                if byte in cur:
                    continue
                for ct_byte in cur:
                    if not (32 <= ct_byte ^ byte < 127):
                        works = False
                        break
                if works:
                    potential.add(byte)
            for i in range(min(6, len(ctr))):
                likely[start].add(ctr.most_common()[i][0])

        for key in itertools.product(*likely):
            key = bytes(key)
            pt = decrypt(s, key)
            print(pt)


# wwwssseeennn
def solve_g():
    print(crt([5, 7, 13], [2, 6, 9]))
    print(crt([1277, 3911, 6833], [616, 1892, 3267]))

    a1 = 5485948154512337139220437723513046430670172804
    a2 = 2108813835706513804248871264701897235977426762
    a3 = 59351473308659155928757459746804856485
    a4 = 924847477382640006890848669912858050701990
    a5 = 12741718618862212680555500636008445150492416265

    b1 = 2661929484162718513247006741545910067104673680
    b2 = 1051667267149052195100488400753935294543177150
    b3 = 47216332074545827727316304129354717936
    b4 = 532886655965436047074701814450039258213526
    b5 = 11163090230050187304714123613300073905576382766
    print(crt([a1, a2, a3, a4, a5], [b1, b2, b3, b4, b5]))


# wwwssseeennnw
def solve_f():
    print(len(list(primerange(1200, 1500))))
    print(len(list(primerange(123456780, 234567890))))


# ssswn
def solve():
    # known_pt = (0x23df1b9f02d5d50702bfc77f0328dd94).to_bytes(16, 'big')
    # known_ct = (0x4311bffa7d121a5f1586faf15afc4605).to_bytes(16, 'big')
    # ct = (0x0e88440701074a7a0ce6a8cb9d93a5bb).to_bytes(16, 'big')
    #
    # for b1 in range(256):
    #     cipher1 = AES.new(b'\x00' * 15 + bytes([b1]), AES.MODE_ECB)
    #     middle = cipher1.encrypt(known_pt)
    #     for b2 in range(256):
    #         cipher2 = AES.new(b'\x00' * 15 + bytes([b2]), AES.MODE_ECB)
    #         out = cipher2.encrypt(middle)
    #         if known_ct == out:
    #             print(cipher1.decrypt(cipher2.decrypt(ct)))
    #             break

    # known_pt = (0x23df1b9f02d5d50702bfc77f0328dd94).to_bytes(16, 'big')
    # known_ct = (0xa6a28395f882097d1f542db61ee2a4bd).to_bytes(16, 'big')
    # ct = (0x0294c9250b515e1686ba600a0b23d767).to_bytes(16, 'big')
    # middle = dict()
    # for b1 in range(256):
    #     for b2 in range(256):
    #         cipher2 = AES.new(b'\x00' * 14 + bytes([b1, b2]), AES.MODE_ECB)
    #         out = cipher2.encrypt(known_pt)
    #         middle[out] = bytes([b1, b2])
    #
    #
    # for b1 in range(256):
    #     for b2 in range(256):
    #         key1 = b'\x00' * 14 + bytes([b1, b2])
    #         cipher2 = AES.new(key1, AES.MODE_ECB)
    #         out = cipher2.decrypt(known_ct)
    #         if out in middle:
    #             key2 = b'\x00' * 14 + middle[out]
    #             cipher1 = AES.new(key2, AES.MODE_ECB)
    #             print(cipher1.decrypt(cipher2.decrypt(ct)))

    known_pt = (0x23df1b9f02d5d50702bfc77f0328dd94).to_bytes(16, 'big')
    known_ct = (0x842c99112b424fb7096d4347f4901daf).to_bytes(16, 'big')
    ct = (0x42c10856b60a631c4fb4b936ef9546ff).to_bytes(16, 'big')
    middle = dict()
    key1 = bytearray(16)
    for b1 in range(256):
        print(b1)
        key1[13] = b1
        for b2 in range(256):
            key1[14] = b2
            for b3 in range(256):
                key1[15] = b3
                cipher2 = AES.new(key1, AES.MODE_ECB)
                out = cipher2.encrypt(known_pt)
                middle[out] = key1

    for b1 in range(256):
        print(b1)
        key1[13] = b1
        for b2 in range(256):
            key1[14] = b2
            for b3 in range(256):
                key1[15] = b3
                cipher2 = AES.new(key1, AES.MODE_ECB)
                out = cipher2.decrypt(known_ct)
                if out in middle:
                    cipher1 = AES.new(middle[out], AES.MODE_ECB)
                    ret = cipher1.decrypt(cipher2.decrypt(ct))
                    print(ret)


solve()
