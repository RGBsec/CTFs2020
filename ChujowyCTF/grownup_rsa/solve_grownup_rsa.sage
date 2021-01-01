# this uses https://github.com/mimoo/RSA-and-LLL-attacks/blob/master/coppersmith.sage


def coppersmith_howgrave_univariate(pol, modulus, beta, mm, tt, XX):
    """
    Coppersmith revisited by Howgrave-Graham

    finds a solution if:
    * b|modulus, b >= modulus^beta , 0 < beta <= 1
    * |x| < XX
    """

    dd = pol.degree()
    nn = dd * mm + tt

    if not 0 < beta <= 1:
        raise ValueError("beta should belongs in (0, 1]")
    if not pol.is_monic():
        raise ArithmeticError("Polynomial must be monic.")

    # Coppersmith revisited algo for univariate

    # change ring of pol and x
    polZ = pol.change_ring(ZZ)
    x = polZ.parent().gen()

    # compute polynomials
    gg = []
    for ii in range(mm):
        for jj in range(dd):
            gg.append((x * XX) ** jj * modulus ** (mm - ii) * polZ(x * XX) ** ii)
    for ii in range(tt):
        gg.append((x * XX) ** ii * polZ(x * XX) ** mm)

    # construct lattice B
    BB = Matrix(ZZ, nn)

    for ii in range(nn):
        for jj in range(ii + 1):
            BB[ii, jj] = gg[ii][jj]

    # LLL
    BB = BB.LLL()

    # transform shortest vector in polynomial
    new_pol = 0
    for ii in range(nn):
        new_pol += x ** ii * BB[0, ii] / XX ** ii

    # factor polynomial
    potential_roots = new_pol.roots()

    # test roots
    roots = []
    for root in potential_roots:
        if root[0].is_integer():
            result = polZ(ZZ(root[0]))
            if gcd(modulus, result) >= modulus ^ beta:
                roots.append(ZZ(root[0]))

    return roots


def main():
    n = 0x6552f27b9fa5b4dbbd9859769cc058051533752de33574ab1b316fdf144babd3b095064c2b161e27b8c0d5f12652ce901e08540824367785cf28c38247549b72355ecb9eac0a613c125b33003c4780032a096c9e26313fc74dd37421664d305754d7755086e3ae422eb4eeb13ab2dbe16cbbc97675bc862c697f29fb8e73aabb4ff4b4a735f7f0f14d05e203b0bda4bc6f4b2b03fe4ec14eae229a8e3a5d4f02941c69a1d1f83cb45d090710531c51e9ac16863731543083c88f35d2b58587b2c7fbe0359d0b67b761871385652ddac164aea06b7de404d914e6cb9953fc540b58627ba403687c96055d64530f3f8ef9c0a7b3d04abd5683ab90ac54f45645b
    c = 0x1396c4db226f20a9076f0197826de0220f57cc4359107111b9eebf5e56b52e43e70aa2371b4db64260f0bbad80db0c7f8a121997bb02667a3d2d40d0e086209cd6e18568e251331a536d35257ae57bb7824e8dfbc6d1d1b421eab40ddfef686d8882806e44c353cc9efc2576c76ab856c7c2dbf27e43e2cc61da3f0aee94ed426f3b646981f60a965c9abe80bb09ea5def3db33929b1696d36f773c09989e511d7e16c99ddbe104331cd25e585483469ffeed7dbea1f2c829ed02eb98d6f4cb63ba67bc2aab0ddb44ef218141acd4a6ae14efa3dbf7d2834a6a40d054f1b0c49b757dabb75c5b91d6f415fe5c1e35d9f8a72200ac6a198279bde3e76eb5face
    e = 3
    m = int.from_bytes((b' ' * 97) + (b'\x00' * 31), 'big')
    ZmodN = Zmod(n)
    P.<x> = PolynomialRing(ZmodN, implementation='NTL')
    f = (m + x) ^ e - c
    dd = f.degree()
    beta = 1
    epsilon = beta / 7
    mm = ceil(beta ** 2 / (dd * epsilon))
    tt = floor(dd * mm * ((1 / beta) - 1))
    upper_bound = ceil(n ** ((beta ** 2 / dd) - epsilon))
    roots = coppersmith_howgrave_univariate(f, n, beta, mm, tt, upper_bound)
    print("Roots:", roots)

    assert len(roots) == 1

    flag = int(roots[0]).to_bytes(128, 'big')
    print(flag.strip(b'\x00'))


if __name__ == '__main__':
    main()