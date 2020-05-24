import ast

import random
import numpy as np
from DEFCONQuals2020.flag_sharing.matrix_inverse import getMatrixInverse

P = ast.literal_eval(open("prime.ooo").read().strip())
M = ast.literal_eval(open("matrix.ooo").read().strip())
N = len(M)
K = len(M[0])


def calc_det(A):
    n, _ = np.shape(A)
    if n == 1:
        return A[0, 0]
    else:
        S = 0
        for i in range(n):
            L = [x for x in range(n) if x != i]
            S += (-1) ** i * A[0, i] * calc_det(A[1:, L])
        return int(S)


def split_secret(key, n, k, matrix):
    assert len(matrix) == n, "misshaped matrix"
    assert len(matrix[0]) == k, "misshaped matrix"
    x = [int.from_bytes(key, byteorder='little')]
    for _ in range(k - 1):
        x.append(random.randint(0, P))
    x = np.array(x)

    print(matrix)
    print(x)

    shares = [(n, int(i)) for n, i in enumerate(np.dot(matrix, x))]
    return shares[1:]


def reconstitute_secret(keys, matrix):
    k = len(matrix[0])
    assert k <= len(keys), "not enough keys"
    assert np.linalg.matrix_rank(matrix) == k, "linearly dependent keys"

    subkeys = sorted(keys[:k])
    submatrix = [matrix[e[0]] for e in subkeys]
    subshares = [e[-1] for e in subkeys]
    det = calc_det(np.array(submatrix))
    submatrix = np.array(submatrix)
    inv_float = np.linalg.inv(submatrix)
    # print(submatrix)
    # print(inv_float)

    key = (int(sum([i * j for i, j in zip(
        [int(round(det * inv_float[0][i])) * pow(det, -1, P) for i in range(k)],
        subshares)])) % P).to_bytes(32, byteorder='little')


    return key


def random_matrix(n, k):
    matrix = [list(map(int, row)) for row in (np.random.rand(n, k) * 1000).astype(int)]
    assert np.linalg.matrix_rank(matrix) == k
    return matrix


# N = 100 // 10
# K = 5
# # M = random_matrix(N, K)
# # print(M)
# M = [[30, 222, 187, 503, 39], [950, 412, 209, 212, 29], [299, 949, 217, 59, 349], [853, 230, 901, 174, 365], [64, 262, 477, 50, 494], [577, 479, 355, 92, 160], [783, 523, 497, 761, 365], [230, 691, 21, 43, 359], [606, 296, 315, 76, 158], [663, 678, 106, 375, 982]]
#
# print(split_secret(b"x", N, K, M))
#
# print(np.dot(M, [1,2,3,4,5]))


def to_mod_inv(n: float, mod: int):
    p10 = 1
    while n != int(n):
        n *= 10
        p10 *= 10

    n = int(n)
    inv_p10 = pow(p10, -1, mod)
    return (n * inv_p10) % mod


def main():
    print(M[:5])
    print(getMatrixInverse(M[:5]))


if __name__ == '__main__':
    # reconstitute_secret([(0, 0), (1, 0), (2, 0), (3, 0), (4, 0)], M)
    main()
