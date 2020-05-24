P = 95820804521871446624646154398560990164494336030962272285033480112778980081147


# https://stackoverflow.com/questions/32114054/matrix-inversion-without-numpy
#################### FROM STACKOVERFLOW - INVERSE OF MATRIX IN NATIVE PYTHON ####################
# Modified to give mod inverse instead of decimal
def transposeMatrix(m):
    return [[m[j][i] for j in range(len(m))] for i in range(len(m[0]))]


def getMatrixMinor(m, i, j):
    return [row[:j] + row[j + 1:] for row in (m[:i] + m[i + 1:])]


def getMatrixDeternminant(m):
    # base case for 2x2 matrix
    if len(m) == 2:
        return m[0][0] * m[1][1] - m[0][1] * m[1][0]

    determinant = 0
    for c in range(len(m[0])):
        determinant += ((-1) ** c) * m[0][c] * getMatrixDeternminant(getMatrixMinor(m, 0, c))
    return determinant


def getMatrixInverse(m):
    assert len(m) == len(m[0]), "only works for nxn matrices"
    determinant = getMatrixDeternminant(m)
    # special case for 2x2 matrix:
    if len(m) == 2:
        raise Exception("deal with this later if it comes up")
        # return [[m[1][1] / determinant, -1 * m[0][1] / determinant],
        #         [-1 * m[1][0] / determinant, m[0][0] / determinant]]

    # find matrix of cofactors
    cofactors = []
    for r in range(len(m)):
        cofactorRow = []
        for c in range(len(m[0])):
            minor = getMatrixMinor(m, r, c)
            cofactorRow.append(((-1) ** (r + c)) * getMatrixDeternminant(minor))
        cofactors.append(cofactorRow)
    cofactors = transposeMatrix(cofactors)
    inv = pow(determinant, -1, P)
    for r in range(len(cofactors)):
        for c in range(len(cofactors)):
            cofactors[r][c] = (cofactors[r][c] * inv) % P
    return cofactors


###############################################################################################