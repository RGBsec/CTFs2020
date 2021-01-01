from math import floor
from time import time, sleep

noSquares = 70
noSquaresY = 70
matrix = [[0 for _ in range(noSquares)] for _ in range(noSquares)]
start = 160760000  # Legend has it that he who saw the Big Bang holds all the secrets of this Universe


def unpack(h):
    bits = []
    for i in range(0, len(h), 2):
        parsed = bin(int(h[i:i + 2], 16))[2:]
        parsed = parsed.rjust(8, '0')
        bits.extend([int(c) for c in parsed])
    return bits


def getCell(x, y):
    if x < 0:
        x = noSquares - 1
    if x >= noSquares:
        x = 0

    if y < 0:
        y = noSquares - 1
    if y >= noSquares:
        y = 0
    return matrix[x][y]


def putCell(x, y, val):
    if x < 0:
        x = noSquares - 1
    if x >= noSquares:
        x = 0

    if y < 0:
        y = noSquares - 1
    if y >= noSquares:
        y = 0
    matrix[x][y] = val


def getSquare(x, y):
    return [getCell(x, y), getCell(x + 1, y), getCell(x, y + 1), getCell(x + 1, y + 1)]


def putSquare(x, y, vals):
    putCell(x, y, vals[0])
    putCell(x + 1, y, vals[1])
    putCell(x, y + 1, vals[2])
    putCell(x + 1, y + 1, vals[3])


def processSquare(x, y):
    square = getSquare(x, y)
    noLiveCells = sum(square)
    if noLiveCells != 2:
        for i in range(len(square)):
            if square[i] == 1:
                square[i] = 0
            else:
                square[i] = 1

    if noLiveCells == 3:
        newSquare = [square[3], square[2], square[1], square[0]]
        square = newSquare
    return square


def revSquare(x, y):
    square = getSquare(x, y)
    noLiveCells = sum(square)

    if noLiveCells == 1:
        square = [square[3], square[2], square[1], square[0]]

    if noLiveCells != 2:
        for i in range(len(square)):
            if square[i] == 1:
                square[i] = 0
            else:
                square[i] = 1
    return square


def nextMatrix(m, roundNo):
    startCoord = -(roundNo % 2)

    print(f'Round #{roundNo}')
    for i in range(startCoord, noSquares, 2):
        for j in range(startCoord, noSquares, 2):
            putSquare(i, j, processSquare(i, j))
    if roundNo == 500:
        assert sum([sum(row) for row in matrix]) == 2396
    elif roundNo == 3000:
        assert sum([sum(row) for row in matrix]) == 2504
    return m


def prevMatrix(m, roundNo):
    if roundNo == 500:
        assert sum([sum(row) for row in m]) == 2396
    elif roundNo == 3000:
        assert sum([sum(row) for row in m]) == 2504

    startCoord = -(roundNo % 2)

    print(f'Round #{roundNo}')
    for i in reversed(range(startCoord, noSquares, 2)):
        for j in reversed(range(startCoord, noSquares, 2)):
            putSquare(i, j, revSquare(i, j))
    return m


def setupMatrix():
    global matrix
    initialState_packed = "44f694c51bd68cd06d977e67ab21311db80481a9da4a2dc022bbf1373532586444999029d7a516e183a2ab80bb3432382d4c713538e53ce1950b85c0b038d129ac9a503dca2fc015e3086aa1c129e911bb88a6a1116b41535761800c5a0c14ab9f7e18b0c511c456d6ae7950189bd9086a3c13820350750c8d7c7a6f98a00c3665840517c4a49c992604d4abccb3ea05008681b126fe6b802c012251ddf68b19c295d4838868c7215c092dd55c084870e4461210045427cd8f0a71108840801f42dab83480111899caf7b81ac8c0c000217d69043a0670000dc05b409d84a4881a056a2c562c15880b3008edc306d8044881b84192157b57704820003a2b3d4068a544022970cb628526850500cc4cd1600d04003082a642fad829c4198b13f3d5206918125004502c985160001002014018fc68301a0213c40a4ac7fbe04670025a02a868061124180eb044ed622604e00810dc07efd8c002044308384dc02824e9162801e84aa0111880940996f307ae62360060ba64ede92b642920010228098a4ce910944182a04ffe670970120921d1a0b7200c3194502ca26330d9c041300484df3b525ac906221a2e1ebdf10248808eed6033699e2142040db94a9695a024929a20218f512455008da200e85c86452a704a90f639c03d88820408242d34a2d4ad0558829a83d3a2881dc7224d2e62801bc1452028728da094c353276753b06e681fa8120e89842217dfef660254b1d1fb8c2fd0953ea02de6fad34e64a234634401c6bb2a986ca05df4047c34bbb84d7878ae566181134b6db583ceec955a191e36a2f156f248ab39d620d70c90086aa9b738907e93b9e191b01dc7855c680ca090";
    initialState = unpack(initialState_packed)
    for i in range(noSquares):
        for j in range(noSquares):
            matrix[i][j] = initialState[i * noSquares + j]

    now = floor(time() / 10)
    savedStateTime = 160760160

    for i in range(savedStateTime + 1, now + 1):
        matrix = nextMatrix(matrix, i - start)

    nnow = floor(time() / 10)
    while nnow != now:
        for i in range(now + 1, nnow + 1):
            matrix = nextMatrix(matrix, i - start)
        now = nnow
        nnow = floor(time() / 10)
        print(sum([sum(row) for row in matrix]))


# substitute for the JS Canvas stuff
def printMatrix():
    print('\n\n')
    for row in matrix:
        print(''.join(['X' if c else '.' for c in row]))



def solve():
    global matrix
    initialState_packed = "44f694c51bd68cd06d977e67ab21311db80481a9da4a2dc022bbf1373532586444999029d7a516e183a2ab80bb3432382d4c713538e53ce1950b85c0b038d129ac9a503dca2fc015e3086aa1c129e911bb88a6a1116b41535761800c5a0c14ab9f7e18b0c511c456d6ae7950189bd9086a3c13820350750c8d7c7a6f98a00c3665840517c4a49c992604d4abccb3ea05008681b126fe6b802c012251ddf68b19c295d4838868c7215c092dd55c084870e4461210045427cd8f0a71108840801f42dab83480111899caf7b81ac8c0c000217d69043a0670000dc05b409d84a4881a056a2c562c15880b3008edc306d8044881b84192157b57704820003a2b3d4068a544022970cb628526850500cc4cd1600d04003082a642fad829c4198b13f3d5206918125004502c985160001002014018fc68301a0213c40a4ac7fbe04670025a02a868061124180eb044ed622604e00810dc07efd8c002044308384dc02824e9162801e84aa0111880940996f307ae62360060ba64ede92b642920010228098a4ce910944182a04ffe670970120921d1a0b7200c3194502ca26330d9c041300484df3b525ac906221a2e1ebdf10248808eed6033699e2142040db94a9695a024929a20218f512455008da200e85c86452a704a90f639c03d88820408242d34a2d4ad0558829a83d3a2881dc7224d2e62801bc1452028728da094c353276753b06e681fa8120e89842217dfef660254b1d1fb8c2fd0953ea02de6fad34e64a234634401c6bb2a986ca05df4047c34bbb84d7878ae566181134b6db583ceec955a191e36a2f156f248ab39d620d70c90086aa9b738907e93b9e191b01dc7855c680ca090";
    initialState = unpack(initialState_packed)
    for i in range(noSquares):
        for j in range(noSquares):
            matrix[i][j] = initialState[i * noSquares + j]

    savedStateTime = 160760160
    for i in reversed(range(start+1, savedStateTime+1)):
        # matrix = nextMatrix(matrix, i - start)
        matrix = prevMatrix(matrix, i - start)
        # for i in range(noSquares):
        #     for j in range(noSquares):
        #         assert matrix[i][j] == initialState[i * noSquares + j]

    printMatrix()


solve()
# setupMatrix()
#
# # printMatrix()
# while True:
#     sleep(10)
#     now = floor(time() // 10)
#     roundNo = now - start
#     matrix = nextMatrix(matrix, roundNo)
#     # printMatrix()
#     print(sum([sum(row) for row in matrix]))
