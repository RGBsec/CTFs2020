noSquares = 5

matrix = [
    [1, 0, 1, 0, 1],
    [1, 0, 0, 1, 1],
    [0, 1, 1, 0, 0],
    [1, 1, 0, 0, 1],
    [1, 0, 1, 0, 0]
]


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
    print(square)
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
    print(square)
    print()
    return square


def revSquare(x, y):
    square = getSquare(x, y)
    print(square)
    noLiveCells = sum(square)

    if noLiveCells == 1:
        square = [square[3], square[2], square[1], square[0]]

    if noLiveCells != 2:
        for i in range(len(square)):
            if square[i] == 1:
                square[i] = 0
            else:
                square[i] = 1
    print(square)
    print()
    return square


def nextMatrix(m, roundNo):
    startCoord = -(roundNo % 2)

    print(f'Round #{roundNo}')
    for i in range(startCoord, noSquares, 2):
        for j in range(startCoord, noSquares, 2):
            putSquare(i, j, processSquare(i, j))
    if roundNo == 500:
        assert sum([sum(row) for row in m]) == 2396
    elif roundNo == 3000:
        assert sum([sum(row) for row in m]) == 2504
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


def printMatrix():
    print('\n\n')
    for row in matrix:
        print(''.join([str(c) for c in row]))


printMatrix()
matrix = nextMatrix(matrix, 0)
printMatrix()
matrix = prevMatrix(matrix, 0)
printMatrix()
