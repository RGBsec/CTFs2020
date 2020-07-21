with open("log", 'r') as f:
    lines = [l.strip() for l in f]

starts = [l[:6] for l in lines]
ends = [l[-4:] for l in lines]
print(set(starts))
print(set(ends))

# import matplotlib.pyplot as plt
#
# with open("log", 'r') as f:
#     lines = [str(int(l.strip(), 16)) for l in f]
#
# # tups = [(int(line[:9]) - 623133251, int(line[9:])) for line in lines]
# tups = [(int(line[:9]) / 1e6, int(line[9:]) / 1e6) for line in lines]
# tups = [t for t in tups]# if t[0] < 20]
# tups.sort(key=lambda t: t[1])
# for t in tups:
#     print(t)
#
# X = [t[0] for t in tups]
# Y = [t[1] for t in tups]
#
# print(min(X), max(X))
# print(min(Y), max(Y))
#
# fig = plt.figure()
# ax1 = fig.add_subplot(111)
#
# ax1.set_title("Coords? Pls work")
# ax1.scatter(X, Y, s=1, c='black', marker='x')
# # plt.show()