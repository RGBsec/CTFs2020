from collections import deque
from pwn import remote, process


def solve(N: int, K: int, colleges: list, students: deque, names: list) -> str:
    print(N)
    # print(K)
    # print(students)
    # print(colleges)
    # print(names)
    free_students = deque(range(N), maxlen=N)
    accepted = [-1 for _ in range(N)]

    # while there are students that haven't picked a college
    while len(free_students) > 0:
        # print(accepted)
        # get a free student
        student_id = free_students.popleft()
        # in order of preference, iterate through each college
        for college_id in students[student_id]:
            # if the college hasn't accepted anyone, accept this student
            if accepted[college_id] < 0:
                accepted[college_id] = student_id
                break
            # otherwise check if the college wants this student more
            else:
                other_student = accepted[college_id]
                # if so, change accepted student, and bump the other one to be free again
                if colleges[college_id][student_id] < colleges[college_id][other_student]:
                    free_students.append(accepted[college_id])
                    accepted[college_id] = student_id
                    break
                # if not, keep going

    # print(accepted)
    assert -1 not in accepted
    assert len(set(accepted)) == len(accepted)
    return names[accepted[K]]


def main():
    rem = remote("algo.hsctf.com", 4002)
    # rem = process(["python3", "test_holly.py"])

    for _ in range(15):
        resp = rem.recvuntil("case").decode()
        assert "Here's case" in resp, resp
        resp = rem.recvline().decode()
        assert "!" in resp, resp
        N, K = rem.recvline().decode().strip().split()
        N = int(N)
        K = int(K)

        colleges = [[-1 for _ in range(N)] for _ in range(N)]
        for college in range(N):
            tmp = [int(n) for n in rem.recvline().decode().strip().split()]
            for i, n in enumerate(tmp):
                colleges[college][n] = i
            assert -1 not in colleges[college]
            assert len(set(colleges[college])) == len(colleges[college])

        students = deque(maxlen=N)
        for student in range(N):
            students.append([int(n) for n in rem.recvline().decode().strip().split()])

        names = []
        for name in range(N):
            names.append(rem.recvline().decode().strip())

        ans = solve(N, K, colleges, students, names)

        print("ans:", ans)
        rem.sendline(ans)
    print(rem.recvall(3).decode())


if __name__ == '__main__':
    main()
