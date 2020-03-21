import angr, sys, claripy
from z3 import *


def is_successful(state):
    inp = state.posix.dumps(sys.stdin.fileno())
    out = state.posix.dumps(sys.stdout.fileno())
    return b'Correct Password' in out and b'rift' in inp and len(inp) < 60


def should_abort(state):
    out = state.posix.dumps(sys.stdout.fileno())
    return b'Wrong Password' in out


def main():
    p = angr.Project('rev2.elf')
    arg1 = claripy.BVS('arg1', input("len: "))
    argv = [
        p.filename,
        arg1
    ]
    state = p.factory.entry_state(args=argv)
    sim = p.factory.simgr(state)

    sim.explore(find=is_successful, avoid=should_abort)
    print(sim)
    for sol in sim.found:
        print(sol.posix.dumps(sys.stdin.fileno()))
        print(sol.posix.dumps(sys.stdout.fileno()))
        print(sol.solver.eval(arg1, cast_to=bytes))
        print()


if __name__ == "__main__":
    main()
