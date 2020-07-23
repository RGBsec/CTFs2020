import angr, claripy, sys, binascii

def main():
    proj = angr.Project('./r1sc', load_options={"auto_load_libs": False})
    inp_len = 48
    argv1 = claripy.BVS("argv1", inp_len * 8)

    initial_state = proj.factory.entry_state(stdin=argv1) 
    for byte in argv1.chop(8):
        initial_state.add_constraints(byte != '\x00') # null
        initial_state.add_constraints(byte >= ' ') # '\x20'
        initial_state.add_constraints(byte <= '~') # '\x7e'
    
    

    sm = proj.factory.simulation_manager(initial_state)
    sm.explore(find=lambda s: b"Access authorized" in s.posix.dumps(sys.stdout.fileno()), avoid=lambda s: b"Access denied" in s.posix.dumps(sys.stdout.fileno()))

    found = sm.found[0]
    flag_addr = found.regs.rdi
    found.add_constraints(found.memory.load(flag_addr, 5) == int(binascii.hexlify(b"flag{"), 16))
    
    flag_str = found.solver.eval(argv1, cast_to=bytes)
    return flag_str.rstrip(b'\0')

def test():
    res = main()
    print(repr(res))


if __name__ == '__main__':
    test()