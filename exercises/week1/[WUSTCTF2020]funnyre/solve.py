import angr
import claripy


def Go():
    project = angr.Project("./attachment")
    initial_state = project.factory.entry_state(addr=0x400605)
    flag = claripy.BVS('flag', 32*8)
    initial_state.memory.store(0xdeadbeef+5, flag)
    initial_state.regs.rdx = 0xdeadbeef
    initial_state.regs.rdi = 0xdeadbeef+5
    simulation = project.factory.simulation_manager(initial_state)
    simulation.explore(find=0x401DA9)

    if simulation.found:
        solution_state = simulation.found[0]
        solution = solution_state.solver.eval(flag, cast_to=bytes)
        print("[+] Success! Solution is: {}".format(solution.decode("utf-8")))
    else:
        raise Exception('Could not find the solution')


if __name__ == "__main__":
    Go()
