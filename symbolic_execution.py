import angr
import claripy

# Create a symbolic execution project
project = angr.Project("./dist/ex_binary_simplified", auto_load_libs=False)

# Define symbolic variables for x and y
x = claripy.BVS('x', 32)  # 32-bit symbolic variable
y = claripy.BVS('y', 32)  # 32-bit symbolic variable

# Create the initial state with symbolic inputs
initial_state = project.factory.entry_state(args=["./dist/ex_binary_simplified", x, y])

# Create a simulation manager
simulation = project.factory.simgr(initial_state)

# Explore all possible paths
simulation.explore()

# Print the results
for state in simulation.deadended:
    # Find the address where the program prints the result
    output = state.posix.dumps(1)  # stdout
    if b"Path 1" in output:
        print("Path 1")
    elif b"Path 2" in output:
        print("Path 2")
    else:
        print("Unknown path")
    
    # Print the inputs
    print("Input x:", state.solver.eval(x))
    print("Input y:", state.solver.eval(y))
    print("Result:", state.solver.eval(state.regs.eax))  # Assuming the result is in eax
    