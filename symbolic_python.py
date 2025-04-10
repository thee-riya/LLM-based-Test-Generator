import angr
import claripy

# Load the compiled Python binary (e.g., created with PyInstaller)
project = angr.Project('./dist/example1', auto_load_libs=False)

# Find critical addresses (adjust using your disassembly)
# -----------------------------------------------------
# 1. Find input handling address (e.g., where input() is called)
# 2. Find address of "Reached Target!" branch
input_handler_addr = 0x401234  # Replace with actual address from disassembly
target_addr = 0x401567        # Replace with print("Reached Target!") address

# Create symbolic input
sym_input = claripy.BVS('input', 32)  # 32-bit symbolic value

# Configure initial state
state = project.factory.blank_state(addr=input_handler_addr)
state.memory.store(state.regs.rsp + 8, sym_input)  # Stack-based input storage

# Setup constraints for Python integer handling
state.add_constraints(sym_input >= 0)  # Python ints are signed but often treated as unsigned

# Create simulation manager
simgr = project.factory.simulation_manager(state)

# Explore paths to target
simgr.explore(find=target_addr)

# Extract solutions
if simgr.found:
    found_state = simgr.found[0]
    solution = found_state.solver.eval(sym_input)
    min_val = found_state.solver.min(sym_input)
    max_val = found_state.solver.max(sym_input)
    print(f"Valid inputs: {solution} (Range: {min_val}-{max_val})")
else:
    print("No valid inputs found")