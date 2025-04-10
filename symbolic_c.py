import angr
import claripy

# Load compiled binary
project = angr.Project('./example', auto_load_libs=False)

# Get function addresses from symbols
target_addr = project.loader.main_object.get_symbol("target_function").rebased_addr
start_addr = project.loader.main_object.get_symbol("analyze_input").rebased_addr

sym_input = claripy.BVS('input', 32)               #creates a 32-bit symbolic bitvector

state = project.factory.blank_state(
    addr=start_addr,
    add_options={angr.options.SYMBOL_FILL_UNCONSTRAINED_MEMORY}
)
state.regs.rdi = sym_input  # x86_64 first argument register

# Create simulation manager
simgr = project.factory.simulation_manager(state)

# Explore paths to target function
simgr.explore(find=target_addr)

if simgr.found:
    solution = simgr.found[0].solver.eval(sym_input)
    print(f"Valid input reaching target: {solution}")
    print(f"Input range: {simgr.found[0].solver.min(sym_input)}-{simgr.found[0].solver.max(sym_input)}")
else:
    print("No solution found")
