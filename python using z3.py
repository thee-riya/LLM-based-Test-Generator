def target_function():
    """This function represents the target state we want to reach."""
    print("Reached Target!")
    
def analyze_input(input_val):
    """
    Analyzes the input value. If it falls within a specific range,
    it calls the target_function.

    Args:
        input_val: An integer input value.
                   (Note: Python ints have arbitrary precision,
                    unlike C's fixed-size uint32_t, but the logic
                    of comparison is the same for the given range)
    """
    if input_val > 100 and input_val <= 200:
        target_function()
    else:
        pass

def main():
    """Gets user input and calls the analysis function."""
    try:
        user_input_str = input("Enter number: ")
        user_input = int(user_input_str)
        analyze_input(user_input)
    except ValueError:
        print("Invalid input. Please enter an integer.")

if __name__ == "__main__":
    pass 