def example_function(x, y):
    z = x + y
    print(f"z = {z}")  # Debug logging
    if z > 10:
        z = z - 5
    else:
        z = z + 5
    if z == 15:
        return "Path 1"
    else:
        return "Path 2"

def main():
    x = 5  # Hardcoded value
    y = 10  # Hardcoded value
    result = example_function(x, y)
    print(result)

if __name__ == "__main__":
    main()