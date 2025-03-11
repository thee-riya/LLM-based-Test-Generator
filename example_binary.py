def example_function(x, y):
    z = x + y
    if z > 10:
        z = z - 5
    else:
        z = z + 5
    if z == 15:
        return "Path 1"
    else:
        return "Path 2"

def main():
    x = int(input("Enter x: "))
    y = int(input("Enter y: "))
    result = example_function(x, y)
    print(result)

if __name__ == "__main__":
    main()