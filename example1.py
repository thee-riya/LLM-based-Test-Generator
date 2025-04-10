def analyze_input(num):
    if num > 100 and num <= 200:
        print("Reached Target!")
    else:
        print("Invalid Input!")

if __name__ == "__main__":
    user_input = int(input("Enter a number: "))
    analyze_input(user_input)
