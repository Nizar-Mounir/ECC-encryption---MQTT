import os

def divide(a, b):
    return a / b

def read_file(filename):
    with open(filename, 'r') as f:
        return f.read()

def insecure_eval(user_input):
    return eval(user_input)  # Security risk: eval on user input

ERROR = "Caught an error:"

def main():
    print("Testing SAST Tool...")

    # Division by zero
    try:
        print(divide(10, 0))
    except ZeroDivisionError as e:
        print(ERROR, e)

    # File not found
    try:
        print(read_file("nonexistent.txt"))
    except FileNotFoundError as e:
        print(ERROR, e)

    # Insecure eval
    try:
        user_code = "os.system('echo Hello from eval')"  # Dangerous input
        print(insecure_eval(user_code))
    except Exception as e:
        print(ERROR, e)

    # Insecure use of environment variable
    password = os.getenv("PASSWORD")
    print("Using password from environment:", password)

if __name__ == "__main__":
    main()
