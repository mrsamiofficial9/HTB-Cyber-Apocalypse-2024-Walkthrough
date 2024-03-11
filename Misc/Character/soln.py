from pwn import remote


def get_flag_character(index):
    r = remote("83.136.253.251", 43158)

    # Input the index
    r.sendline(str(index))

    # Get the output
    output = r.recvline().decode().strip()

    # Close the connection
    r.close()

    # Extract the character
    flag_character = output.split(":")[-1].strip()

    return flag_character


def main():
    flag = ""
    for index in range(107):  # Assuming the flag has 107 characters
        character = get_flag_character(index)
        flag += character

    print("Flag:", flag)


if __name__ == "__main__":
    main()
