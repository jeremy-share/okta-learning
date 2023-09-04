#!/usr/bin/env python3

import sys

import bcrypt


def get_password_from_input():
    return input("Enter the password you want to hash: ")


def get_password_from_args(args):
    return args[1] if len(args) > 1 else None


def main():
    password = get_password_from_args(sys.argv) or get_password_from_input()
    hashed_password = bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt())
    print(f"Hashed password: {hashed_password.decode('utf-8')}")


if __name__ == "__main__":
    main()
