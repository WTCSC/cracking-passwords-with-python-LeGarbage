import argparse
import hashlib
import time

def main():
    parser = argparse.ArgumentParser(description='Uses a word list to crack passwords in a password list') # Argparse stuff
    parser.add_argument("password_file", help="The file that contains the list of passwords you wish to crack") # Positional argument
    parser.add_argument("word_file", help="The file that contains the words used to crack the passwords") # Positional argument
    parser.add_argument("-v", "--verbosity", action="store_true", help="Adds additional information about how long it took to crack each password and how many passwords couldn't be cracked") # Flag
    parser.add_argument("-a", "--algorithm", choices=["sha256", "sha512", "md5"], default="sha256", help="The hashing algorithm to be used to crack the passwords") # Optional argument limited to choices
    
    args = parser.parse_args()
    passwords = open(args.password_file, "r") # Opens the files
    words = open(args.word_file, "r")
    password_list = passwords.readlines() # Splits the files into lists of lines
    word_list = words.readlines()
    hashed_words = [hash_password(i.strip(), args.algorithm) for i in word_list] # Hashes each word in the word list so they can be compared to the hashed passwords later
    failed_passwords = 0 # Counts the number of passwords that could not be cracked
    for i in password_list:
        timer = time.clock_gettime_ns(time.CLOCK_MONOTONIC)
        username, password = i.strip().split(":") # Splits the entry in the password list into the username and password
        if password in hashed_words: # If the password is found in the hashed words list,
            elapsed_time = f" ({((time.clock_gettime_ns(time.CLOCK_MONOTONIC) - timer) * 1e-9):f} seconds)" # Then find out how long it took to find,
            print(f"{username}:{word_list[hashed_words.index(password)].strip()}{elapsed_time if args.verbosity else ""}") # And find it in the unhashed words list and print it along with the username and the time if verbosity is flagged
        else: # If the password is not one of the hashed words, 
            failed_passwords += 1 # then increment the fail counter
    if args.verbosity: # If verbosity is flagged,
        if failed_passwords == len(password_list): # Then if no passwords could be cracked,
            print("No passwords could be cracked") # Print that no passwords could be cracked
        else: # Then otherwise,
            print(f"\n{failed_passwords} passwords could not be cracked") # Print how many passwords could not be cracked
    passwords.close() # Close the files
    words.close()


def hash_password(password, algorithm):
    if algorithm == "sha256":
        hashed = hashlib.sha256()
    elif algorithm == "sha512":
        hashed = hashlib.sha512()
    elif algorithm == "md5":
        hashed = hashlib.md5()
    hashed.update(password.encode())
    return hashed.hexdigest()


if __name__ == "__main__":
    main()