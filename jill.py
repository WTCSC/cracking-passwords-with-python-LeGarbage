import argparse
import hashlib
def main():
    parser = argparse.ArgumentParser(description='Uses a word list to crack passwords in a password list') # Argparse stuff
    parser.add_argument("password_file", help="The file that contains the list of passwords you wish to crack") # Positional argument
    parser.add_argument("word_file", help="The file that contains the words used to crack the passwords") # Positional argument
    args = parser.parse_args()
    passwords = open(args.password_file, "r") # Opens the files
    words = open(args.word_file, "r")
    password_list = passwords.readlines() # Splits the files into lists of lines
    word_list = words.readlines()
    hashed_words = [hash_password(i.strip()) for i in word_list] # Hashes each word in the word list so they can be compared to the hashed passwords later
    for i in password_list:
        username, password = i.strip().split(":") # Splits the entry in the password list into the username and password
        if password in hashed_words: # If the password is found in the hashed words list,
            print(f"{username}:{word_list[hashed_words.index(password)]}".strip()) # Then find it in the unhashed words list and print it along with the username
    passwords.close() # Close the file
    words.close()
def hash_password(password):
    sha256_hash = hashlib.sha256()
    sha256_hash.update(password.encode())
    return sha256_hash.hexdigest()
if __name__ == "__main__":
    main()