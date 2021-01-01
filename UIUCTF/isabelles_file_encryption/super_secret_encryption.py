#!/usr/bin/python

# password-protect your files with this super powerful encryption!
def super_secret_encryption(file_name, password):
    with open(file_name, "rb") as f:
        plaintext = f.read()

    assert (len(password) == 8)  # I heard 8 character long passwords are super strong!
    assert (password.decode("utf-8").isalpha())  # The numbers on my keyboard don't work...
    assert (b"Isabelle" in plaintext)  # Only encrypt files Isabelle has been mentioned in
    add_spice = lambda b: 0xff & ((b << 1) | (b >> 7))
    ciphertext = bytearray(add_spice(c) ^ password[i % len(password)] for i, c in enumerate(plaintext))

    with open(file_name + "_encrypted", "wb") as f:
        f.write(ciphertext)


# use this to decrypt the file with the same password!
def super_secret_decryption(file_name, password):
    with open(file_name + "_encrypted", "rb") as f:
        ciphertext = f.read()

    remove_spice = lambda b: 0xff & ((b >> 1) | (b << 7))
    plaintext = bytearray(remove_spice(c ^ password[i % len(password)]) for i, c in enumerate(ciphertext))

    with open(file_name + "_decrypted", "wb") as f:
        f.write(plaintext)


with open("password", "rb") as f:  # I got too lazy typing it in each time
    password = f.read()
    # Make sure to encrypt the text in the middle!!!
    super_secret_encryption("blackmail", password)
    super_secret_decryption("blackmail", password)
