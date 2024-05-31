#coding = "utf-8"

import os.path
import base64
from Crypto.Cipher import AES
import getpass

def encrypt_file(filename, password):
    data = get_data(filename)
    new_password = get_md5(password)
    new_data = encrypt_data(data, new_password)
    return write_file(filename, new_data)

def encrypt_string(data, password):
    new_password = get_md5(password)
    new_data = encrypt_data(data.encode('utf-8'), new_password)
    return new_data.decode('utf-8')

def get_data(filename):
    with open(filename, "rb") as f:
        data = f.read()
    return data

def get_md5(password):
    import hashlib
    md5 = hashlib.md5()
    md5.update(password.encode("utf-8"))
    new_password = md5.hexdigest().encode("utf-8")
    return new_password

def encrypt_data(data, password):
    return aes_encrypt(data, password)

def aes_encrypt(data, password):
    pre_encrypt_data = data
    cryptor = AES.new(password, AES.MODE_CBC,  b'bc000000000000bc')
    must_len = 16
    reponse_length = len(pre_encrypt_data)
    add_len = must_len - (reponse_length % must_len)
    pre_encrypt_data += (b'\0' * add_len)
    encrypt_response = cryptor.encrypt(pre_encrypt_data)
    return base64.encodebytes(encrypt_response)

def write_file(filename, new_data, type="encrypt"):
    new_filename = get_new_filename(filename, type)
    with open(new_filename, "wb") as f:
        f.write(new_data)
    return new_filename

def get_new_filename(filename, type="encrypt"):
    if type not in ["decrypt", "encrypt"]:
        raise "I don’t know the encryption and decryption type, must be encrypt or decrypt"
    import os.path
    if type == "encrypt":
        new_filename = os.path.splitext(filename)[0] + ".enc"
    else:
        new_filename = os.path.splitext(filename)[0] + ".dec"
    return new_filename

def decrypt_file(filename, password):
    data = get_data(filename)
    new_password = get_md5(password)
    new_data = decrypt_data(data, new_password)
    return write_file(filename, new_data, 'decrypt')

def decrypt_string(data, password):
    new_password = get_md5(password)
    new_data = decrypt_data(data.encode('utf-8'), new_password)
    return new_data.decode('utf-8')

def decrypt_data(data, password):
    return aes_decrypt(data, password)

def decrypt(data, password):
    return aes_decrypt(data, password)

def aes_decrypt(data, password):
    cryptor = AES.new(password, AES.MODE_CBC, b'bc000000000000bc')
    plain_text = cryptor.decrypt(base64.decodebytes(data))
    return plain_text.rstrip(b'\0')

def display_menu():
    print("Options:")
    print("  1 - Encrypt File")
    print("  2 - Decrypt File")
    print("  3 - Encrypt String")
    print("  4 - Decrypt String")
    print("  Q/q - Quit")

def get_password():
    return getpass.getpass("Please enter the password: ")

def main():
    display_menu()
    option = input("Options: ").strip()

    if option.lower() == 'q':
        print("Bye!")
        return False

    if option == '1':
        filepath = input("Please enter the file to encrypt: ")
        if not os.path.exists(filepath):
            print("The file does not exist")
            return True
        password = get_password()
        print("start to encrypt the file, plase waiting!")
        encrypt_file_path = encrypt_file(filepath, password)
        print("finish encrypt the file, the output is path %s" % encrypt_file_path)
    elif option == '2':
        filepath = input("Please enter the file to decrypt: ")
        if not os.path.exists(filepath):
            print("The file does not exist")
            return True
        password = get_password()
        print("start to decrypt the file, plase waiting!")
        decrypt_file_path = decrypt_file(filepath, password)
        print("finish decrypt the file, the output is path %s" % decrypt_file_path)
    elif option == '3':
        content = input("Please enter the string you want encrypt: ")
        password = get_password()
        print("start to encrypt the string, plase waiting!")
        encrypt_data = encrypt_string(content, password)
        print("finish encrypt string, the output is %s" % encrypt_data)
    elif option == '4':
        content = input("Please enter the string you want decrypt: ")
        password = get_password()
        print("start to decrypt the string, plase waiting!")
        decrypt_data = decrypt_string(content, password)
        print("finish encrypt string, the output is %s" % decrypt_data)
    else:
        print("Invalid option. Please choose a valid option (1, 2, 3, or 4).")
        return True
    return True

if __name__ == "__main__":
    while True:
        print("================================")
        if not main(): break