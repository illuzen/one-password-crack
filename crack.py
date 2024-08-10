import hashlib
import json
import base64
import hmac
from Crypto.Cipher import AES
import time
import struct
import multiprocessing
from tqdm import tqdm
from functools import partial

password_file = './passwords.txt'

def try_password(pw, salt, iterations, encrypted_master, encrypted_overview):
    try:
        password = pw.encode()
        derived_key = hashlib.pbkdf2_hmac('sha512', password, salt, iterations)
        key = derived_key[:32]
        hmac_key = derived_key[32:64]

#         print(salt, iterations, password, derived_key, key, hmac_key)

        master_key, master_mac_key = decrypt_keys(encrypted_master, key, hmac_key)
        overview_key, overview_mac_key = decrypt_keys(encrypted_overview, key, hmac_key)
        return True, pw
    except Exception as e:
#         print('Incorrect password: "{}": {}'.format(pw, e))
        return False, pw


def decrypt_keys(encrypted_key, derived_key, derived_mac_key):
    """Decrypt all encrypted keys"""
    key_base = decrypt_opdata(
        encrypted_key, derived_key, derived_mac_key)

    keys = hashlib.sha512(bytes(key_base))
    digest = keys.digest()

    key_from_digest = digest[:32]
    hmac_from_digest = digest[32:64]

    return key_from_digest, hmac_from_digest

def decrypt_opdata(cipher_text, cipher_key, cipher_mac_key):
    """Decrypt opvault data"""
    key_data = cipher_text[:-32]
    mac_data = cipher_text[-32:]

    check_hmac(key_data, cipher_mac_key, mac_data)

    plaintext = decrypt_data(
        cipher_key, key_data[16:32], key_data[32:])
    plaintext_size = int(struct.unpack('Q', key_data[8:16])[0])

    plaintext_start = plaintext_size*-1
    opdata = plaintext[plaintext_start:]

    return opdata

def check_hmac(data, hmac_key, desired_hmac):
    """Check if hmac matches"""
    computed_hmac = hmac.new(
        hmac_key, msg=data, digestmod=hashlib.sha256).digest()

    if bytes(computed_hmac) != bytes(desired_hmac):
        raise Exception('Error checking HMAC')

    return True

def decrypt_data(key, initialization_vector, data):
    """Decrypt data"""
    cipher = AES.new(key, AES.MODE_CBC, initialization_vector)
    return cipher.decrypt(data)


def crack():
    data = None
    with open('./profile.json', 'r') as profile:
        data = json.load(profile)
        print(data)

    # if using sqlite input, the data will be hex string, so you can decode it to bytes like this
#     salt = bytes.fromhex(data['salt'])
#     encrypted_master = bytes.fromhex(data['masterKey'])
#     encrypted_overview = bytes.fromhex(data['overviewKey'])
    # if using profile.js, you will need to decode from base64 like this
    salt = bytes(base64.decodebytes(data['salt'].encode()))
    encrypted_master = bytes(base64.decodebytes(data['masterKey'].encode()))
    encrypted_overview = bytes(base64.decodebytes(data['overviewKey'].encode()))
    iterations = data['iterations']
    print(salt, iterations, encrypted_master, encrypted_overview)

    # passwords into memory
    passwords = None
    with open(password_file, 'r') as file:
        passwords = [
            line.replace('\n', '')
            for line in file.readlines()
        ]

    num_processes = multiprocessing.cpu_count() - 2 # Use all available CPU cores - 2
    t0 = time.time()

    with multiprocessing.Pool(processes=num_processes) as pool:
        func = partial(try_password, salt=salt, iterations=iterations, encrypted_master=encrypted_master, encrypted_overview=encrypted_overview)

        results = []
        pbar = tqdm(total=len(passwords), desc="Processing", unit="item")

        for should_stop, result in pool.imap_unordered(func, passwords):
            results.append(result)
            pbar.update(1)

            if should_stop:
                print('This is the password: {}'.format(result))
                pool.terminate()  # Stop all worker processes
                break


        pbar.close()


# old onepassword versions can be found here: https://app-updates.agilebits.com/

if __name__ == '__main__':

    crack()

