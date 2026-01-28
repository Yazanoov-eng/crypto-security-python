import os
import random
#import hashlib
import base64
from Cryptodome.PublicKey import RSA
from Cryptodome.Cipher import PKCS1_OAEP, DES
from Cryptodome.Signature import pkcs1_15
from Cryptodome.Hash import SHA256
from Cryptodome.Util.Padding import pad, unpad
from Cryptodome.Random import get_random_bytes


# --------- RC4 Stream Cipher ---------
def rc4_init(key):
    S = list(range(256))
    j = 0
    for i in range(256):
        j = (j + S[i] + key[i % len(key)]) % 256
        S[i], S[j] = S[j], S[i]
    return S


def rc4_process(data, key):
    S = rc4_init(key)
    i = j = 0
    result = bytearray()
    for idx, byte in enumerate(data):
        i = (i + 1) % 256
        j = (j + S[i]) % 256
        S[i], S[j] = S[j], S[i]
        K = S[(S[i] + S[j]) % 256]
        result.append(byte ^ K)
        print(f"After processing byte {idx + 1}: Key matrix K = {S}")
    return bytes(result)


def rc4_menu():
    while True:
        print("\nRC4 Encryption/Decryption")
        print("1. Encrypt plaintext")
        print("2. Decrypt ciphertext (hex input)")
        print("3. Return to main menu")
        choice = input("Choose an option: ")
        if choice == "1":
            key_str = input("Enter key: ")
            plaintext = input("Enter plaintext: ")
            key = key_str.encode()
            plaintext_bytes = plaintext.encode()
            ciphertext = rc4_process(plaintext_bytes, key)
            print("Ciphertext (hex):", ciphertext.hex())
        elif choice == "2":
            key_str = input("Enter key: ")
            ciphertext_hex = input("Enter ciphertext (hex): ")
            try:
                ciphertext = bytes.fromhex(ciphertext_hex)
            except:
                print("Invalid hex ciphertext!")
                continue
            key = key_str.encode()
            decrypted = rc4_process(ciphertext, key)
            try:
                print("Decrypted plaintext:", decrypted.decode())
            except:
                print("Decrypted bytes:", decrypted)
        elif choice == "3":
            break
        else:
            print("Invalid option!")


# --------- Message Authentication ---------
def message_authentication_menu():
    key_pair = RSA.generate(1024)
    used_nonces = set()

    while True:
        print("\nMessage Authentication")
        print("1. Generate MAC")
        print("2. Verify MAC")
        print("3. Return to main menu")
        choice = input("Choose option: ")

        if choice == "1":
            try:
                message = input("Enter message: ").encode()
                nonce = os.urandom(8)
                combined = nonce + message

                # Generate hash digest
                h = SHA256.new(combined)

                # Sign the digest with private key
                signer = pkcs1_15.new(key_pair)
                signature = signer.sign(h)

                # Build authenticated message
                auth_msg = f"nonce={nonce.hex()}||message={message.decode()}||MAC={base64.b64encode(signature).decode()}"
                print("\nAuthenticated Message:")
                print(auth_msg)

            except Exception as e:
                print(f"Error: {str(e)}")

        elif choice == "2":
            try:
                auth_msg = input("Enter message (nonce||message||MAC): ")
                parts = auth_msg.split("||")

                # Validate format
                if len(parts) != 3 or not all([parts[0].startswith("nonce="),
                                               parts[1].startswith("message="),
                                               parts[2].startswith("MAC=")]):
                    print("Invalid format! Use: nonce=hex||message=text||MAC=base64")
                    continue

                # Extract components
                nonce = bytes.fromhex(parts[0][6:])
                message = parts[1][8:].encode()
                signature = base64.b64decode(parts[2][4:])

                # Check replay attacks
                if nonce in used_nonces:
                    print("Replay attack detected! Nonce already used.")
                    continue

                # Verify signature
                combined = nonce + message
                h = SHA256.new(combined)
                verifier = pkcs1_15.new(key_pair.publickey())

                try:
                    verifier.verify(h, signature)
                    print("\nMAC Valid! Message is authentic and fresh")
                    used_nonces.add(nonce)
                except (ValueError, TypeError):
                    print("\nMAC Invalid! Message may be altered")

            except Exception as e:
                print(f"Error: {str(e)}")

        elif choice == "3":
            break

        else:
            print("Invalid option!")


# --------- Digital Envelope ---------
def des_ctr_encrypt(plaintext, key, counter_start):
    des_ciphertext = b""
    counter = counter_start
    des = DES.new(key, DES.MODE_ECB)

    for i in range(0, len(plaintext), 8):
        block = plaintext[i:i + 8]
        counter_block = counter.to_bytes(8, 'big')
        encrypted_counter = des.encrypt(counter_block)
        cipher_block = bytes([b ^ e for b, e in zip(block, encrypted_counter[:len(block)])])
        des_ciphertext += cipher_block
        counter += 1
    return des_ciphertext, counter


def des_ctr_decrypt(ciphertext, key, counter_start):
    return des_ctr_encrypt(ciphertext, key, counter_start)[0]


def digital_envelope_menu():
    key_pair = RSA.generate(1024)
    # Initialize counter with random value and maintain state
    current_counter = random.randint(0, 2 ** 64 - 1)

    while True:
        print("\nDigital Envelope")
        print("1. Encrypt")
        print("2. Decrypt")
        print("3. Return to main menu")
        choice = input("Choose option: ")

        if choice == "1":
            try:
                plaintext = input("Enter message: ").encode()
                des_key = get_random_bytes(8)

                # Encrypt with current counter
                ciphertext, new_counter = des_ctr_encrypt(plaintext, des_key, current_counter)

                # Encrypt DES key
                cipher = PKCS1_OAEP.new(key_pair.publickey())
                enc_des_key = cipher.encrypt(des_key)

                print("\nEncrypted Envelope:")
                print(f"DES Key: {des_key.hex()}")
                print(f"Encrypted DES Key (hex): {enc_des_key.hex()}")
                print(f"Ciphertext (hex): {ciphertext.hex()}")
                print(f"Used Counter : {current_counter}")

                # Update counter for next operation
                current_counter = new_counter

            except Exception as e:
                print(f"Error: {str(e)}")

        elif choice == "2":
            try:
                enc_des_key = bytes.fromhex(input("Enter encrypted DES key (hex): "))
                ciphertext = bytes.fromhex(input("Enter ciphertext (hex): "))
                counter_start = int(input("Enter counter : "))

                # Decrypt DES key
                cipher = PKCS1_OAEP.new(key_pair)
                des_key = cipher.decrypt(enc_des_key)

                # Decrypt message
                plaintext = des_ctr_decrypt(ciphertext, des_key, counter_start)
                print("\nDecrypted Message:", plaintext.decode())

            except Exception as e:
                print(f"Error: {str(e)}")

        elif choice == "3":
            break

        else:
            print("Invalid option!")


# --------- Main Menu ---------
def main():
    try:
        while True:
            print("\nMain Menu")
            print("1. RC4 Encryption")
            print("2. Message Authentication")
            print("3. Digital Envelope")
            print("4. Exit")

            try:
                choice = input("Choose option: ")
            except KeyboardInterrupt:
                print("\nExiting program...")
                break

            if choice == "1":
                rc4_menu()
            elif choice == "2":
                message_authentication_menu()
            elif choice == "3":
                digital_envelope_menu()
            elif choice == "4":
                print("Exiting program...")
                break
            else:
                print("Invalid option!")
    except KeyboardInterrupt:
        print("\nExiting program...")


if __name__ == "__main__":
    main()