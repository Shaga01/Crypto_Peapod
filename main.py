import os
import time
import random
from elgamal_encryption import ElGamalCrypto
from server import Server
from des_encryption import encrypt_3des, decrypt_3des

def can_transform_key():
    timestamp_file = "last_transform_key_access.txt"
    if os.path.exists(timestamp_file):
        with open(timestamp_file, "r") as file:
            last_access = float(file.read().strip())
        if time.time() - last_access < 86400:
            return False
    with open(timestamp_file, "w") as file:
        file.write(str(time.time()))
    return True

def send_otp():
    otp = random.randint(1000, 9999)  # Generate a 4-digit OTP
    print(f"Your OTP is: {otp}")  # Simulates sending the OTP (use SMS/email API in real-world apps)
    return otp

def verify_otp(expected_otp):
    user_otp = int(input("Enter the OTP sent to you: "))
    return user_otp == expected_otp

def main():
    crypto = ElGamalCrypto()
    k = 17
    m = 26
    print(f"Original message is: {m}")
    encrypted_message = encrypt_3des(m, k)
    y = crypto.generate_public_key(k)
    print(f"Alice's original key k: {k}")
    server = Server()

    if can_transform_key():
        otp = send_otp()
        if not verify_otp(otp):
            print("OTP verification failed. Exiting.")
            return
        k_transformed = server.transform_key(k, y)
    else:
        print("The key transformation function can only be used once per day.")
        return

    print("Bob makes request to server")
    print("Are you a Graduate?")
    a = int(input("Enter 1 for Yes and 0 for No: "))
    print("Are you an Undergraduate?")
    b = int(input("Enter 1 for Yes and 0 for No: "))
    print("Are you a CS?")
    c = int(input("Enter 1 for Yes and 0 for No: "))
    bob_request = [a, b, c]

    s_cpb = 11
    x_cpb = k - s_cpb

    if server.verify_request(bob_request):
        k_reencrypted = server.reencrpyt_key(k_transformed, y, s_cpb)
        k_restored = crypto.decrypt(*k_reencrypted, x_cpb)
        print(f"Bob restores k: {k_restored}")
        decrypted_message = decrypt_3des(encrypted_message, k_restored)
        print(f"The decrypted message obtained by Bob is: {decrypted_message}")

if __name__ == "__main__":
    main()
