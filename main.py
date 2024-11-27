# main.py
from elgamal_encryption import ElGamalCrypto
from server import Server
from des_encryption import encrypt_3des, decrypt_3des

def main():

    crypto = ElGamalCrypto()
    
    # Initiating Key K given by Third party and message m to be encrypted
    k = 17
    m = 26  
    
    
    # Print original message
    print(f"Original message is: {m}")
    
    # For Symmetric Key encyption od message we have chosen 3DES
    encrypted_message = encrypt_3des(m, k)
    
    

    y = crypto.generate_public_key(k)
    print(f"Alice's original key k: {k}")
    
    
    # Server transforms the key
    server = Server()
    k_transformed = server.transform_key(k, y)
    
    # For the attribute with many options(AND OR) values are sent as list within tuple <Yes, No, [Yes,Yes,No], No>
    print("Bob makes request to server")
    print("Are you a Graduate?")
    a = int(input("Enter 1 for Yes and 0 for No: "))
    print("Are you a Undergraduate?")
    b = int(input("Enter 1 for Yes and 0 for No: "))
    print("Are you a CS?")
    c = int(input("Enter 1 for Yes and 0 for No: "))

    bob_request = [a, b, c] #1-Yes 0-No
    
    # Choose s_cpb first
    s_cpb = 11
    
    # Calculate x_cpb to ensure s_cpb + x_cpb = k
    x_cpb = k - s_cpb
    
    
    
    if server.verify_request(bob_request):
        # Reencrpyt key for Bob if verifies conditions and send to bob
        k_reencrypted = server.reencrpyt_key(k_transformed, y, s_cpb)
        
        # Bob decrypts the reencrypted value
        #Since for implementation we are only working on single attribute with multiple options no need to multiply
        k_restored = crypto.decrypt(*k_reencrypted, x_cpb)
        print(f"Bob restores k: {k_restored}")
        
        # Bob decrypts the encrypted message using 3DES using restored k
        decrypted_message = decrypt_3des(encrypted_message, k_restored)
        print(f"The decrypted message obtained by Bob is: {decrypted_message}")

if __name__ == "__main__":
    main()