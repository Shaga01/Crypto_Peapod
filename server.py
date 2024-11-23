from elgamal_encryption import ElGamalCrypto

class Server:
    def __init__(self):
        self.crypto = ElGamalCrypto()
        self.k_transformed = None
        self.k_reencrypted = None

    def transform_key(self, k, y):
        #Transform key using ElGamal encryption
        
        s = 15
        print("Server: Transforming key")
        # get transformed ciphertext
        c1, c2 = self.crypto.encrypt(k, y, s)
        
        
        print("Key Transformed")
        
        self.k_transformed = (c1, c2)
        return self.k_transformed

    def verify_request(self, request):
        #Verify Bob's request
        a, b, c = request
        
        # Compute verification value
        verify_val = (
            a * b * (1 - c) + 
            (1 - a) * (1 - b) * c + 
            a * (1 - b) * c + 
            (1 - a) * b * c
        )
        
        if verify_val == 0:
            print("Bob doesn't match")
            return False
        
        print("Bob matches")
        return True

    def reencrpyt_key(self, k_transformed, y, s_cpb):
        # Re-encryption of the transformed key without decrypting back to k
        c1, c2 = k_transformed

      
        c1_new = c1  # The c1 part remains unchanged
        c2_new = (c2 * pow(y, s_cpb)) % self.crypto.p  # Re-encrypt c2 with y^s_cpb
    
        print("Re-encrypt Key and send to Bob")
        self.k_reencrypted = (c1_new, c2_new)
        return self.k_reencrypted
        