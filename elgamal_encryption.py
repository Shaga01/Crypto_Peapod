from crypto_utils import mod_pow, mod_inverse

class ElGamalCrypto:
    def __init__(self, p=23, g=5):
        
        self.p = p  
        self.g = g  

    def generate_public_key(self, private_key):
       
        return mod_pow(self.g, private_key, self.p)

    def encrypt(self, m, y, s):
        #Encrypt message using ElGamal encryption
        # c1 = g^s mod p
        c1 = mod_pow(self.g, s, self.p)
        
        # Shared secret = y^s mod p
        shared_secret = mod_pow(y, s, self.p)
        
        # c2 = m * shared_secret mod p
        c2 = (m * shared_secret) % self.p
        
        return c1, c2

    def decrypt(self, c1, c2, x):
        #Decrypt ciphertext using private key
        # Compute shared secret
        shared_secret = mod_pow(c1, x, self.p)
        
        # Compute modular multiplicative inverse
        shared_secret_inv = mod_inverse(shared_secret, self.p)
        
        # Recover message
        m = (c2 * shared_secret_inv) % self.p
        
        return m