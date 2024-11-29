from elgamal_encryption import ElGamalCrypto

import json

class Server:
    def __init__(self, state_file="server_state.json"):
        self.crypto = ElGamalCrypto()
        self.k_transformed = None
        self.k_reencrypted = None
        self.state_file = state_file
        self.bob_disqualified = self.load_state()

    def save_state(self):
        # Save Bob's disqualification status to a file
        with open(self.state_file, "w") as file:
            json.dump({"bob_disqualified": self.bob_disqualified}, file)

    def load_state(self):
        # Load Bob's disqualification status from a file
        try:
            with open(self.state_file, "r") as file:
                state = json.load(file)
                return state.get("bob_disqualified", False)
        except FileNotFoundError:
            return False  # Default to not disqualified if no file exists

    def transform_key(self, k, y):
        # Transform key using ElGamal encryption
        s = 15
        print("Server: Transforming key")
        c1, c2 = self.crypto.encrypt(k, y, s)
        print("Key Transformed")
        self.k_transformed = (c1, c2)
        return self.k_transformed

    def verify_request(self, request):
        if self.bob_disqualified:
            print("Bob is disqualified. Verification denied.")
            return False

        # Verify Bob's request
        a, b, c = request
        verify_val = a or (b and c)

        if verify_val == 0:
            print("Bob doesn't match")
            self.bob_disqualified = True  # Disqualify Bob permanently
            self.save_state()  # Save state to file
            return False

        print("Bob matches")
        return True

    def reencrpyt_key(self, k_transformed, y, s_cpb):
        # Re-encryption of the transformed key without decrypting back to k
        if self.bob_disqualified:
            print("Re-encryption denied. Bob is disqualified.")
            return None

        c1, c2 = k_transformed
        c1_new = c1  # The c1 part remains unchanged
        c2_new = (c2 * pow(y, s_cpb)) % self.crypto.p  # Re-encrypt c2 with y^s_cpb
        print("Re-encrypt Key and send to Bob")
        self.k_reencrypted = (c1_new, c2_new)
        return self.k_reencrypted

