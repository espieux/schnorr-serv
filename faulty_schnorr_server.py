from flask import Flask, jsonify, request
from hashlib import sha256
from random import randint
from Crypto.Util.number import getPrime

app = Flask(__name__)

# Set the parameters for Schnorr proof
p = getPrime(512)  # Large prime modulus
g = 2  # Generator
x = randint(1, p - 1)  # Private key (secret exponent)
y = pow(g, x, p)  # Public key g^x mod p

#  nonce `k`
k = randint(1, p - 1)  

# the below code is faulty
@app.route('/vulnerable-proof', methods=['GET'])
def vulnerable_schnorr_proof():
    """
    Vulnerable server 
    """
    r = pow(g, k, p)  # Commitment
    # Calculate challenge e as hash of r
    e = int(sha256(str(r).encode()).hexdigest(), 16)
    # Response s = k + e*x mod (p-1)
    s = (k + e * x) % (p - 1)
    proof = {
                'r': r,
                'e': e,
                's': s,
                'y': y,  # Public key
                'g': g,  # Generator
                'p': p,  # Prime modulus
            }
    return jsonify(proof)

@app.route('/')
def home():
    return "Schnorr Proof Server - Query /vulnerable-proof for the vulnerable proof"

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5000)