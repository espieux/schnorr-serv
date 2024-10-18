from flask import Flask, jsonify, request
from hashlib import sha256
from random import randint
from Crypto.Util.number import getPrime

# Flask app initialization
app = Flask(__name__)

# Set the parameters for Schnorr proof
p = getPrime(512)  # Large prime modulus
g = 2  # Generator
x = randint(1, p - 1)  # Private key (secret exponent)
y = pow(g, x, p)  # Public key y = g^x mod p

@app.route('/schnorr-proof', methods=['GET'])
def schnorr_proof():
    """
    Generate Schnorr proof for the secret exponent `x`.
    Return the proof as a JSON object.
    """
    # Generate a random nonce k
    k = randint(1, p - 1)
    # Compute r = g^k mod p
    r = pow(g, k, p)
    # Compute the challenge e as the hash of r and y
    e_input = f'{r}{y}'.encode()
    e = int(sha256(e_input).hexdigest(), 16) % (p - 1)
    # Compute s = k + e * x mod (p - 1)
    s = (k + e * x) % (p - 1)
    # Return the proof (r, e, s) to the user
    proof = {
        'r': r,
        'e': e,
        's': s,
        'y': y,  # Public key
        'g': g,  # Generator
        'p': p,  # Prime modulus
    }
    return jsonify(proof)

def verify_proof(y, r, e, s, g, p):
    """
    Verify the Schnorr proof.
    :param y: Public key
    :param r: Commitment (r)
    :param e: Challenge (e)
    :param s: Response (s)
    :param g: Generator
    :param p: Prime modulus
    :return: Boolean indicating whether the proof is valid or not
    """
    # Compute lhs = g^s mod p
    lhs = pow(g, s, p)
    # Compute rhs = r * y^e mod p
    rhs = (r * pow(y, e, p)) % p
    # Return True if lhs equals rhs, False otherwise
    return lhs == rhs

@app.route('/verify-proof', methods=['POST'])
def verify_schnorr_proof():
    """
    Verify the Schnorr proof provided by the user.
    Expects JSON with fields: 'r', 'e', 's', 'y', 'g', 'p'
    """
    data = request.get_json()
    # Extract the proof data from the request
    r = int(data['r'])
    e = int(data['e'])
    s = int(data['s'])
    y = int(data['y'])
    g = int(data['g'])
    p = int(data['p'])
    # Call the verification function
    valid = verify_proof(y, r, e, s, g, p)
    # Prepare the result
    result = {
        'valid': valid,
        'message': 'Proof is valid!' if valid else 'Proof is invalid!'
    }
    return jsonify(result)

@app.route('/')
def home():
    return "Schnorr Proof Server - Query /schnorr-proof to get a Schnorr proof or /verify-proof to verify a proof"

if __name__ == '__main__':
    # Start the Flask server
    app.run(host='0.0.0.0', port=5000)
