import os
import ecdsa
import hashlib
import base58
import csv
import argparse
import time

# Function to generate a random private key
def generate_private_key():
    return os.urandom(32)

# Function to get the public key from the private key
def get_public_key(private_key):
    sk = ecdsa.SigningKey.from_string(private_key, curve=ecdsa.SECP256k1)
    vk = sk.verifying_key
    return b'\x04' + vk.to_string()

# Function to get the Bitcoin address from the public key
def public_key_to_address(public_key):
    sha256_bpk = hashlib.sha256(public_key).digest()
    ripemd160_bpk = hashlib.new('ripemd160', sha256_bpk).digest()
    hashed_pubkey = b'\x00' + ripemd160_bpk  # Add version byte (0x00 for mainnet)
    checksum_full = hashlib.sha256(hashlib.sha256(hashed_pubkey).digest()).digest()
    checksum = checksum_full[:4]
    address = base58.b58encode(hashed_pubkey + checksum)
    return address.decode()

# Convert private key to Wallet Import Format (WIF)
def private_key_to_wif(private_key):
    extended_key = b'\x80' + private_key  # Add 0x80 byte in front of private key for mainnet
    hashed_privkey = hashlib.sha256(hashlib.sha256(extended_key).digest()).digest()
    wif = base58.b58encode(extended_key + hashed_privkey[:4])
    return wif.decode()

# Generate a new private/public key pair and save in CSV
def generate_bitcoin_keypair(num_keys=-1, output_csv='bitcoin_keys.csv'):
    # Check if file exists to avoid rewriting headers
    file_exists = os.path.isfile(output_csv)

    with open(output_csv, mode='a', newline='') as file:  # 'a' mode for append
        writer = csv.writer(file)

        # Write headers only if the file is new
        if not file_exists:
            writer.writerow(['Private Key (hex)', 'Private Key (WIF)', 'Public Key', 'Bitcoin Address'])

        count = 0
        while num_keys == -1 or count < num_keys:
            private_key = generate_private_key()
            public_key = get_public_key(private_key)
            address = public_key_to_address(public_key)
            wif = private_key_to_wif(private_key)

            # Show the entire Bitcoin address in the console
            print(f"Address: {address}")

            # Save full details to CSV
            writer.writerow([private_key.hex(), wif, public_key.hex(), address])

            count += 1
            if num_keys == -1:
                time.sleep(1)  # Delay to slow down generation for indefinite runs

# Command-line interface for the script
if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Generate Bitcoin keypairs")
    parser.add_argument('-m', '--max', type=int, default=-1, help="Number of Bitcoin keypairs to generate. Use -1 for indefinite generation.")

    args = parser.parse_args()
    generate_bitcoin_keypair(num_keys=args.max)
