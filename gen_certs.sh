#!/bin/bash

# Check if the argument is provided
if [ -z "$1" ]; then
    echo "Usage: $0 <output_file_prefix>"
    exit 1
fi

# Generate a private key
openssl genpkey -algorithm RSA -out "$1_private_key.pem" -pkeyopt rsa_keygen_bits:2048

# Extract the public key
openssl rsa -pubout -in "$1_private_key.pem" -out "$1_public_key.pem"

echo "Public and private key pair generated:"
echo "Private key saved as: $1_private_key.pem"
echo "Public key saved as: $1_public_key.pem"