#!/bin/bash

# Create a persistent keyring 
keyring_id=$(keyctl create persistent "persistent_keyring" @u)

# Add a secret key with description "aes_key" and payload as the AES key
keyctl add secret "aes_key" "my_secret_aes_key" $keyring_id

# Verify that the key has been added by listing keys in the persistent keyring
echo "Keys in the persistent keyring:"
keyctl list $keyring_id

# Retrieve the secret AES key to confirm the payload contains your data
# Retrieve the key using the description "aes_key" and key type "secret"
key_id=$(keyctl search @u "aes_key" "secret")
echo "Retrieved AES key payload:"
keyctl read $key_id
