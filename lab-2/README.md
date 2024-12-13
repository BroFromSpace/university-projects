# Secure File Encryption and Decryption Utilities

This project uses the following tools and libraries:

- **Package Management**: Poetry
- **Linting and Formatting**: Ruff
- **Cryptography**: Python Cryptography
- **CLI Commands**: Typer
- **Rich Formatting**: Rich

```bash
# Symmetric Encryption
docker compose run app symmetric encrypt -i lab_2/symmetric/input.txt -o lab_2/symmetric/encrypted.txt

# Symmetric Decryption
docker compose run app symmetric decrypt -i lab_2/symmetric/encrypted.txt -o lab_2/symmetric/decrypted.txt -k lab_2/symmetric/key.txt.key

# Asymmetric Key Generation
docker compose run app asymmetric generate-keys

# Asymmetric Encryption
docker compose run app asymmetric encrypt -i lab_2/asymmetric/input.txt -o lab_2/asymmetric/encrypted.txt -k lab_2/asymmetric/public.pem

# Asymmetric Decryption
docker compose run app asymmetric decrypt -i lab_2/asymmetric/encrypted.txt -o lab_2/asymmetric/decrypted.txt -k lab_2/asymmetric/private.pem

# Digital Signing
docker compose run app asymmetric sign -i lab_2/asymmetric/input.txt -k lab_2/asymmetric/private.pem -s lab_2/asymmetric/signature.txt

# Signature Verification
docker compose run app asymmetric verify -i lab_2/asymmetric/input.txt -k lab_2/asymmetric/public.pem -s lab_2/asymmetric/signature.txt
```
