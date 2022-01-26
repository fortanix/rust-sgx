# EIF utilities

Compiles with Rust nightly.

## ftxvme-elf2eif

`ftxvme-elf2eif` converts ELF executables to AWS Nitro's EIF format.

## eif-sign

`eif-sign` signs an unsigned EIF file.

You can create a signing key and a certificate using

```bash
openssl ecparam -name secp384r1 -genkey -out signing_key.pem
openssl req -new -key signing_key.pem -sha384 -nodes -subj "/CN=fortanix" -out csr.pem
openssl x509 -req -days 365  -in csr.pem -out cert.pem -sha384 -signkey signing_key.pem
```
