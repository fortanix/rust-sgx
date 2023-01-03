# Version 0.7.4 - 2022-12-21

## New Features
- Refactored the signing APIs to permit signatures to be generated separately (for example using an HSM).
  The way to use this new functionality is to construct a Sigstruct as usual and call
  `sigstruct.unsigned_hash()` to produce the hash that must be signed externally. Once the signature is
  available, reconstruct the sigstruct and call `sigstruct.cat_sign()` with the signature to get the signed
  and populated Sigstruct.
- If you are using a custom key implementation, you will need to implement the new `SgxRsaPubOps()`
  trait for your key. This trait must provide a `calculate_q1_q2()` method that calculates the q1 and q2
  values for a given signature. The q1 and q2 calculation is the same as for the existing
  `sign_sha256_pkcs1v1_5_with_q1_q2()` method, but the `calculate_q1_q2()` method takes the signature
  as a parameter instead of creating the signature.


