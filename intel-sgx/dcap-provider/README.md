## Testing

To test this crate, install it as your DCAP quote provider.
Then, run the tests for the **dcap-ql** crate:

```
# Requirement: have the DCAP quote provider installed
cd ../dcap-ql
OCP_APIM_SUBSCRIPTION_KEY=... DCAP_QL_TEST_ATT_KEY_TYPE=pck_cert_chain cargo test --features test-sgx-flc
```
