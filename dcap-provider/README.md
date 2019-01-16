## Testing

To test this crate, install it as your DCAP quote provider.
Then, run the tests for the **dcap-ql** crate:

```
OCP_APIM_SUBSCRIPTION_KEY=... DCAP_QL_TEST_ATT_KEY_TYPE=pck_cert_chain cargo test -p dcap-ql
```
