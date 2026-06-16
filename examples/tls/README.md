To run this example via docker you can use the following steps.

1. Setup

You need to follow steps from 'Install SGX driver' and 'Install AESM service' from https://edp.fortanix.com/docs/installation/guide/


2. Build the target image.

```
# docker build -t sgx-tls .
```

Note: This is a multi-stage build, only the ftxsgx-runner, tls.sgxs, libssl-dev are part of final image on top of ubuntu:16.04.

3. Running the image

```
docker run --rm -p 7878:7878 -v /var/run/aesmd:/var/run/aesmd/ --device /dev/isgx -it sgx-tls
```

4. Connecting to it

```
openssl s_client -connect 127.0.0.1:7878
```

This will result in a secure connection that echoes back all text sent.