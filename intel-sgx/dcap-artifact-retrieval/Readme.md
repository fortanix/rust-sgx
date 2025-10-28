# Description
This Rust program is a command-line tool for retrieving and storing Data Center Attestation Primitives (DCAP) artifacts (to know more about DCAP you can see [presentation](#) and its [recording](#)) for attestation purposes, either from Intel or Azure.

## CLI API

### Console arguments

| Argument      | Description                                                               | Required | Notes               |
|---------------|---------------------------------------------------------------------------|----------|---------------------|
| --origin      | Specifies the source of the artifacts (intel or azure). Default is intel. | No       |                     |
| --pckid-file  | Path to the file describing the PCK identity.                             | Yes      |                     |
| --output-dir  | Directory where the fetched artifacts will be stored.                     | Yes      |                     |
| --api-key     | API key for authenticating with Intel provisioning service.               | No       |                     |
| --verbose     | Flag to enable verbose output for debugging and information.              | No       |                     |

## File Input
Format of the input provided by the user to run the program.

### PckID
Describes a CSV file containing a list of Platform Certification Key (PCK) Identities used in the context of DCAP (Data Center Attestation Primitives) attestation. The format of each identity is the following:

| Field name | Description                                     | Type            |
|------------|-------------------------------------------------|-----------------|
| enc_ppid   | Represents the encrypted Platform Provisioning ID (PPID) | Array of bytes  |
| pce_id     | Represents the Platform Configuration Enclave ID (PCE ID). | Integer         |
| cpu_svn    | Represents the CPU Security Version Number (SVN) | Array of bytes  |
| pce_isvsvn | Represents the PCE ISV Security Version Number (ISVSVN) | Integer         |
| qe_id      | Represents the Quoting Enclave ID (QE ID).       | Array of bytes  |

#### Example file:
```csv
enc_ppid,pce_id,cpu_svn,pce_isvsvn,qe_id
5133c5451dff82456e83fd5f8b4402304bf7b8edf5ea93e23e33,0000,08080e0dffff01000000000000000000,0d00,4041a3c4d3af9f15e68513108e773a7f
```
## File output
The following artifacts are written to the file specified by `--output-dir` argument one by one:

### PckCert or Platform Certification Keys Certificates (PCK Certs)
This certificate is used in Intel's Software Guard Extensions (SGX) technology to authenticate and ensure the integrity of a platform's enclave.

It has the following format:

| Field name | Description                             | Type             |
|------------|-----------------------------------------|------------------|
| cert       | The actual certificate string           | String           |
| ca_chain   | Represents the Platform Configuration Enclave ID (PCE ID). | Vector of Strings |

#### Example output:
```json
{
    "cert": "-----BEGIN CERTIFICATE-----\nMIIEjjCCBDSgAwIBAgIVAKiHtqpAgwVmQnvUbNnRRzB\n-----END CERTIFICATE-----\n",
    "ca_chain": [
        "-----BEGIN CERTIFICATE-----\nMIICizCCAjKgAwIBAgIUfjiC1ftVKU==\n-----END CERTIFICATE-----\n",
        "-----BEGIN CERTIFICATE-----\nMIICjzCCAjSgAwIBAgIUImUM1lqdNInzg=\n-----END CERTIFICATE-----\n"
    ]
}
```
## TcbInfo
This struct is related to managing and handling Trust Center Base (TCB) information in a security context. It has the following format:

| Field name   | Description                                              | Type              |
|--------------|----------------------------------------------------------|-------------------|
| raw_tcb_info | Contains raw TCB information in a string format          | String            |
| signature    | Contains the digital signature of the TCB information    | Vector of bytes   |
| ca_chain     | Holds a chain of certificate authority (CA) certificates. The CA chain is used to validate the trustworthiness of the raw_tcb_info and its signature by providing a path to a trusted root CA. | Vector of strings |

### Example output:
```json
{
    "raw_tcb_info": "{\"id\":\"SGX\",\"version\":3,\"issueDate\":\"2024-06-28T17:01:07Z\",\"nextUpdate\":\"2024-07-28T17:01:07Z\",\"fmspc\":\"00906ea10000\",\"pceId\":\"0000\",\"tcbType\":0,\"tcbEvaluationDataNumber\":16,\"tcbLevels\":[{\"tcb\":{\"sgxtcbcomponents\":[{\"svn\":20},{\"svn\":20},{\"svn\":2},{\"svn\":4},{\"svn\":1},{\"svn\":128},{\"svn\":0}],\"pcesvn\":13},\"tcbDate\":\"2023-08-09T00:00:00Z\",\"tcbStatus\":\"SWHardeningNeeded\",\"advisoryIDs\":[\"INTEL-SA-00334\",\"INTEL-SA-00615\"]}]}",
    "signature": [
        253,
        22,
        179,
        179,
        217,
        164,
        44,
        4
    ],
    "ca_chain": [
        "-----BEGIN CERTIFICATE-----\nMIICizCCAjKgAwIBAgIUfjiC1ftVKU==\n-----END CERTIFICATE-----\n",
        "-----BEGIN CERTIFICATE-----\nMIICjzCCAjSgAwIBAgIUImUM1lqdNInzg=\n-----END CERTIFICATE-----\n"
    ]
}
```
# PckCrl

Represents a Certificate Revocation List (CRL) for Platform Certification Keys (PCK), along with the associated certification authority (CA) chain. CRLs are used in certificate management to list certificates that have been revoked and should no longer be trusted. It has the following format:

## Table Format

| **Field**   | **Description**                                                                                      | **Type**          |
|-------------|------------------------------------------------------------------------------------------------------|-------------------|
| `crl`       | Contains the CRL data as a string. The CRL is a list of revoked certificates.                        | String            |
| `ca_chain`  | Contains the chain of CA certificates as a vector of strings. Each string represents a CA certificate, and the chain is used to validate the CRL itself. | Vector of String  |

## Example Output

```json
{
    "crl": "-----BEGIN X509 CRL-----\nMIIBKjCB0QIBATAdIwQY\nMBaAFNDoqtp11/kuSRebkoJH+OPq5WbSEO3PJ7y\n8zkHsHTgNjst7rhFDA8=\n-----END X509 CRL-----\n",
    "ca_chain": [
        "-----BEGIN CERTIFICATE-----\nMIICmDCCAj6gAwIBAgIVANDoqtp11/kBLQq5s5A70pdoiaRJ8z/0uDz4NgV91k=\n-----END CERTIFICATE-----\n",
        "-----BEGIN CERTIFICATE-----\nMIICjzCCAjSgAwIBAgIUImUM1lqdNInzg7SVUr9QX6O9QWxHRAvZUGOdRQ7cvqRXaqI=\n-----END CERTIFICATE-----\n"
    ]
}
```
# QeIdentitySigned

This struct is a part of the system dealing with the verification and management of Quoting Enclave (QE) identities. It has the following format:

## Fields

| **Field**               | **Description**                                                                                                                                                              | **Type**          |
|-------------------------|------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|-------------------|
| `raw_enclave_identity`  | Contains the raw data representing the enclave identity.                                                                                                                   | String            |
| `signature`             | Holds the digital signature associated with the `raw_enclave_identity`. The signature is used to verify the authenticity and integrity of the `raw_enclave_identity`. | Vector of String  |
| `ca_chain`              | Contains a chain of certificate authority (CA) certificates in the form of strings. Each string represents a CA certificate, and the chain is used to validate the digital signature and the `raw_enclave_identity` by providing a trust path to a trusted root CA. | Vector of String  |

## Example Output

```json
{
    "raw_enclave_identity": "{\"id\":\"QE\",\"version\":2,\"issueDate\":\"2024-06-28T16:42:00Z\",\"nextUpdate\":\"2024-07-28T16:42:00Z\",\"tcbEvaluationDataNumber\":16,\"miscselect\":\"00000000\",\"miscselectMask\":\"FFFFFFFF\",\"attributes\":\"11000000000000000000000000000000\",\"attributesMask\":\"FBFFFFFFFFFFFFFF0000000000000000\",\"mrsigner\":\"8C4F5775D796503E96137F77C68A829A0056AC8DED70140B081B094490C57BFF\",\"isvprodid\":1,\"tcbLevels\":[{\"tcb\":{\"isvsvn\":8},\"tcbDate\":\"2023-08-09T00:00:00Z\",\"tcbStatus\":\"UpToDate\"},{\"tcb\":{\"isvsvn\":6},\"tcbDate\":\"2021-11-10T00:00:00Z\",\"tcbStatus\":\"OutOfDate\",\"advisoryIDs\":[\"INTEL-SA-00615\"]},{\"tcb\":{\"isvsvn\":5},\"tcbDate\":\"2020-11-11T00:00:00Z\",\"tcbStatus\":\"OutOfDate\",\"advisoryIDs\":[\"INTEL-SA-00477\",\"INTEL-SA-00615\"]},{\"tcb\":{\"isvsvn\":4},\"tcbDate\":\"2019-11-13T00:00:00Z\",\"tcbStatus\":\"OutOfDate\",\"advisoryIDs\":[\"INTEL-SA-00334\",\"INTEL-SA-00477\",\"INTEL-SA-00615\"]},{\"tcb\":{\"isvsvn\":2},\"tcbDate\":\"2019-05-15T00:00:00Z\",\"tcbStatus\":\"OutOfDate\",\"advisoryIDs\":[\"INTEL-SA-00219\",\"INTEL-SA-00293\",\"INTEL-SA-00334\",\"INTEL-SA-00477\",\"INTEL-SA-00615\"]},{\"tcb\":{\"isvsvn\":1},\"tcbDate\":\"2018-08-15T00:00:00Z\",\"tcbStatus\":\"OutOfDate\",\"advisoryIDs\":[\"INTEL-SA-00202\",\"INTEL-SA-00219\",\"INTEL-SA-00293\",\"INTEL-SA-00334\",\"INTEL-SA-00477\",\"INTEL-SA-00615\"]}]}",
    "signature": [       
        99,
        75,
        157,
        16,
        107,
        78,
        218,
        178,
        245,
        0,
        4,
        50,
        83,
        75,
        17,
        33,
        204
    ],
    "ca_chain": [
        "-----BEGIN CERTIFICATE-----\nMIICizCCAjKgAwIBAgIUU2FudGEgQ2xhcmExCzP+mAh91PEyV7Jh6FGJd5ndE9aBH7RK\nQEmORYQD6RSRvfRVMA4GA1UdDwEB/wQEAwIGwDAMBgNVHRMBAf8EAjAAMAoGCCqG\nSM49BAMCA0cAMEQCIB9C8wOAN/ImxDtGACV246KcqjagZOR0kyctyBrsGGJVAiAj\nftbrNGsGU8YH211dRiYNoPPu19Zp/ze8JmhujB0oBw==\n-----END CERTIFICATE-----\n",
        "-----BEGIN CERTIFICATE-----\nMIICjzCCAjSgAwIBmF0\naW9TELMAHQ4EFgQUImUM1lqdNInzg7SV\nUr9QGzknBqwwDgYDVR0PAQH/BAQDAgEGMBIGA1UdEwEB/wQIMAYBAf8CAQEwCgYI\nKoZIzj0EAwIDSQAwRgIhAOW/5QkR+S9CiSDcNoowLuPRLsWGf/Yi7GSX94BgwTwg\nAiEA4J0lrHoMs+Xo5o/sX6O9QWxHRAvZUGOdRQ7cvqRXaqI=\n-----END CERTIFICATE-----\n"
    ]
}
```
# Console Output

The following output is provided to the user if specific flags are applied when running the program.

## Artifact Information (When verbose is enabled)

For each artifact associated with a PckID entry, the output includes the following information:

| **Field Name** | **Description**                                  | **Type** |
|----------------|--------------------------------------------------|----------|
| `pck certs`    | The path to the stored PCK certificates file.    | String   |
| `tcb info`     | The path to the stored TCB info file.            | String   |

### Example Output

```plaintext
PckID: def456
------------------------
pck certs: /path/to/pck_certificates/def456_cert.pem
tcb info: /path/to/tcb_info/def456_tcb.json
```
## Generic Artifact Information (When verbose is enabled)

After iterating over all PckID entries, the output includes information about generic artifacts:

| **Field Name** | **Description**                     | **Type** |
|----------------|-------------------------------------|----------|
| `pck crl`      | The path to the stored PCK CRL file. | String   |
| `qe identity`  | The path to the stored QE identity file. | String   |

### Example Output

```plaintext
PckID: def456
------------------------
pck crl: /path/to/pck_crl/crl.pem
qe identity: /path/to/qe_identity/identity.json

