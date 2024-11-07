# PPID Decryption Tool

This tool provides functionality to decrypt the **Platform Provisioning ID (PPID)** from the **Provisioning Certification Enclave (PCE)**.

## Overview

The tool is inspired by Intel's **PCKRetrievalTool**, which is used to retrieve platform-specific information from the PCE. However, Intel’s tool returns only an **encrypted version of the PPID**. This utility extends the functionality by enabling decryption of the PPID, allowing access to the data in an unencrypted form.

## How It Works

The solution involves creating two custom functions:

1. **RSA Key-Pair Generation**: Generates an RSA key-pair from predefined parameters under our control.
2. **PPID Decryption**: Decrypts the encrypted PPID obtained from the PCE.

By leveraging the generated RSA key-pair, the tool decrypts the PPID as it is returned from the PCE, making it accessible in plaintext form.

## Usage

To use this tool:

1. Ensure your environment is set up to communicate with the PCE.
2. Run the tool with the appropriate permissions and parameters as described below to retrieve and decrypt the PPID.

## Project Modules

### 1. PPID Enclave
The PPID Enclave module contains:
- **RSA Key-Pair Generation**: Creates a pair of RSA keys for the PCE enclave.
- **PPID Decryption**: Uses the RSA keys to decrypt the PPID retrieved from the PCE.

Both functionalities are encapsulated within the PPID enclave to prevent adversaries from accessing the RSA parameters or the private key used for PPID decryption.

### 2. PCE Enclave
This module handles the **encrypted PPID retrieval**. It contains:
- A function to return the PPID in encrypted form.

The compiled C code for this enclave is provided by Intel as a prebuilt `.so` file. To integrate this with our tool, we supply an enclave definition file (`.edl`) and generate a C wrapper using the **sgx_edger8r** tool.

### 3. Main Program (`main.c`)
- The main program serves as the **entry point** of the tool, located at the root of the project.
- It connects the ID and PCE enclaves and prints the decrypted PPID to the console.

## How It Works

The tool’s decryption process involves the following steps:
1. The PPID enclave generates an RSA key-pair based on controlled parameters.
2. The tool retrieves the encrypted PPID from the PCE enclave.
3. The PPID enclave then decrypts this PPID and outputs it in plaintext form.

## Usage

To use this tool:

1. Set up the environment to allow communication with the PCE.
2. Run the tool with appropriate permissions to retrieve and decrypt the PPID.

## Additional Information

More information about the PPID, PCE, and the broader DCAP attestation process can be found [here](https://docs.enclaive.cloud/confidential-cloud/technology-in-depth/intel-sgx/technology/concepts/dcap-attestation-framework).

For details on Intel's PCKRetrievalTool, visit the [PCKRetrievalTool GitHub repository](https://github.com/intel/SGXDataCenterAttestationPrimitives/tree/main/tools/PCKRetrievalTool).
