# PCK ID retrieval tool

This is a retrieval tool for the SGX PCK ID that works with AESM.

## Usage

Simply run the tool with an active AESM (version 2.9.1 and higher).

It is important that AESM is not configured with a DCAP quote provider, or that
the quote provider always returns “Platform Library Unavailable.” Otherwise,
this tool might return the following error: “Certification data is already
available for the current platform.”
