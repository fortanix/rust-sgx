This is the default directory where the Nitro blob files will be downloaded.

This crate will reuse the downloaded blobs if they are already available in this directory and their hashes are as expected.

The blob files in this directory should not be committed to git.
