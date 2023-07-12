/* Copyright (c) Fortanix, Inc.
 *
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/. */

use pkix::types::ObjectIdentifier;

lazy_static! {
    /// This OID identifies an extension containing a Nitro attestation report.
    /// Note that all OIDs beginning with 1.3.6.1.4.1.49690 are registered to Fortanix.
    pub static ref ATTESTATION_NITRO: ObjectIdentifier = vec![1, 3, 6, 1, 4, 1, 49690, 2, 2, 6].into();
    /// This OID identifies an extension containing the PCR0 of a Nitro enclave;
    /// used to insecurely provide identification to debug attestations that
    /// otherwise contain all zeroes in their PCR0 measurement.
    pub static ref ATTESTATION_NITRO_PCR0: ObjectIdentifier = vec![1, 3, 6, 1, 4, 1, 49690, 2, 2, 6, 1].into();
}
