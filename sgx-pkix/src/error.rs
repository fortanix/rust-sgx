/* Copyright (c) Fortanix, Inc.
 *
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/. */

quick_error!{
    #[derive(Debug)]
    pub enum Error {
        MissingCpusvn { description("missing CPUSVN") }
        MissingMiscselect { description("missing MISCSELECT") }
        MissingAttributes { description("missing ATTRIBUTES") }
        MissingMrenclave { description("missing MRENCLAVE") }
        MissingMrsigner { description("missing MRSIGNER") }
        MissingIsvprodid { description("missing ISVPRODID") }
        MissingIsvsvn { description("missing ISVSVN") }
        MissingReportdata { description("missing REPORTDATA") }
        MissingAttestation { description("missing attestation") }

        InvalidCpusvn { description("invalid CPUSVN") }
        InvalidMiscselect { description("invalid MISCSELECT") }
        InvalidAttributes { description("invalid ATTRIBUTES") }
        InvalidMrenclave { description("invalid MRENCLAVE") }
        InvalidMrsigner { description("invalid MRSIGNER") }
        InvalidIsvprodid { description("invalid ISVPRODID") }
        InvalidIsvsvn { description("invalid ISVSVN") }
        InvalidReportdata { description("invalid REPORTDATA") }
        InvalidAttestation { description("invalid attestation") }
        InvalidKeyid { description("invalid key ID") }
        InvalidMac { description("invalid MAC") }

        InvalidAsn1Type { description("invalid ASN.1 type") }
        InvalidLength { description("invalid length") }
        InvalidValue { description("invalid value") }
    }
}

pub type Result<T> = ::std::result::Result<T, Error>;
