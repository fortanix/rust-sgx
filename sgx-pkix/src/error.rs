/* Copyright (c) Fortanix, Inc.
 *
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/. */

quick_error!{
    #[derive(Debug)]
    pub enum Error {
        MissingCpusvn { display("missing CPUSVN") }
        MissingMiscselect { display("missing MISCSELECT") }
        MissingAttributes { display("missing ATTRIBUTES") }
        MissingMrenclave { display("missing MRENCLAVE") }
        MissingMrsigner { display("missing MRSIGNER") }
        MissingIsvprodid { display("missing ISVPRODID") }
        MissingIsvsvn { display("missing ISVSVN") }
        MissingReportdata { display("missing REPORTDATA") }
        MissingAttestation { display("missing attestation") }

        InvalidCpusvn { display("invalid CPUSVN") }
        InvalidMiscselect { display("invalid MISCSELECT") }
        InvalidAttributes { display("invalid ATTRIBUTES") }
        InvalidMrenclave { display("invalid MRENCLAVE") }
        InvalidMrsigner { display("invalid MRSIGNER") }
        InvalidIsvprodid { display("invalid ISVPRODID") }
        InvalidIsvsvn { display("invalid ISVSVN") }
        InvalidReportdata { display("invalid REPORTDATA") }
        InvalidAttestation { display("invalid attestation") }
        InvalidKeyid { display("invalid key ID") }
        InvalidMac { display("invalid MAC") }

        InvalidAsn1Type { display("invalid ASN.1 type") }
        InvalidLength { display("invalid length") }
        InvalidValue { display("invalid value") }
    }
}

pub type Result<T> = ::std::result::Result<T, Error>;
