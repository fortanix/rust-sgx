/* Copyright (c) Fortanix, Inc.
 *
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/. */

#![allow(non_upper_case_globals)]

use pkix::types::ObjectIdentifier;

lazy_static!{
    pub static ref ATTESTATION_NITRO: ObjectIdentifier = vec![1, 3, 6, 1, 4, 1, 49690, 2, 2, 6].into();
}