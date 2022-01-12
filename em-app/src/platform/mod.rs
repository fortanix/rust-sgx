/* Copyright (c) Fortanix, Inc.
 *
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/. */

#[cfg(target_env = "sgx")]
pub(crate) mod sgx;

#[cfg(target_env = "sgx")]
pub(crate) use sgx::get_remote_attestation_parameters;

#[cfg(all(target_arch="x86_64",
          target_vendor="unknown",
          target_os="linux",
          any(target_env="gnu",
              target_env="musl",
              target_env = "fortanixvme")))]
pub(crate) mod nitro;

#[cfg(all(target_arch="x86_64",
          target_vendor="unknown",
          target_os="linux",
          any(target_env="gnu",
              target_env="musl",
              target_env = "fortanixvme")))]
pub(crate) use nitro::get_remote_attestation_parameters;
