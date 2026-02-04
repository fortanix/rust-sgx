/* Copyright (c) Fortanix, Inc.
 *
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/. */

use anyhow::Error;

type CommandFn = Box<dyn FnOnce() -> Result<(), Error>>;

pub struct Command {
    f: CommandFn
}

impl From<CommandFn> for Command {
    fn from(f: CommandFn) -> Self {
        Command {
            f
        }
    }
}

impl Command {
    pub fn run(self) -> Result<(), Error> {
        (self.f)()
    }
}
