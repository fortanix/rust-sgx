/*
 * Bare-bones SGX EPC driver. Exposes ENCLS pretty much directly to userspace.
 * Not intended for production use.
 *
 * (C) Copyright 2015 Jethro G. Beekman
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License
 * as published by the Free Software Foundation; version 2
 * of the License.
 */

.global encls_might_fault
.global encls_after_fault

.section .text
encls_might_fault:
    encls
encls_after_fault:
    ret
