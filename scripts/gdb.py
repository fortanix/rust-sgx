#!/usr/bin/env python3
#
# Copyright (c) Fortanix, Inc.
# 
# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this
# file, You can obtain one at http://mozilla.org/MPL/2.0/.
#
# Debugging aid for SGX with GDB
#
# Assumptions made:
# * given an address in an SGX enclave, the memory mapping start address is at
#   the memory mapping offset from the enclave base.
# * SSAFRAMESIZE is

import gdb
import re
from subprocess import Popen, PIPE 

TCS_OSSA = 16
TCS_CSSA = 24
TCS_OGSBASGX = 56
SSAFRAMESIZE = 1 # No clue how to get this from inferior

def read_long(inferior, address, length):
  mem = inferior.read_memory(address, length)
  ret = int(0)
  for b in reversed(bytes(mem)):
    ret *= 256
    ret += b
  return ret

def find_vma_base(addr):
  s = gdb.execute("info proc mappings", False, True)
  for l in s.split('\n'):
    # Python doesn't support repeated group captures
    m = re.match("^(?:\s*0x[0-9a-fA-F]+\s){4}", l)
    if m:
      addrs = re.findall("0x([0-9a-fA-F]+)", l)
      start = int(addrs[0], 16)
      end = int(addrs[1], 16)
      if start <= addr and addr < end:
        offset = int(addrs[3], 16)
        return start-offset
  return None

def get_text_offset(file_name):
  command=['readelf', '-SW', file_name]
  proc = Popen(command, stdout=PIPE, stderr=PIPE)
  sections, err = proc.communicate()
  if proc.returncode != 0:
      raise Exception("ELF Read Error")
  for line in sections.decode('utf-8').rstrip().split('\n'):
      if ".text" in line:
          # 1     2    3    4
          # [Nr]  Name Type Address
          m=re.match('^\s+\[\s*(\d+)\]\s+(\.text)\s+(\S+)\s+([0-9a-fA-F]+)\s', line)
          if m is not None:
              return int(m.group(4), 16)
          break

  raise Exception(".text section not found")

def sgx_load_sym_file(file_name, encl_addr):
   offset=get_text_offset(file_name)
   address=find_vma_base(encl_addr) + offset
   gdb.execute("add-symbol-file {} {}".format(file_name, address))


class SgxState (gdb.Command):
  """Set/restore register state from SGX memory"""

  state = None

  def __init__ (self):
    super (SgxState, self).__init__ ("sgxstate", gdb.COMMAND_USER)

  def invoke (self, arg, from_tty):
    args = gdb.string_to_argv(arg)
    if args[0] == 'tcs':
      tcs = int(gdb.parse_and_eval(args[1]))
      base = find_vma_base(tcs)
      inf = gdb.selected_inferior()

      cssa = read_long(inf, tcs+TCS_CSSA, 4)
      if cssa == 0:
        # This branch is specific to x86_64-fortanix-unknown-sgx
        TLS_RSP = 0x10
        TLS_PANIC_RSP = 0x18

        ogsbas = read_long(inf, tcs+TCS_OGSBASGX, 8)
        tls = base+ogsbas
        f0_rsp = read_long(inf, tls+TLS_RSP, 8)

        if f0_rsp == 0:
          f0_rsp = read_long(inf, tls+TLS_PANIC_RSP, 8)

        if f0_rsp == 0:
          raise Exception("Current stack frame not found")

        newstate = {
          'rax': 0,
          'rcx': 0,
          'rdx': 0,
          'rbx': read_long(inf, f0_rsp + 0x08, 8),
          'rsp':                f0_rsp + 0x40,
          'rbp': read_long(inf, f0_rsp + 0x10, 8),
          'rsi': 0,
          'rdi': 0,
          'r8':  0,
          'r9':  0,
          'r10': 0,
          'r11': 0,
          'r12': read_long(inf, f0_rsp + 0x18, 8),
          'r13': read_long(inf, f0_rsp + 0x20, 8),
          'r14': read_long(inf, f0_rsp + 0x28, 8),
          'r15': read_long(inf, f0_rsp + 0x30, 8),
          'eflags': 0,
          'rip': read_long(inf, f0_rsp + 0x38, 8),
        }
      else:
        ossa = read_long(inf, tcs+TCS_OSSA, 8)
        ssa = base+ossa+(cssa-1)*SSAFRAMESIZE
        newstate = {
          'rax':    read_long(inf, ssa + 0xf48, 8),
          'rcx':    read_long(inf, ssa + 0xf50, 8),
          'rdx':    read_long(inf, ssa + 0xf58, 8),
          'rbx':    read_long(inf, ssa + 0xf60, 8),
          'rsp':    read_long(inf, ssa + 0xf68, 8),
          'rbp':    read_long(inf, ssa + 0xf70, 8),
          'rsi':    read_long(inf, ssa + 0xf78, 8),
          'rdi':    read_long(inf, ssa + 0xf80, 8),
          'r8':     read_long(inf, ssa + 0xf88, 8),
          'r9':     read_long(inf, ssa + 0xf90, 8),
          'r10':    read_long(inf, ssa + 0xf98, 8),
          'r11':    read_long(inf, ssa + 0xfa0, 8),
          'r12':    read_long(inf, ssa + 0xfa8, 8),
          'r13':    read_long(inf, ssa + 0xfb0, 8),
          'r14':    read_long(inf, ssa + 0xfb8, 8),
          'r15':    read_long(inf, ssa + 0xfc0, 8),
          'eflags': read_long(inf, ssa + 0xfc8, 8),
          'rip':    read_long(inf, ssa + 0xfd0, 8),
        }

      if SgxState.state is None:
        print("Saving original register state")
        self.save_state()
      self.set_state(newstate)
    elif args[0] == 'restore':
      if not SgxState.state is None:
        self.set_state(SgxState.state)
        SgxState.state = None
      else:
        print("No state to restore")
    elif args[0] == 'auto':
      """
      This should be called after the runner signals SIGTRAP with tcs address in RBX.
      The user could optionally provide path to the executable, in which case the symbol mapping will be loaded.
      """
      tcs=int(gdb.parse_and_eval("$rbx"));
      if len(args) >= 2:
        sgx_load_sym_file(args[1], tcs)
      gdb.execute("sgxstate tcs {}".format(tcs))
    else:
      raise Exception("Invalid subcommand")

  def save_state(self):
    SgxState.state = {}
    for r in ["rax", "rcx", "rdx", "rbx", "rsp", "rbp", "rsi", "rdi", "r8", "r9", "r10", "r11", "r12", "r13", "r14", "r15", "eflags", "rip"]:
      SgxState.state[r] = int(gdb.parse_and_eval("$"+r))

  def set_state(self, registers):
    gdb.newest_frame().select()
    for r, v in registers.items():
      gdb.execute("set ${} = {}".format(r,v))

class Sgx_Add_Symbol_File (gdb.Command):
  """
  Given any address in the enclave and ELF path, load enclave's symbols.
  sgx-add-symbol-file <ADDR_IN_ENCLAVE | auto> <ELF_PATH>
  Specifying address as auto is equivalent to specifying $rbx.
  """

  def __init__ (self):
    super (Sgx_Add_Symbol_File, self).__init__ ("sgx-add-symbol-file", gdb.COMMAND_USER)

  def invoke (self, arg, from_tty):
    args = gdb.string_to_argv(arg)
    if (len(args) != 2):
      raise Exception("Incorrect number of arguments.")
    if (args[0] == 'auto'):
        encl_addr=int(gdb.parse_and_eval("$rbx"))
    else:
        encl_addr=int(gdb.parse_and_eval(args[0]))
    file_path=args[1]
    sgx_load_sym_file(file_path, encl_addr)


class SgxBase (gdb.Function):
  """Given an address, return the enclave base address.
If the address is not inside an enclave, the return value is unspecified."""

  def __init__ (self):
    super (SgxBase, self).__init__ ("sgxbase")

  def invoke (self, addr):
    return find_vma_base(int(addr))

SgxState()
Sgx_Add_Symbol_File()
SgxBase()
