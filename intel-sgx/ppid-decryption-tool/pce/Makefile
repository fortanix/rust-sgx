# Copyright (c) Fortanix, Inc.
#
# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this
# file, You can obtain one at http://mozilla.org/MPL/2.0/.

CC		  = gcc
AR		  = ar
LD		  = gcc
EDGER		  = sgx_edger8r
SIGNER		  = sgx_sign
INCLUDE           = -I${SGX_SDK}/include                               \
		    		-I${SGX_SDK}/include/tlibc
T_CFLAGS	  = $(CFLAGS) -nostdinc -fvisibility=hidden -fpie -fstack-protector -g
U_CFLAGS	  = $(CFLAGS) -nostdinc -fvisibility=hidden -fpie -fstack-protector -g
AR_FLAGS	  = rcs
OBJECTS		  = pce_u.c pce_u.h pce_u.o
LIB_SGX_TRTS      = -lsgx_trts
LIB_SGX_TSERVICE  = -lsgx_tservice

ENCLAVE_LIBS      = $(LIB_SGX_TRTS)
ENCLAVE_LIB_PARTS = -lsgx_tstdc -lsgx_tcrypto $(LIB_SGX_TSERVICE)
ENCLAVE	          = pce
ENCLAVE_EDL       = $(ENCLAVE).edl
OUTPUT_U          = $(ENCLAVE)_u.o

#.SILENT:
all: $(OUTPUT_U)

%_u.o : $(subst .o,.c,$@) edger
	echo "$(INDENT)[CC] " $(subst .o,.c,$@) "(untrusted edge)"
	touch $(subst .o,.c,$@)
	$(CC) -c $(INCLUDE) $(U_CFLAGS) $(subst .o,.c,$@)

%.o : %.c edger
	echo "$(INDENT)[CC] " $< "(core)"
	$(CC) $(INCLUDE) $(T_CFLAGS) -c $<

edger: $(ENCLAVE).edl
	echo "$(INDENT)[GEN]" $(EDGER) $(ENCLAVE_EDL)
	$(EDGER) --untrusted $(ENCLAVE_EDL)

.PHONY: force_check
force_check:
	true

.PHONY: clean
clean:
	echo "$(INDENT)[RM]" $(OBJECTS)
	$(RM) $(OBJECTS)
