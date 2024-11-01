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
OBJECTS		  = id_enclave.o
LIB_SGX_TRTS      = -lsgx_trts
LIB_SGX_TSERVICE  = -lsgx_tservice

ENCLAVE_LIBS      = $(LIB_SGX_TRTS)
ENCLAVE_LIB_PARTS = -lsgx_tstdc -lsgx_tcrypto $(LIB_SGX_TSERVICE)
ENCLAVE	          = id_enclave
PCE_ENCLAVE		  = pce
PRIVATE_KEY       = private_key.pem
PUBLIC_KEY        = public_key.pem
KEY_SIZE          = 3072
ENCLAVE_EDL       = $(ENCLAVE).edl
PCE_ENCLAVE_EDL   = pce.edl
ENCLAVE_CONFIG    = $(ENCLAVE).config.xml
OUTPUT_T          = $(ENCLAVE).so
OUTPUT_T_UNSIG    = $(ENCLAVE).unsigned.so
OUTPUT_U          = lib$(ENCLAVE)_proxy.a
LIB_DIRS          = -L ${SGX_SDK}/lib64
LD_FLAGS	  = -Wl,--no-undefined -nostdlib -nodefaultlibs -nostartfiles \
                    -Wl,--whole-archive -Wl,--start-group $(ENCLAVE_LIBS) -Wl,--end-group \
                    -Wl,--no-whole-archive -Wl,--start-group $(ENCLAVE_LIB_PARTS) -Wl,--end-group \
                    -Wl,-Bstatic -Wl,-Bsymbolic -Wl,--no-undefined \
                    -Wl,-pie,-eenclave_entry -Wl,--export-dynamic  \
                    -Wl,--defsym,__ImageBase=0
TRUSTED_OBJECTS   = $(ENCLAVE)_t.o $(PCE_ENCLAVE)_t.o
UNTRUSTED_OBJECTS = $(ENCLAVE)_u.o $(PCE_ENCLAVE)_u.o
TRUSTED_CODE      = $(ENCLAVE)_t.h $(ENCLAVE)_t.c $(PCE_ENCLAVE)_t.h $(PCE_ENCLAVE)_t.c
UNTRUSTED_CODE    = $(ENCLAVE)_u.h $(ENCLAVE)_u.c $(PCE_ENCLAVE)_u.h $(PCE_ENCLAVE)_u.c

#.SILENT:
all: $(OUTPUT_T) $(OUTPUT_U)

$(OUTPUT_T) : $(TRUSTED_OBJECTS) $(OBJECTS)
	echo "$(INDENT)[LD]  " $(OBJECTS) $(TRUSTED_OBJECTS) $(ENCLAVE_LIBS) $(ENCLAVE_LIBS_PARTS) $(OUTPUT_T_UNSIG)
	$(LD) $(OBJECTS) $(TRUSTED_OBJECTS) $(LD_FLAGS) $(LIB_DIRS) -o $(OUTPUT_T_UNSIG)

	echo "$(INDENT)[SGN]" $(OUTPUT_T_UNSIG)
	$(SIGNER) sign -key $(PRIVATE_KEY) -enclave $(OUTPUT_T_UNSIG) -out $(OUTPUT_T) -config $(ENCLAVE_CONFIG) > /dev/null 2> /dev/null

$(OUTPUT_U) : $(UNTRUSTED_OBJECTS)
	echo "$(INDENT)[AR]  " $(OUTPUT_U)
	$(AR) $(AR_FLAGS) $(OUTPUT_U) $(UNTRUSTED_OBJECTS)

%_t.o : $(subst .o,.c,$@) edger
	echo "$(INDENT)[CC] " $(subst .o,.c,$@) "(trusted edge)"
	touch $(subst .o,.c,$@)
	$(CC) -c $(INCLUDE) $(T_CFLAGS) $(subst .o,.c,$@)

%_u.o : $(subst .o,.c,$@) edger
	echo "$(INDENT)[CC] " $(subst .o,.c,$@) "(untrusted edge)"
	touch $(subst .o,.c,$@)
	$(CC) -c $(INCLUDE) $(U_CFLAGS) $(subst .o,.c,$@)

%.o : %.c edger
	echo "$(INDENT)[CC] " $< "(core)"
	$(CC) $(INCLUDE) $(T_CFLAGS) -c $<

edger: $(ENCLAVE).edl
	echo "$(INDENT)[GEN]" $(EDGER) $(ENCLAVE_EDL)
	$(EDGER) $(ENCLAVE_EDL)

pce_u_c: $(PCE_ENCLAVE_EDL)
	echo "$(INDENT)[GEN]" $(EDGER) $(PCE_ENCLAVE_EDL)
	$(EDGER) $(PCE_ENCLAVE_EDL)
pce_u_o: pce_u_c
	@echo "CC   <=  $<"
	$(CC) -c $(INCLUDE) $(U_CFLAGS) $(subst .o,.c,pce_u.c)

.PHONY: force_check
force_check:
	true

.PHONY: scrub
scrub: 
	echo "$(INDENT)[RM]  " $(PRIVATE_KEY) $(PUBLIC_KEY)
	$(RM) $(PRIVATE_KEY) $(PUBLIC_KEY)

.PHONY: configure
configure: 
	echo "$(INDENT)[GEN] $(PRIVATE_KEY) ($(KEY_SIZE) bits)"

	# generate 3072 bit private RSA key
	openssl genrsa -out $(PRIVATE_KEY) -3 $(KEY_SIZE)
	
	echo "$(INDENT)[EXT] $(PUBLIC_KEY)"
	# extract public key
	openssl rsa -in $(PRIVATE_KEY) -pubout -out $(PUBLIC_KEY) 
	
.PHONY: clean
clean:
	echo "$(INDENT)[RM]" $(OBJECTS)
	$(RM) $(OBJECTS)
	
	echo "$(INDENT)[RM]" $(OUTPUT_T_UNSIG) $(OUTPUT_T)
	$(RM) $(OUTPUT_T_UNSIG) $(OUTPUT_T)
	
	echo "$(INDENT)[RM]" $(TRUSTED_OBJECTS)
	$(RM) $(TRUSTED_OBJECTS)
	
	echo "$(INDENT)[RM]" $(TRUSTED_CODE)
	$(RM) $(TRUSTED_CODE)
	
	echo "$(INDENT)[RM]" $(UNTRUSTED_OBJECTS)
	$(RM) $(UNTRUSTED_OBJECTS)
	
	echo "$(INDENT)[RM]" $(UNTRUSTED_CODE)
	$(RM) $(UNTRUSTED_CODE)
	
	echo "$(INDENT)[RM]" $(OUTPUT_U)
	$(RM) $(OUTPUT_U)
	

