# Copyright (c) Fortanix, Inc.
#
# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this
# file, You can obtain one at http://mozilla.org/MPL/2.0/.

CC                   = gcc
AS                   = gcc
AR                   = ar
LD                   = gcc
CFLAGS              += -g
ARFLAGS              = -rcs
INCLUDE              = -I ${SGX_SDK}/include
OBJECTS              = main.o
SUBDIRS              = Enclave pce
LIB_SGX_URTS         = -lsgx_urts
LIBS                 = -lppid_proxy $(LIB_SGX_URTS) -lpthread pce/pce_u.o
LIB_DIRS             = $(SUBDIRS:%=-L %)                                            \
			$(patsubst %,-L%,$(subst :, ,$(SGX_LIBS)))
BUILDDIRS            = $(SUBDIRS:%=build-%)
CLEANDIRS            = $(SUBDIRS:%=clean-%)
SCRUBDIRS            = $(SUBDIRS:%=scrub-%)
CONFIGDIRS           = $(SUBDIRS:%=config-%)
INSTALLDIRS          = $(SUBDIRS:%=install-%)
UNINSTALLDIRS        = $(SUBDIRS:%=uninstall-%)
OUTPUT               = ppid_retrieval

.SILENT:
all:	$(OUTPUT)
	
$(OUTPUT): $(BUILDDIRS) $(OBJECTS)
	#echo "[   building   ]"
	echo "$(INDENT)[LD]" $(OBJECTS) $(LIBS) -o $(OUTPUT) 
	$(LD) $(OBJECTS) $(LIB_DIRS) $(LIBS) -o $(OUTPUT) 
	
%.o : %.c
	echo "$(INDENT)[CC]" $<
	$(CC) $(CFLAGS) $(INCLUDE) -c $<

.PHONY: scrub
scrub:  $(SCRUBDIRS)
	#echo "[   scrubbing   ]"

.PHONY: configure
configure: $(CONFIGDIRS)
	#echo "[   configuring   ]"
	
.PHONY: install
install:  $(INSTALLDIRS)
	#echo "[   installing   ]"

.PHONY: uninstall
uninstall: $(UNINSTALLDIRS)
	#echo "[   uninstalling   ]"

.PHONY: clean
clean: $(CLEANDIRS)
	#echo "[   cleaning   ]"
	echo "$(INDENT)[RM]" $(OBJECTS) $(OUTPUT)
	rm -f $(OBJECTS)
	rm -f $(OUTPUT)
	
$(BUILDDIRS): force_check
	echo "$(INDENT)[===] $(@:build-%=%) [===]"
	$(MAKE) -C $(@:build-%=%) INDENT+="$(INDENT_STEP)" curr-dir=$(curr-dir)/$(@:build-%=%)

$(CLEANDIRS): force_check
	echo "$(INDENT)[===] $(@:clean-%=%) [===]"
	$(MAKE) clean -C $(@:clean-%=%) INDENT+="$(INDENT_STEP)" curr-dir=$(curr-dir)/$(@:build-%=%)

$(SCRUBDIRS): force_check
	echo "$(INDENT)[===] $(@:scrub-%=%) [===]"
	$(MAKE) scrub -C $(@:scrub-%=%) INDENT+="$(INDENT_STEP)" curr-dir=$(curr-dir)/$(@:build-%=%)

$(CONFIGDIRS): force_check
	echo "$(INDENT)[===] $(@:config-%=%) [===]"
	$(MAKE) configure -C $(@:config-%=%) INDENT+="$(INDENT_STEP)" curr-dir=$(curr-dir)/$(@:build-%=%)

$(INSTALLDIRS): force_check
	echo "$(INDENT)[===] $(@:install-%=%) [===]"
	$(MAKE) install -C $(@:install-%=%) INDENT+="$(INDENT_STEP)" curr-dir=$(curr-dir)/$(@:build-%=%)

$(UNINSTALLDIRS): force_check
	echo "$(INDENT)[===] $(@:uninstall-%=%) [===]"
	$(MAKE) uninstall -C $(@:uninstall-%=%) INDENT+="$(INDENT_STEP)" curr-dir=$(curr-dir)/$(@:build-%=%)

force_check:
	true
