obj-$(CONFIG_INTEL_SGX) += intel_sgx.o

intel_sgx-$(CONFIG_INTEL_SGX) += \
	isgx_ioctl.o \
	isgx_main.o \
	isgx_page_cache.o \
	isgx_util.o \
	isgx_vma.o

ifdef CONFIG_COMPAT
intel_sgx-$(CONFIG_INTEL_SGX) += isgx_compat_ioctl.o
endif
