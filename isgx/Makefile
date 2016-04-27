obj-m += intel_sgx.o

intel_sgx-objs += \
	isgx_ioctl.o \
	isgx_main.o \
	isgx_page_cache.o \
	isgx_util.o \
	isgx_vma.o

ifdef CONFIG_COMPAT
intel_sgx-objs += isgx_compat_ioctl.o
endif
