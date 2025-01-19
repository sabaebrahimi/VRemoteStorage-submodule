obj-m += server_file_module.o

BUILD_DIR := build
KERNEL_SOURCE := /home/amirmnoohi/linux-6.11.6
PWD := $(shell pwd)

default: $(BUILD_DIR)
	make -C $(KERNEL_SOURCE) M=$(PWD) modules
