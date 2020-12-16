# SPDX-License-Identifier: GPL-2.0-only
ccflags-y := -Wno-unused-function
obj-y := data-eth.o

obj-$(CONFIG_R8125) += drivers/r8125/src/
