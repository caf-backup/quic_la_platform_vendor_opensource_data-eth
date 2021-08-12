# SPDX-License-Identifier: GPL-2.0-only
ccflags-y := -Wno-unused-function
obj-y := data-eth.o

obj-$(CONFIG_QPS615) += drivers/qps615/src/
obj-$(CONFIG_QPS615_IOSS) += drivers/qps615_ioss/
obj-$(CONFIG_R8125) += drivers/r8125/src/
obj-$(CONFIG_IOSS) += drivers/ioss/
obj-$(CONFIG_AQFWD_IOSS)  += drivers/aqc_ioss/
