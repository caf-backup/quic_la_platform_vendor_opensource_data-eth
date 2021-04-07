/* SPDX-License-Identifier: GPL-2.0-only
 * Copyright (c) 2021, The Linux Foundation. All rights reserved.
 */

#ifndef _IOSS_H_
#define _IOSS_H_

#include <linux/list.h>
#include <linux/bitops.h>
#include <linux/ipc_logging.h>
#include <linux/scatterlist.h>

#include <linux/device.h>
#include <linux/netdevice.h>

#include <linux/pci.h>
#include <linux/pm_wakeup.h>
#include <linux/refcount.h>

/**
 * API Version    Changes
 * ---------------------------------------------------------------------------
 *           1    - Initial version
 */

#define IOSS_API_VER 1
#define IOSS_SUBSYS "ioss"

/**
 * enum ioss_device_events - Events supported by a device
 * @IOSS_DEV_EV_MSI_BIT: MSI interrupt
 * @IOSS_DEV_EV_PTR_BIT: Ring pointer write-back
 */
enum ioss_device_events {
	IOSS_DEV_EV_MSI_BIT,
	IOSS_DEV_EV_PTR_BIT,
};

#define IOSS_DEV_EV(ev) BIT(IOSS_DEV_EV_##ev##_BIT)

enum ioss_device_event {
	IOSS_DEV_EV_MSI = IOSS_DEV_EV(MSI),
	IOSS_DEV_EV_PTR = IOSS_DEV_EV(PTR),
};

/**
 * enum ioss_channel_dir - Direction of a ring / channel
 * @IOSS_CH_DIR_RX: Traffic flowing from device to IPA
 * @IOSS_CH_DIR_TX: Traffic flowing from IPA to device
 */
enum ioss_channel_dir {
	IOSS_CH_DIR_RX,
	IOSS_CH_DIR_TX,
};

/**
 * enum ioss_offload_state - Offload state of a device
 * @IOSS_OF_ST_DEINITED: No offload path resources are allocated
 * @IOSS_OF_ST_INITED: Offload path resources are allocated, but not started
 * @IOSS_OF_ST_STARTED: Offload path is started and ready to handle traffic
 * @IOSS_OF_ST_ERROR: One or more offload path components are in error state
 * @IOSS_OF_ST_RECOVERY: Offload path is attempting to recover from error
 */
enum ioss_interface_state_t {
	IOSS_IF_ST_OFFLINE,
	IOSS_IF_ST_ONLINE,
	IOSS_IF_ST_ERROR,
	IOSS_IF_ST_RECOVERY,
	IOSS_OF_ST_MAX,
};

/* Rx filter types */
enum {
	IOSS_RXF_BE, /* Best effort */
	IOSS_RXF_IP, /* IP traffic */
};

enum ioss_filter_types {
	IOSS_RXF_F_BE = BIT(IOSS_RXF_BE),
	IOSS_RXF_F_IP = BIT(IOSS_RXF_IP),
};

extern struct bus_type ioss_bus;
extern struct device_type ioss_pci_dev;
extern struct device_type ioss_net_dev;

/* IOSS platform node */
struct ioss {
	struct workqueue_struct *wq;
	struct platform_device *pdev;

	struct notifier_block pci_bus_nb;

	void *ioss_priv;

	unsigned long status;
};

struct ioss_driver;

struct ioss_device {
	struct ioss *root;
	struct device dev;
	struct net_device *net_dev; /* Real net dev */

	struct list_head interfaces;
	struct mutex pm_lock;
	refcount_t pm_refcnt;
	const struct dev_pm_ops *pm_ops_real;
	void *private;
};

#define to_ioss_device(device) \
	container_of(device, struct ioss_device, dev)

#define ioss_to_real_dev(idev) (idev->dev.parent)

struct ioss_interface {
	struct list_head node;

	const char *name;
	struct ioss_device *idev;
	struct net_device *net_dev;
	unsigned long state;

	u32 instance_id;

	struct notifier_block net_dev_nb;
	struct work_struct refresh;
	struct wakeup_source *refresh_ws;
	struct list_head channels;

	bool present;
	bool registered;
	void *ioss_priv;
};

#define ioss_iface_dev(iface) (iface->idev)

#define ioss_for_each_iface(_iface, idev) \
	list_for_each_entry(_iface, &idev->interfaces, node)

#define ioss_nb_to_iface(nb) \
	container_of(nb, struct ioss_interface, net_dev_nb)

#define refresh_work_to_ioss_if(work) \
	container_of(work, struct ioss_interface, refresh)

struct ioss_mem {
	void *addr;
	size_t size;

	dma_addr_t daddr;

	/* IOSS internal */
	struct list_head node;
	struct sg_table sgt;
};

struct ioss_mem_allocator {
	const char *name;

	void * (*alloc)(struct ioss_device *idev,
			size_t size, dma_addr_t *daddr,
			gfp_t gfp, struct ioss_mem_allocator *alctr);

	void (*free)(struct ioss_device *idev,
			size_t size, void *addr, dma_addr_t daddr,
			struct ioss_mem_allocator *alctr);

	phys_addr_t (*pa)(struct ioss_device *idev,
			void *addr, dma_addr_t daddr,
			struct ioss_mem_allocator *alctr);

	/* IOSS internal */
	struct ioss *iroot;
	void *ioss_priv;
};

struct ioss_channel_config {
	u32 ring_size;
	u32 buff_size;

	struct ioss_mem_allocator *desc_alctr;
	struct ioss_mem_allocator *buff_alctr;
};

enum ioss_channel_event_type {
	IOSS_CH_EV_MSI,
	IOSS_CH_EV_PTR,
};

struct ioss_channel;

struct ioss_channel_event {
	struct ioss_channel *channel;

	enum ioss_channel_event_type type;
	phys_addr_t paddr;
	dma_addr_t daddr;
	u64 data;

	u32 mod_count_min;
	u32 mod_count_max;
	u32 mod_usecs_min;
	u32 mod_usecs_max;

	void *private;

	/* IOSS managed */
	bool allocated;
	bool enabled;
};

struct ioss_channel {
	struct list_head node;

	struct ioss_interface *iface;

	struct ioss_channel_config config;
	enum ioss_channel_dir direction;
	enum ioss_filter_types filter_types;

	struct ioss_channel_event event;

	int id;

	struct list_head desc_mem;
	struct list_head buff_mem;

	void *private;

	bool allocated;
	bool enabled;

	void *ioss_priv;
};

#define ioss_ch_dev(ch) (ch->iface->idev)

#define ioss_for_each_channel(ch, iface) \
	list_for_each_entry(ch, &iface->channels, node)

static inline int ioss_channel_add_mem(
			struct ioss_channel *ch,
			struct list_head *list,
			void *addr, dma_addr_t daddr, size_t size)
{
	struct device *real_dev = ioss_to_real_dev(ioss_ch_dev(ch));
	struct ioss_mem *imem = kzalloc(sizeof(*imem), GFP_KERNEL);

	if (!imem)
		return -ENOMEM;

	imem->addr = addr;
	imem->daddr = daddr;
	imem->size = size;

	if (dma_get_sgtable(real_dev, &imem->sgt, addr, daddr, size)) {
		kfree(imem);
		return -EFAULT;
	}

	list_add_tail(&imem->node, list);

	return 0;
}

static inline void ioss_channel_del_mem(
			struct ioss_channel *ch,
			struct list_head *list, void *addr)
{
	struct ioss_mem *imem, *tmp;

	list_for_each_entry_safe(imem, tmp, list, node) {
		if (imem->addr == addr) {
			list_del(&imem->node);
			sg_free_table(&imem->sgt);
			kfree(imem);
		}
	}
}

#define ioss_channel_add_desc_mem(ch, addr, daddr, size) \
	ioss_channel_add_mem(ch, &ch->desc_mem, addr, daddr, size)

#define ioss_channel_del_desc_mem(ch, addr) \
	ioss_channel_del_mem(ch, &ch->desc_mem, addr)

#define ioss_channel_add_buff_mem(ch, addr, daddr, size) \
	ioss_channel_add_mem(ch, &ch->buff_mem, addr, daddr, size)

#define ioss_channel_del_buff_mem(ch, addr) \
	ioss_channel_del_mem(ch, &ch->buff_mem, addr)

struct ioss_driver {
	struct list_head node;

	/* Fields to be filled by network driver */
	const char *name;
	bool (*match)(struct device *dev);

	struct ioss_driver_ops *ops;
	enum ioss_filter_types filter_types;

	/* IOSS managed */
	struct device_driver drv;
};

#define to_ioss_driver(driver) \
	container_of(driver, struct ioss_driver, drv)

struct ioss_driver_ops {
	int (*open_device)(struct ioss_device *idev);
	int (*close_device)(struct ioss_device *idev);

	int (*request_channel)(struct ioss_channel *ch);
	int (*release_channel)(struct ioss_channel *ch);

	int (*enable_channel)(struct ioss_channel *ch);
	int (*disable_channel)(struct ioss_channel *ch);

	int (*request_event)(struct ioss_channel *ch);
	int (*release_event)(struct ioss_channel *ch);

	int (*enable_event)(struct ioss_channel *ch);
	int (*disable_event)(struct ioss_channel *ch);
};

#define ioss_dev_op(idev, op, args...) \
	({ \
		struct ioss_driver *idrv = to_ioss_driver(idev->dev.driver); \
		(idrv && idrv->ops->op) ? idrv->ops->op(args) : -ENOENT; \
	}) \

int __ioss_pci_register_driver(struct ioss_driver *drv, struct module *owner);

#define ioss_pci_register_driver(driver) \
	__ioss_pci_register_driver(driver, THIS_MODULE)

void ioss_pci_unregister_driver(struct ioss_driver *drv);

#define __ioss_log_msg(ipcbuf, fmt, args...) \
	do { \
		void *__buf = (ipcbuf); \
		if (__buf) \
			ipc_log_string(__buf, " %s:%d " fmt "\n", \
					__func__, __LINE__, ## args); \
	} while (0)

#define ioss_log_err(dev, fmt, args...) \
	do { \
		void *ioss_get_ipclog_buf_prio(void); \
		void *ioss_get_ipclog_buf_norm(void); \
		dev_err(dev, IOSS_SUBSYS ":ERR:" fmt "\n", ##args); \
		__ioss_log_msg(ioss_get_ipclog_buf_prio(), \
					"ERR:" fmt, ## args); \
		__ioss_log_msg(ioss_get_ipclog_buf_norm(), \
					"ERR:" fmt, ## args); \
	} while (0)

#define ioss_log_bug(dev, fmt, args...) \
	do { \
		ioss_log_err(dev, "BUG:" fmt, ##args); \
		dump_stack(); \
	} while (0)

#define ioss_log_cfg(dev, fmt, args...) \
	do { \
		void *ioss_get_ipclog_buf_prio(void); \
		void *ioss_get_ipclog_buf_norm(void); \
		dev_info(dev, IOSS_SUBSYS ":cfg:" fmt "\n", ##args); \
		__ioss_log_msg(ioss_get_ipclog_buf_prio(), \
					"cfg:" fmt, ## args); \
		__ioss_log_msg(ioss_get_ipclog_buf_norm(), \
					"cfg:" fmt, ## args); \
	} while (0)

#define ioss_log_msg(dev, fmt, args...) \
	do { \
		void *ioss_get_ipclog_buf_norm(void); \
		dev_dbg(dev, IOSS_SUBSYS fmt, ##args); \
		__ioss_log_msg(ioss_get_ipclog_buf_norm(), fmt, ## args); \
	} while (0)

#define ioss_log_dbg(dev, fmt, args...) \
	do { \
		void *ioss_get_ipclog_buf_debug(void); \
		dev_dbg(dev, IOSS_SUBSYS ":dbg:" fmt "\n", ##args); \
		__ioss_log_msg(ioss_get_ipclog_buf_debug(), \
					"dbg:" fmt, ## args); \
	} while (0)

static inline const char *__ioss_dev_name(struct ioss_device *idev)
{
	if (!idev)
		return NULL;

	if (idev->net_dev)
		return idev->net_dev->name;

	return dev_name(idev->dev.parent);
}

static inline const char *ioss_dev_name(struct ioss_device *idev)
{
	const char *name = __ioss_dev_name(idev);

	if (!name)
		name = "<noname>";

	return name;
}

#define ioss_dev_err(idev, fmt, args...) \
	do { \
		struct ioss_device *__idev = (idev); \
		struct device *dev = __idev ? &__idev->dev : NULL; \
		ioss_log_err(dev, "(%s) " fmt, ioss_dev_name(idev), ## args); \
	} while (0)

#define ioss_dev_bug(idev, fmt, args...) \
	do { \
		struct ioss_device *__idev = (idev); \
		struct device *dev = __idev ? &__idev->dev : NULL; \
		ioss_log_bug(dev, "(%s) " fmt, ioss_dev_name(idev), ## args); \
	} while (0)

#define ioss_dev_dbg(idev, fmt, args...) \
	do { \
		struct ioss_device *__idev = (idev); \
		struct device *dev = __idev ? &__idev->dev : NULL; \
		ioss_log_dbg(dev, "(%s) " fmt, ioss_dev_name(idev), ## args); \
	} while (0)

#define ioss_dev_log(idev, fmt, args...) \
	do { \
		struct ioss_device *__idev = (idev); \
		struct device *dev = __idev ? &__idev->dev : NULL; \
		ioss_log_msg(dev, "(%s) " fmt, ioss_dev_name(idev), ## args); \
	} while (0)

#define ioss_dev_cfg(idev, fmt, args...) \
	do { \
		struct ioss_device *__idev = (idev); \
		struct device *dev = __idev ? &__idev->dev : NULL; \
		ioss_log_cfg(, "(%s) " fmt, ioss_dev_name(idev), ## args); \
	} while (0)

#endif /* _IOSS_H_ */
