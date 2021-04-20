// SPDX-License-Identifier: GPL-2.0-only
/* Copyright (c) 2021, The Linux Foundation. All rights reserved.
 */

#include <linux/module.h>
#include <linux/pci.h>
#include <linux/gfp.h>
#include <linux/slab.h>
#include <linux/device.h>
#include <linux/pm_wakeup.h>

#include <linux/msm/ioss.h>
#include <atl_fwd.h>

#define AQC_FLT_LOC_CATCH_ALL 40
#define AQC_DRIVER_NAME "atlantic-fwd"
#define MODULENAME "aqc-ioss"

struct aqc_ioss_device {
	struct atl_nic *nic;
	struct notifier_block nb;
};

static void *aqc_ioss_dma_alloc(struct ioss_device *idev,
			       size_t size, dma_addr_t *daddr, gfp_t gfp,
			       struct ioss_mem_allocator *alctr)
{
	return alctr->alloc(idev, size, daddr, gfp, alctr);
}

static void aqc_ioss_dma_free(struct ioss_device *idev,
			     size_t size, void *buf, dma_addr_t daddr,
			     struct ioss_mem_allocator *alctr)
{
	return alctr->free(idev, size, buf, daddr, alctr);
}

static void *aqc_ioss_alloc_descs(struct device *dev, size_t size,
				 dma_addr_t *daddr, gfp_t gfp,
				 struct atl_fwd_mem_ops *ops)
{
	struct ioss_channel *ch = ops->private;

	return aqc_ioss_dma_alloc(ioss_ch_dev(ch), size, daddr, gfp,
			ch->config.desc_alctr);
}

static void *aqc_ioss_alloc_buf(struct device *dev, size_t size,
			       dma_addr_t *daddr, gfp_t gfp,
			       struct atl_fwd_mem_ops *ops)
{
	struct ioss_channel *ch = ops->private;

	return aqc_ioss_dma_alloc(ioss_ch_dev(ch), size, daddr, gfp,
			ch->config.buff_alctr);
}

static void aqc_ioss_free_descs(void *buf, struct device *dev, size_t size,
			       dma_addr_t daddr, struct atl_fwd_mem_ops *ops)
{
	struct ioss_channel *ch = ops->private;

	return aqc_ioss_dma_free(ioss_ch_dev(ch), size, buf, daddr,
			ch->config.desc_alctr);
}

static void aqc_ioss_free_buf(void *buf, struct device *dev, size_t size,
			     dma_addr_t daddr, struct atl_fwd_mem_ops *ops)
{
	struct ioss_channel *ch = ops->private;

	return aqc_ioss_dma_free(ioss_ch_dev(ch), size, buf, daddr,
			ch->config.buff_alctr);
}

static int aqc_notifier_cb(struct notifier_block *nb,
		unsigned long action, void *data)
{
	struct aqc_ioss_device *aqdev =
			container_of(nb, typeof(*aqdev), nb);

	switch (action) {
	case ATL_FWD_NOTIFY_RESET_PREPARE:
		ioss_log_msg(NULL, "AQC reset prepare");
		break;
	case ATL_FWD_NOTIFY_RESET_COMPLETE:
		ioss_log_msg(NULL, "AQC reset complete");
		break;
	}

	return NOTIFY_DONE;
}

static int aqc_ioss_open_device(struct ioss_device *idev)
{
	struct aqc_ioss_device *aqdev;

	ioss_dev_dbg(idev, "%s", __func__);

	aqdev = kzalloc(sizeof(*aqdev), GFP_KERNEL);
	if (!aqdev)
		return -ENOMEM;

	aqdev->nic = netdev_priv(idev->net_dev);

	aqdev->nb.notifier_call = aqc_notifier_cb;
	if (atl_fwd_register_notifier(idev->net_dev, &aqdev->nb)) {
		ioss_dev_err(idev, "Failed to register with ATL notifier");
		goto err_notif;
	}

	idev->private = aqdev;

	return 0;

err_notif:
	kzfree(aqdev);

	return -EFAULT;
}

static int aqc_ioss_close_device(struct ioss_device *idev)
{
	struct aqc_ioss_device *aqdev = idev->private;

	ioss_dev_dbg(idev, "%s", __func__);

	atl_fwd_unregister_notifier(idev->net_dev, &aqdev->nb);
	kzfree(aqdev);

	return 0;
}

static int aqc_ioss_request_channel(struct ioss_channel *ch)
{
	int i, desc_size;
	int rc = 0;
	struct atl_fwd_ring *ring = NULL;
	enum atl_fwd_ring_flags ring_flags = 0;
	struct atl_fwd_mem_ops *mem_ops = NULL;

	ioss_dev_log(ch->iface->idev, "%s, ring_size=%d, buf_size=%d, dir=%d",
		     __func__, ch->config.ring_size, ch->config.buff_size,
			ch->direction);

	mem_ops = kzalloc(sizeof(*mem_ops), GFP_KERNEL);
	if (!mem_ops)
		return -ENOMEM;

	mem_ops->alloc_descs = aqc_ioss_alloc_descs;
	mem_ops->alloc_buf = aqc_ioss_alloc_buf;
	mem_ops->free_descs = aqc_ioss_free_descs;
	mem_ops->free_buf = aqc_ioss_free_buf;
	mem_ops->private = ch;

	switch (ch->direction) {
	case IOSS_CH_DIR_RX:
		desc_size = sizeof(struct atl_rx_desc);
		break;
	case IOSS_CH_DIR_TX:
		desc_size = sizeof(struct atl_tx_desc);
		ring_flags |= ATL_FWR_TX;
		break;
	default:
		ioss_dev_err(ch->iface->idev, "Unsupported direction %d", ch->direction);
		kzfree(mem_ops);
		return -EINVAL;
	}

	ring_flags |= ATL_FWR_ALLOC_BUFS;
	ring_flags |= ATL_FWR_CONTIG_BUFS;

	ring = atl_fwd_request_ring(ioss_ch_dev(ch)->net_dev, ring_flags,
			ch->config.ring_size, ch->config.buff_size, 1, mem_ops);
	if (!ring) {
		ioss_dev_err(ch->iface->idev, "Failed to request ring");
		goto err_ring;
	}

	rc = ioss_channel_add_desc_mem(ch,
			ring->hw.descs, ring->hw.daddr, (desc_size * ring->hw.size));
	if (rc) {
		ioss_dev_err(ch->iface->idev, "Failed to add desc mem");
		goto err_add_desc;
	}

	for (i = 0; i < ring->hw.size; i++) {
		void *vaddr = (void *)ring->bufs->vaddr_vec;
		void *addr = vaddr + (ring->buf_size * i);
		dma_addr_t daddr = ring->bufs->daddr_vec_base + (ring->buf_size * i);

		rc = ioss_channel_add_buff_mem(ch,
				addr, daddr, ring->buf_size);
		if (rc) {
			ioss_dev_err(ch->iface->idev, "Failed to add buff mem");
			goto err_add_buff;
		}
	}

	ch->id = ring->idx;
	ch->private = ring;

	return 0;

err_add_buff:
	for (i = 0; i < ring->hw.size; i++) {
		void *vaddr = (void *)ring->bufs->vaddr_vec;
		void *addr = vaddr + (ring->buf_size * i);

		ioss_channel_del_buff_mem(ch, addr);
	}
	ioss_channel_del_desc_mem(ch, ring->hw.descs);
err_add_desc:
	atl_fwd_release_ring(ring);
err_ring:
	kzfree(mem_ops);

	ch->id = -1;
	ch->private = NULL;

	return rc;
}

static int aqc_ioss_release_channel(struct ioss_channel *ch)
{
	int i;
	struct atl_fwd_ring *ring = ch->private;
	struct atl_fwd_mem_ops *mem_ops = ring->mem_ops;

	ioss_dev_dbg(ch->iface->idev, "Release ring %d", ring->idx);

	for (i = 0; i < ring->hw.size; i++) {
		void *vaddr = (void *)ring->bufs->vaddr_vec;
		void *addr = vaddr + (ring->buf_size * i);

		ioss_channel_del_buff_mem(ch, addr);
	}

	ioss_channel_del_desc_mem(ch, ring->hw.descs);

	atl_fwd_release_ring(ring);
	kzfree(mem_ops);

	ch->id = -1;
	ch->private = NULL;

	return 0;
}

static int aqc_ioss_enable_channel(struct ioss_channel *ch)
{
	struct atl_fwd_ring *ring = ch->private;

	return atl_fwd_enable_ring(ring);
}

static int aqc_ioss_disable_channel(struct ioss_channel *ch)
{
	struct atl_fwd_ring *ring = ch->private;

	atl_fwd_disable_ring(ring);

	return 0;
}

static int aqc_ioss_request_event(struct ioss_channel *ch)
{
	int rc;
	struct atl_fwd_ring *ring = ch->private;
	struct atl_fwd_event *event = NULL;
	struct atl_fwd_event atl_event = {0};

	ioss_dev_log(ch->iface->idev, "Request EVENT: daddr=%pad, DATA: %llu",
		&ch->event.daddr, ch->event.data);

	switch (ch->direction) {
	case IOSS_CH_DIR_RX:
		atl_event.msi_addr = ch->event.daddr;
		atl_event.msi_data = (u32)ch->event.data;
		break;
	case IOSS_CH_DIR_TX:
		atl_event.flags = ATL_FWD_EVT_TXWB;
		atl_event.tx_head_wrb = ch->event.daddr;
		break;
	default:
		ioss_dev_err(ch->iface->idev, "Unsupported direction %d\n", ch->direction);
		return -ENODEV;
	}

	event = kzalloc(sizeof(*event), GFP_KERNEL);
		if (!event)
			return -ENOMEM;

	*event = atl_event;
	event->ring = ring;

	rc = atl_fwd_request_event(event);
	if (rc) {
		ioss_dev_err(ch->iface->idev, "Failed to request event");
		goto err_req_event;
	}

	if (ch->direction == IOSS_CH_DIR_RX) {
		if (atl_fwd_set_ring_intr_mod(ring, ch->event.mod_usecs_min,
					      ch->event.mod_usecs_max)) {
			ioss_dev_err(ch->iface->idev, "Failed to set interrupt moderation");
			goto err_intr_mod;
		}
	}

	return 0;

err_intr_mod:
	atl_fwd_release_event(event);
err_req_event:
	kzfree(event);

	return -EINVAL;
}

static int aqc_ioss_release_event(struct ioss_channel *ch)
{
	struct atl_fwd_ring *ring = ch->private;

	ioss_dev_log(ch->iface->idev, "Release EVENT: daddr=%pad, DATA: %llu",
		&ch->event.daddr, ch->event.data);

	atl_fwd_release_event(ring->evt);

	return 0;
}

/**
 * __config_catchall_filter() - Installs or removes the catch-all AQC Rx filter
 *
 * @ch: ioss channel
 * @insert: If true, inserts rule at %AQC_FLT_LOC_CATCH_ALL. Otherwise removes
 *          any filter installed at the same location.
 *
 * Configure the catch-all filter on AQC NIC. When installed, the catch-all
 * filter directs all incoming traffic to Rx queue associated with offload path.
 * Catch-all filter in Aquantia is implemented using Flex Filter that matches
 * the packet with zero bitmask (effectively matching any packet) and the filter
 * is applied on any packet that is not already matched by other filters (except
 * RSS filter).
 *
 * Returns 0 on success, non-zero otherwise.
 */
static int __config_catchall_filter(struct ioss_channel *ch, bool insert)
{
	struct ethtool_rxnfc rxnfc;
	struct atl_fwd_ring *ring = ch->private;
	struct net_device *net_dev = ioss_ch_dev(ch)->net_dev;

	if (!net_dev) {
		ioss_dev_err(ch->iface->idev, "Net device information is missing");
		return -EFAULT;
	}

	if (!net_dev->ethtool_ops || !net_dev->ethtool_ops->set_rxnfc) {
		ioss_dev_err(ch->iface->idev, "set_rxnfc is not supported by the network driver");
		return -EFAULT;
	}

	memset(&rxnfc, 0, sizeof(rxnfc));

	rxnfc.cmd = insert ? ETHTOOL_SRXCLSRLINS : ETHTOOL_SRXCLSRLDEL;

	rxnfc.fs.ring_cookie = ring->idx;
	rxnfc.fs.location = AQC_FLT_LOC_CATCH_ALL;

	return net_dev->ethtool_ops->set_rxnfc(net_dev, &rxnfc);
}

static int aqc_ioss_netdev_rxflow_set(struct ioss_channel *ch)
{
	int rc = __config_catchall_filter(ch, true);

	if (rc)
		ioss_dev_err(ch->iface->idev, "Failed to install catch-all filter");
	else
		ioss_dev_dbg(ch->iface->idev, "Installed Rx catch-all filter");

	return rc;
}

static int aqc_ioss_netdev_rxflow_reset(struct ioss_channel *ch)
{
	int rc = __config_catchall_filter(ch, false);

	if (rc)
		ioss_dev_err(ch->iface->idev, "Failed to remove catch-all filter");
	else
		ioss_dev_dbg(ch->iface->idev, "Removed Rx catch-all filter");

	return rc;
}

static int aqc_ioss_enable_filters(struct ioss_channel *ch)
{
	enum ioss_filter_types filters = ch->filter_types;

	ioss_dev_log(ch->iface->idev, "Enabling filters %d and IOSS_RXF_BE %d\n",
		     filters, IOSS_RXF_F_BE);

	if (!filters)
		return 0;

	if (ch->direction != IOSS_CH_DIR_RX)
		return -EFAULT;

	if (filters & IOSS_RXF_F_BE) {
		ioss_dev_dbg(ch->iface->idev, "Enabling catch-all filter");

		if (aqc_ioss_netdev_rxflow_set(ch)) {
			ioss_dev_err(ch->iface->idev, "Failed to install catch-all filter");
			return -EFAULT;
		}

		filters &= ~IOSS_RXF_F_BE;
	}

	if (filters) {
		ioss_dev_err(ch->iface->idev, "Unsupported filters requested");
		aqc_ioss_netdev_rxflow_reset(ch);
		return -EFAULT;
	}

	return 0;
}

static int aqc_ioss_disable_filters(struct ioss_channel *ch)
{
	enum ioss_filter_types filters = ch->filter_types;

	ioss_dev_log(ch->iface->idev, "Disabling filters %d\n", filters);

	if (!filters)
		return 0;

	if (ch->direction != IOSS_CH_DIR_RX)
		return -EFAULT;

	if (filters & IOSS_RXF_F_BE) {
		ioss_dev_dbg(ch->iface->idev, "Disabling catch-all filter");

		if (aqc_ioss_netdev_rxflow_reset(ch)) {
			ioss_dev_err(ch->iface->idev, "Failed to reset catch-all filter");
			return -EFAULT;
		}

		filters &= ~IOSS_RXF_F_BE;
	}

	return 0;
}

static int aqc_ioss_enable_event(struct ioss_channel *ch)
{
	int rc;
	struct atl_fwd_ring *ring = ch->private;

	rc = atl_fwd_enable_event(ring->evt);
	if (rc) {
		ioss_dev_err(ch->iface->idev, "Failed to enable event");
		return rc;
	}

	rc = aqc_ioss_enable_filters(ch);
	if (rc) {
		ioss_dev_err(ch->iface->idev, "Failed to enable filters");
		atl_fwd_disable_event(ring->evt);
		return rc;
	}

	return 0;
}

static int aqc_ioss_disable_event(struct ioss_channel *ch)
{
	int rc;
	struct atl_fwd_ring *ring = ch->private;

	rc = aqc_ioss_disable_filters(ch);
	if (rc) {
		ioss_dev_err(ch->iface->idev, "Failed to disable filters");
		return rc;
	}

	rc = atl_fwd_disable_event(ring->evt);
	if (rc) {
		ioss_dev_err(ch->iface->idev, "Failed to disable event");
		return rc;
	}

	return 0;
}

static struct ioss_driver_ops aqc_ioss_ops = {
	.open_device = aqc_ioss_open_device,
	.close_device = aqc_ioss_close_device,

	.request_channel = aqc_ioss_request_channel,
	.release_channel = aqc_ioss_release_channel,

	.enable_channel = aqc_ioss_enable_channel,
	.disable_channel = aqc_ioss_disable_channel,

	.request_event = aqc_ioss_request_event,
	.release_event = aqc_ioss_release_event,

	.enable_event = aqc_ioss_enable_event,
	.disable_event = aqc_ioss_disable_event,
};

static bool aqc_driver_match(struct device *dev)
{
	ioss_log_dbg(NULL, "MATCH %s", dev_name(dev));

	/* Just match the driver name */
	return (dev->bus == &pci_bus_type) &&
		!strcmp(to_pci_driver(dev->driver)->name, AQC_DRIVER_NAME);
}

static struct ioss_driver aqc_ioss_drv = {
	.name = MODULENAME,
	.match = aqc_driver_match,
	.ops = &aqc_ioss_ops,
	.filter_types = IOSS_RXF_F_BE,
};

static int __init aqc_ioss_init(void)
{
	return ioss_pci_register_driver(&aqc_ioss_drv);

}
module_init(aqc_ioss_init);

static void __exit aqc_ioss_exit(void)
{
	ioss_pci_unregister_driver(&aqc_ioss_drv);
}
module_exit(aqc_ioss_exit);

MODULE_LICENSE("GPL v2");
MODULE_DESCRIPTION("AQC IOSS Glue Driver");
