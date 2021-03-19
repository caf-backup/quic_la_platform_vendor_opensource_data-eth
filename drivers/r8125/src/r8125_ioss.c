/* SPDX-License-Identifier: GPL-2.0-only
 * Copyright (c) 2021, The Linux Foundation. All rights reserved.
 */

#include <linux/pci.h>

#include <linux/module.h>
#include <linux/device.h>
#include <linux/pm_wakeup.h>

#include <linux/msm/ioss.h>

#include "r8125_lib.h"
#include "r8125.h"

struct r8125_ioss_device {
	struct ioss_device *idev;
	struct wakeup_source *ws;
	struct rtl8125_private *_tp;
	struct notifier_block nb;
};

static int r8125_notifier_cb(struct notifier_block *nb,
		unsigned long action, void *data)
{
	struct r8125_ioss_device *rdev =
			container_of(nb, typeof(*rdev), nb);

	switch (action) {
	case RTL8125_NOTIFY_RESET_PREPARE:
		ioss_dev_err(rdev->idev, "RTL8125 reset prepare");
		break;
	case RTL8125_NOTIFY_RESET_COMPLETE:
		ioss_dev_err(rdev->idev, "RTL8125 reset complete");
		break;
	}

	return NOTIFY_DONE;
}

static int r8125_ioss_open_device(struct ioss_device *idev)
{
	struct r8125_ioss_device *rdev;

	ioss_dev_dbg(idev, "%s", __func__);

	rdev = kzalloc(sizeof(*rdev), GFP_KERNEL);
	if (!rdev)
		return -ENOMEM;

	rdev->idev = idev;
	rdev->_tp = netdev_priv(idev->net_dev);

	rdev->ws = wakeup_source_register(&idev->dev, "r8125-ioss");
	if (!rdev->ws) {
		ioss_dev_err(idev, "Error in initializing wake up source");
		goto err_ws;
	}

	rdev->nb.notifier_call = r8125_notifier_cb;
	if (rtl8125_register_notifier(idev->net_dev, &rdev->nb)) {
		ioss_dev_err(idev, "Failed to register with r8125 notifier");
		goto err_notif;
	}

	/* Hold wake lock since IOSS does yet support power management */
	__pm_stay_awake(rdev->ws);

	idev->private = rdev;

	return 0;

err_notif:
	wakeup_source_unregister(rdev->ws);
err_ws:
	kzfree(rdev);

	return -EFAULT;
}

static int r8125_ioss_close_device(struct ioss_device *idev)
{
	struct r8125_ioss_device *rdev = idev->private;

	ioss_dev_dbg(idev, "%s", __func__);

	__pm_relax(rdev->ws);
	rtl8125_unregister_notifier(idev->net_dev, &rdev->nb);
	wakeup_source_unregister(rdev->ws);
	kzfree(rdev);

	return 0;
}

static int r8125_ioss_request_channel(struct ioss_channel *ch)
{
	int i;
	int rc = 0;
	enum rtl8125_channel_dir direction =
			(ch->direction == IOSS_CH_DIR_RX) ?
				RTL8125_CH_DIR_RX : RTL8125_CH_DIR_TX;
	struct rtl8125_ring *ring;

	ioss_dev_log(ch->iface->idev, "%s, ring_size=%d, buf_size=%d, dir=%d",
			__func__, ch->config.ring_size, ch->config.buff_size,
			direction);

	ring = rtl8125_request_ring(ioss_ch_dev(ch)->net_dev,
			ch->config.ring_size, ch->config.buff_size,
			direction, RTL8125_CONTIG_BUFS, NULL);
	if (!ring) {
		ioss_dev_err(ch->iface->idev, "Failed to request ring");
		return -EFAULT;
	}

	rc = ioss_channel_add_desc_mem(ch,
			ring->desc_addr, ring->desc_daddr, ring->desc_size);
	if (rc) {
		ioss_dev_err(ch->iface->idev, "Failed to add desc mem");
		goto err_add_desc;
	}

	for (i = 0; i < ring->ring_size; i++) {
		struct rtl8125_buf *buff = &ring->bufs[i];

		rc = ioss_channel_add_buff_mem(ch,
				buff->addr, buff->dma_addr, buff->size);
		if (rc) {
			ioss_dev_err(ch->iface->idev, "Failed to add buff mem");
			goto err_add_buff;
		}
	}

	ch->id = ring->queue_num;
	ch->private = ring;

	return 0;

err_add_buff:
	for (i = 0; i < ring->ring_size; i++)
		ioss_channel_del_buff_mem(ch, ring->bufs[i].addr);

	ioss_channel_del_desc_mem(ch, ring->desc_addr);

err_add_desc:
	rtl8125_release_ring(ring);

	ch->id = -1;
	ch->private = NULL;

	return rc;
}

static int r8125_ioss_release_channel(struct ioss_channel *ch)
{
	int i;
	struct rtl8125_ring *ring = ch->private;

	ioss_dev_log(ch->iface->idev, "Release ring %d", ring->queue_num);

	ioss_channel_del_desc_mem(ch, ring->desc_addr);

	for (i = 0; i < ring->ring_size; i++)
		ioss_channel_del_buff_mem(ch, ring->bufs[i].addr);

	rtl8125_release_ring(ring);

	ch->id = -1;
	ch->private = NULL;

	return 0;
}

static int r8125_ioss_enable_channel(struct ioss_channel *ch)
{
	struct rtl8125_ring *ring = ch->private;

	return rtl8125_enable_ring(ring);
}

static int r8125_ioss_disable_channel(struct ioss_channel *ch)
{
	struct rtl8125_ring *ring = ch->private;

	rtl8125_disable_ring(ring);

	return 0;
}

static int r8125_ioss_request_event(struct ioss_channel *ch)
{
	int rc;
	int mod;
	struct rtl8125_ring *ring = ch->private;

	ioss_dev_log(ch->iface->idev, "Request EVENT: daddr=%pad, DATA: %llu",
		&ch->event.daddr, ch->event.data);

	rc = rtl8125_request_event(ring, MSIX_event_type,
					ch->event.daddr, ch->event.data);
	if (rc) {
		ioss_dev_err(ch->iface->idev, "Failed to request event");
		return rc;
	}

	/* Each mod unit is 2048 ns (~2 uS). */
	mod = ch->event.mod_usecs_max / 2;

	ioss_dev_log(ch->iface->idev, "EVENT: mod=%d", mod);

	rc = rtl8125_set_ring_intr_mod(ring, mod);
	if (rc) {
		ioss_dev_err(ch->iface->idev,
			"Failed to set interrupt moderation");
		rtl8125_release_event(ring);
		return rc;
	}

	return 0;
}

static int r8125_ioss_release_event(struct ioss_channel *ch)
{
	struct rtl8125_ring *ring = ch->private;

	ioss_dev_log(ch->iface->idev, "Release EVENT: daddr=%pad, DATA: %llu",
			&ch->event.daddr, ch->event.data);

	rtl8125_release_event(ring);

	return 0;
}

static int __r8125_ioss_enable_filters(struct ioss_channel *ch)
{
	struct rtl8125_ring *ring = ch->private;
	struct net_device *net_dev = ioss_ch_dev(ch)->net_dev;
	enum ioss_filter_types filters = ch->filter_types;

	ioss_dev_log(ch->iface->idev, "Enabling filters %d", filters);

	if (!filters)
		return 0;

	if (ch->direction != IOSS_CH_DIR_RX)
		return -EFAULT;

	if (filters & IOSS_RXF_F_IP) {
		ioss_dev_log(ch->iface->idev, "Enabling RSS filter");

		if (rtl8125_rss_redirect(net_dev, 0, ring)) {
			ioss_dev_err(ch->iface->idev,
					"Failed to install rss filter");
			return -EFAULT;
		}

		filters &= ~IOSS_RXF_F_IP;
	}

	if (filters) {
		ioss_dev_err(ch->iface->idev, "Unsupported filters requested");
		rtl8125_rss_reset(net_dev);
		return -EFAULT;
	}

	return 0;
}

static int __r8125_ioss_disable_filters(struct ioss_channel *ch)
{
	struct net_device *net_dev = ioss_ch_dev(ch)->net_dev;
	enum ioss_filter_types filters = ch->filter_types;

	ioss_dev_log(ch->iface->idev, "Disabling filters %d", filters);

	if (!filters)
		return 0;

	if (ch->direction != IOSS_CH_DIR_RX)
		return -EFAULT;

	if (filters & IOSS_RXF_F_IP) {
		ioss_dev_log(ch->iface->idev, "Disabling RSS filter");

		if (rtl8125_rss_reset(net_dev)) {
			ioss_dev_err(ch->iface->idev, "Failed to reset rss filter");
			return -EFAULT;
		}

		filters &= ~IOSS_RXF_F_IP;
	}

	return 0;
}

static int r8125_ioss_enable_event(struct ioss_channel *ch)
{
	int rc;
	struct rtl8125_ring *ring = ch->private;

	rc = rtl8125_enable_event(ring);
	if (rc) {
		ioss_dev_err(ch->iface->idev, "Failed to enable event");
		return rc;
	}

	rc = __r8125_ioss_enable_filters(ch);
	if (rc) {
		ioss_dev_err(ch->iface->idev, "Failed to enable filters");
		rtl8125_disable_event(ring);
		return rc;
	}

	return 0;
}

static int r8125_ioss_disable_event(struct ioss_channel *ch)
{
	int rc;
	struct rtl8125_ring *ring = ch->private;

	rc = __r8125_ioss_disable_filters(ch);
	if (rc) {
		ioss_dev_err(ch->iface->idev, "Failed to disable filters");
		return rc;
	}

	rc = rtl8125_disable_event(ring);
	if (rc) {
		ioss_dev_err(ch->iface->idev, "Failed to disable event");
		return rc;
	}

	return 0;
}

static struct ioss_driver_ops r8125_ioss_ops = {
	.open_device = r8125_ioss_open_device,
	.close_device = r8125_ioss_close_device,

	.request_channel = r8125_ioss_request_channel,
	.release_channel = r8125_ioss_release_channel,

	.enable_channel = r8125_ioss_enable_channel,
	.disable_channel = r8125_ioss_disable_channel,

	.request_event = r8125_ioss_request_event,
	.release_event = r8125_ioss_release_event,

	.enable_event = r8125_ioss_enable_event,
	.disable_event = r8125_ioss_disable_event,
};

static bool r8125_driver_match(struct device *dev)
{
	ioss_log_dbg(NULL, "MATCH %s", dev_name(dev));

	/* Just match the driver name */
	return (dev->bus == &pci_bus_type) &&
		!strcmp(to_pci_driver(dev->driver)->name, MODULENAME);
}

static struct ioss_driver r8125_ioss_drv = {
	.name = MODULENAME "_ioss",
	.match = r8125_driver_match,
	.ops = &r8125_ioss_ops,
	.filter_types = IOSS_RXF_F_IP,
};

static int __init r8125_ioss_init(void)
{
	return ioss_pci_register_driver(&r8125_ioss_drv);

}
module_init(r8125_ioss_init);

static void __exit r8125_ioss_exit(void)
{
	ioss_pci_unregister_driver(&r8125_ioss_drv);
}
module_exit(r8125_ioss_exit);

MODULE_LICENSE("GPL v2");
MODULE_DESCRIPTION("Realtek R8125 IOSS Glue Driver");
