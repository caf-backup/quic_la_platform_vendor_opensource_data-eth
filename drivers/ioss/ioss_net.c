/* SPDX-License-Identifier: GPL-2.0-only
 * Copyright (c) 2021, The Linux Foundation. All rights reserved.
 */

#include <linux/workqueue.h>
#include <linux/rtnetlink.h>
#include <linux/suspend.h>
#include <linux/bitops.h>

#include "ioss_i.h"

#define IOSS_CHECK_ACTIVE_MS 1250
#define IOSS_NET_DEVICE_MAX_EVENTS (NETDEV_CHANGE_TX_QUEUE_LEN + 1)

static const char * const
		ioss_netdev_event_names[IOSS_NET_DEVICE_MAX_EVENTS] = {
	[NETDEV_REGISTER] = "REGISTER",
	[NETDEV_UNREGISTER] = "UNREGISTER",
	[NETDEV_CHANGENAME] = "CHANGE_NAME",
	[NETDEV_PRE_UP] = "PRE_UP",
	[NETDEV_UP] = "UP",
	[NETDEV_GOING_DOWN] = "GOING_DOWN",
	[NETDEV_DOWN] = "DOWN",
	[NETDEV_CHANGE] = "CHANGE",
	[NETDEV_CHANGELOWERSTATE] = "CHANGE_LOWER_STATE",
	[NETDEV_PRECHANGEUPPER] = "PRE_CHANGE_UPPER",
	[NETDEV_CHANGEUPPER] = "CHANGE_UPPER",
	[NETDEV_JOIN] = "JOIN",
};

const char *ioss_netdev_event_name(unsigned long event)
{
	const char *name = "<unknown>";

	if (event < IOSS_NET_DEVICE_MAX_EVENTS &&
				ioss_netdev_event_names[event])
		name = ioss_netdev_event_names[event];

	return name;
}

static bool net_device_belongs_to(struct net_device *net_dev,
	struct ioss_device *idev)
{
	return net_dev->dev.parent == idev->dev.parent;
}

static void ioss_iface_queue_refresh(struct ioss_interface *iface)
{
	if (queue_work(iface->idev->root->wq, &iface->refresh))
		__pm_stay_awake(iface->refresh_ws);
}

static void ioss_net_check_active(struct ioss_interface *iface)
{
	struct rtnl_link_stats64 last_stats = iface->netdev_stats;
	struct net_device *net_dev = ioss_iface_to_netdev(iface);

	if (!net_dev)
		return;

	dev_get_stats(net_dev, &iface->netdev_stats);

	if (last_stats.rx_packets != iface->netdev_stats.rx_packets)
		__pm_stay_awake(iface->active_ws);
	else
		__pm_relax(iface->active_ws);

	queue_delayed_work(iface->idev->root->wq, &iface->check_active,
				msecs_to_jiffies(IOSS_CHECK_ACTIVE_MS));
}

static void __netdev_get_stats64(struct net_device *net_dev,
		struct rtnl_link_stats64 *stats)
{
	struct ioss_interface *iface = ioss_netdev_to_iface(net_dev);
	const struct net_device_ops *real_ops = iface->netdev_ops_real;

	/* Retrieve stats for direct software path. Modeled after kernel API
	 * dev_get_stats().
	 */
	if (real_ops->ndo_get_stats64)
		real_ops->ndo_get_stats64(net_dev, stats);
	else if (real_ops->ndo_get_stats)
		netdev_stats_to_stats64(stats,
					real_ops->ndo_get_stats(net_dev));
	else
		netdev_stats_to_stats64(stats, &net_dev->stats);

	/* Add exception path stats */
	stats->rx_packets += iface->exception_stats.rx_packets;
	stats->rx_bytes += iface->exception_stats.rx_bytes;
}

static void __hijack_netdev_ops(struct ioss_interface *iface)
{
	struct net_device *net_dev = ioss_iface_to_netdev(iface);

	iface->netdev_ops_real = net_dev->netdev_ops;
	iface->netdev_ops = *iface->netdev_ops_real;

	iface->netdev_ops.ndo_get_stats64 = __netdev_get_stats64;

	net_dev->netdev_ops = &iface->netdev_ops;
}

static void __restore_netdev_ops(struct ioss_interface *iface)
{
	ioss_iface_to_netdev(iface)->netdev_ops = iface->netdev_ops_real;
}

static int __pm_notifier_cb(struct notifier_block *nb,
	unsigned long pm_event, void *__unused)
{
	struct ioss_interface *iface =
			container_of(nb, struct ioss_interface, pm_nb);

	switch (pm_event) {
	case PM_SUSPEND_PREPARE:
	case PM_POST_SUSPEND:
		ioss_net_check_active(iface);
		break;
	}

	return NOTIFY_DONE;
}

static void ioss_net_event_register(struct ioss_interface *iface,
		unsigned long event, void *ptr)
{
	struct net_device *net_dev = netdev_notifier_info_to_dev(ptr);

	ioss_dev_log(iface->idev, "Register event for %s", net_dev->name);

	memset(&iface->exception_stats, 0, sizeof(iface->exception_stats));

	if (ioss_bus_register_iface(iface, net_dev)) {
		ioss_dev_err(iface->idev,
			"Failed to register interface %s", net_dev->name);
		iface->state = IOSS_IF_ST_ERROR;
		return;
	}

	__hijack_netdev_ops(iface);

	iface->pm_nb.notifier_call = __pm_notifier_cb;
	register_pm_notifier(&iface->pm_nb);

	ioss_iface_queue_refresh(iface);
	ioss_net_check_active(iface);
}

static void ioss_net_event_unregister(struct ioss_interface *iface,
		unsigned long event, void *ptr)
{
	struct net_device *net_dev = netdev_notifier_info_to_dev(ptr);

	ioss_dev_log(iface->idev, "Unregister event for %s", net_dev->name);

	cancel_delayed_work_sync(&iface->check_active);
	__pm_relax(iface->active_ws);

	unregister_pm_notifier(&iface->pm_nb);
	__restore_netdev_ops(iface);

	ioss_bus_unregister_iface(iface);

	ioss_iface_queue_refresh(iface);
}

static void ioss_net_event_generic(struct ioss_interface *iface,
		unsigned long event, void *ptr)
{
	struct net_device *net_dev = netdev_notifier_info_to_dev(ptr);

	ioss_dev_log(iface->idev, "Generic event for %s", net_dev->name);

	ioss_iface_queue_refresh(iface);
}

typedef void (*ioss_net_event_handler)(struct ioss_interface *iface,
		unsigned long event, void *ptr);

/* Event handlers for netdevice events from real interface */
static ioss_net_event_handler
		ioss_net_event_handlers[IOSS_NET_DEVICE_MAX_EVENTS] = {
	[NETDEV_REGISTER] = ioss_net_event_register,
	[NETDEV_UNREGISTER] = ioss_net_event_unregister,
	[NETDEV_UP] = ioss_net_event_generic,
	[NETDEV_GOING_DOWN] = ioss_net_event_generic,
	[NETDEV_CHANGE] = ioss_net_event_generic,
};

static int ioss_net_device_event(struct notifier_block *nb,
	unsigned long event, void *ptr)
{
	struct net_device *net_dev = netdev_notifier_info_to_dev(ptr);
	struct ioss_interface *iface = ioss_nb_to_iface(nb);

	if (strcmp(net_dev->name, iface->name) != 0)
		return NOTIFY_OK;

	if (!net_device_belongs_to(net_dev, iface->idev))
		return NOTIFY_OK;

	ioss_dev_dbg(iface->idev, "Received netdev event %s (%lu) for %s",
			ioss_netdev_event_name(event), event, iface->name);

	if (event < IOSS_NET_DEVICE_MAX_EVENTS) {
		ioss_net_event_handler handler = ioss_net_event_handlers[event];

		if (handler)
			handler(iface, event, ptr);

	} else {
		ioss_dev_err(iface->idev,
			"Netdev event number %lu out of bounds", event);
		return NOTIFY_DONE;
	}

	return NOTIFY_OK;
}

static int __ioss_net_alloc_channel(struct ioss_channel *ch)
{
	int rc;
	struct ioss_device *idev = ioss_ch_dev(ch);

	ioss_dev_dbg(ch->iface->idev,
			"Allocating channel for %s", ch->iface->name);

	rc = ioss_dev_op(idev, request_channel, ch);
	if (rc) {
		ioss_dev_err(ch->iface->idev,
			"Failed to alloc channel for %s", ch->iface->name);
		return rc;
	}

	ch->allocated = true;

	ioss_dev_log(ch->iface->idev, "Allocated channel %d for interface %s",
			ch->id, ch->iface->name);

	return 0;
}

static int ioss_net_alloc_channels(struct ioss_interface *iface)
{
	int rc;
	struct ioss_channel *ch;

	ioss_dev_dbg(iface->idev, "Allocating channels for %s", iface->name);

	ioss_for_each_channel(ch, iface) {
		rc = __ioss_net_alloc_channel(ch);
		if (rc) {
			ioss_dev_err(ch->iface->idev,
					"Failed to setup channel for %s",
					iface->name);
			return rc;
		}
	}

	return 0;
}

static int __ioss_net_enable_channel(struct ioss_channel *ch)
{
	int rc;
	struct ioss_device *idev = ioss_ch_dev(ch);

	ioss_dev_dbg(ch->iface->idev,
			"Enabling channel for %s", ch->iface->name);

	rc = ioss_dev_op(idev, enable_channel, ch);
	if (rc) {
		ioss_dev_err(ch->iface->idev,
			"Failed to enable channel %d", ch->id);
		ioss_dev_op(ioss_ch_dev(ch), release_channel, ch);
		return rc;
	}

	ch->enabled = true;

	ioss_dev_log(ch->iface->idev,
		"Enabled channel %d for interface %s", ch->id, ch->iface->name);

	return 0;
}

static int ioss_net_enable_channels(struct ioss_interface *iface)
{
	int rc;
	struct ioss_channel *ch;

	ioss_dev_dbg(iface->idev, "Enabling channels for %s", iface->name);

	ioss_for_each_channel(ch, iface) {
		rc = __ioss_net_enable_channel(ch);
		if (rc) {
			ioss_dev_err(ch->iface->idev,
					"Failed to enable channel for %s",
					iface->name);
			return rc;
		}
	}

	return 0;
}

static int __ioss_net_free_channel(struct ioss_channel *ch)
{
	int rc;
	int id = ch->id;
	struct ioss_device *idev = ioss_ch_dev(ch);

	ioss_dev_dbg(idev,
		"Releasing channel %d for %s", id, ch->iface->name);

	rc = ioss_dev_op(idev, release_channel, ch);
	if (rc) {
		ioss_dev_err(idev, "Failed to release channel %d", id);
		return rc;
	}

	ch->allocated = false;

	ioss_dev_log(ch->iface->idev,
		"Released channel %d on interface %s", id, ch->iface->name);

	return 0;
}

static int ioss_net_free_channels(struct ioss_interface *iface)
{
	int rc;
	struct ioss_channel *ch;

	ioss_dev_dbg(iface->idev, "Releasing all channels for %s", iface->name);

	ioss_for_each_channel(ch, iface) {
		rc = __ioss_net_free_channel(ch);
		if (rc) {
			ioss_dev_err(ch->iface->idev,
					"Failed to release channel for %s",
					iface->name);
			return rc;
		}
	}

	return 0;
}

static int __ioss_net_disable_channel(struct ioss_channel *ch)
{
	int rc;
	int id = ch->id;
	struct ioss_device *idev = ioss_ch_dev(ch);

	ioss_dev_dbg(idev,
		"Disabling channel %d for %s", id, ch->iface->name);

	rc = ioss_dev_op(idev, disable_channel, ch);
	if (rc) {
		ioss_dev_err(idev, "Failed to disable channel %d", id);
		return rc;
	}

	ch->enabled = false;

	ioss_dev_log(ch->iface->idev,
		"Disabled channel %d on interface %s", id, ch->iface->name);

	return 0;
}

static int ioss_net_disable_channels(struct ioss_interface *iface)
{
	int rc;
	struct ioss_channel *ch;

	ioss_dev_dbg(iface->idev, "Disabling all channels for %s", iface->name);

	ioss_for_each_channel(ch, iface) {
		rc = __ioss_net_disable_channel(ch);
		if (rc) {
			ioss_dev_err(ch->iface->idev,
					"Failed to disable channel for %s",
					iface->name);
			return rc;
		}
	}

	return 0;
}

static int __dma_map_event(struct ioss_channel *ch)
{
	struct device *dev = ioss_idev_to_real(ioss_ch_dev(ch));

	if (ch->event.daddr)
		return 0;

	ch->event.daddr = dma_map_resource(dev,
				ch->event.paddr, sizeof(ch->event.data),
				DMA_FROM_DEVICE, 0);

	if (dma_mapping_error(dev, ch->event.daddr)) {
		ioss_dev_dbg(ch->iface->idev,
				"Failed to DMA map DB address");
		ch->event.daddr = 0;
		return -EFAULT;
	}

	return 0;
}

static int __dma_unmap_event(struct ioss_channel *ch)
{
	struct device *dev = ioss_idev_to_real(ioss_ch_dev(ch));

	if (!ch->event.daddr)
		return 0;

	dma_unmap_resource(dev,
			ch->event.daddr, sizeof(ch->event.data),
			DMA_FROM_DEVICE, 0);

	ch->event.daddr = 0;

	return 0;
}

static int __ioss_net_setup_event(struct ioss_channel *ch)
{
	int rc;
	struct ioss_device *idev = ioss_ch_dev(ch);

	ioss_dev_dbg(ch->iface->idev,
			"Setting up event for channel %d", ch->id);

	rc = __dma_map_event(ch);
	if (rc) {
		ioss_dev_err(ch->iface->idev,
			"Failed to DMA map event for channel %d", ch->id);
		return rc;
	}

	rc = ioss_dev_op(idev, request_event, ch);
	if (rc) {
		ioss_dev_err(ch->iface->idev,
			"Failed to alloc event for channel %d", ch->id);
		goto err_alloc;
	}

	ch->event.allocated = true;

	rc = ioss_dev_op(idev, enable_event, ch);
	if (rc) {
		ioss_dev_err(ch->iface->idev,
			"Failed to enable event for channel %d", ch->id);
		goto err_enable;
	}

	ch->event.enabled = true;

	ioss_dev_log(ch->iface->idev,
		"Setup event for channel %d", ch->id);

	return 0;

err_enable:
	ioss_dev_op(idev, release_event, ch);
err_alloc:
	__dma_unmap_event(ch);

	return rc;
}

static int ioss_net_setup_events(struct ioss_interface *iface)
{
	int rc;
	struct ioss_channel *ch;

	ioss_dev_dbg(iface->idev, "Setting up all device events");

	ioss_for_each_channel(ch, iface) {
		rc = __ioss_net_setup_event(ch);
		if (rc)
			return rc;
	}

	return 0;
}

static int __ioss_net_teardown_event(struct ioss_channel *ch)
{
	int rc;
	struct ioss_device *idev = ioss_ch_dev(ch);

	ioss_dev_dbg(ch->iface->idev,
			"Tearing down event for channel %d", ch->id);

	rc = ioss_dev_op(idev, disable_event, ch);
	if (rc) {
		ioss_dev_err(ch->iface->idev,
			"Failed to disable event for channel %d", ch->id);
		return rc;
	}

	ch->event.enabled = false;

	rc = ioss_dev_op(idev, release_event, ch);
	if (rc) {
		ioss_dev_err(ch->iface->idev,
			"Failed to dealloc event for channel %d", ch->id);
		return rc;
	}

	ch->event.allocated = false;

	rc = __dma_unmap_event(ch);
	if (rc) {
		ioss_dev_err(ch->iface->idev,
			"Failed to DMA unmap event for channel %d", ch->id);
		return rc;
	}

	ioss_dev_log(ch->iface->idev,
		"Teared down event for channel %d", ch->id);

	return 0;
}

static int ioss_net_teardown_events(struct ioss_interface *iface)
{
	int rc;
	struct ioss_channel *ch;

	ioss_dev_dbg(iface->idev, "Tearing down all device events");

	ioss_for_each_channel(ch, iface) {
		rc = __ioss_net_teardown_event(ch);
		if (rc)
			return rc;
	}

	return 0;
}

static void ioss_iface_set_online(struct ioss_interface *iface)
{
	int rc;

	if (iface->state != IOSS_IF_ST_OFFLINE)
		return;

	ioss_dev_log(iface->idev, "Bringing up %s", iface->name);

	rc = ioss_net_alloc_channels(iface);
	if (rc) {
		ioss_dev_err(iface->idev, "Failed to allocate channels");
		iface->state = IOSS_IF_ST_ERROR;
		return;
	}

	rc = ioss_ipa_register(iface);
	if (rc) {
		ioss_dev_err(iface->idev, "Failed to register with IPA");
		iface->state = IOSS_IF_ST_ERROR;
		return;
	}

	rc = ioss_net_setup_events(iface);
	if (rc) {
		ioss_dev_err(iface->idev, "Failed to setup events");
		iface->state = IOSS_IF_ST_ERROR;
		return;
	}

	rc = ioss_net_enable_channels(iface);
	if (rc) {
		ioss_dev_err(iface->idev, "Failed to enable channels");
		iface->state = IOSS_IF_ST_ERROR;
		return;
	}

	rc = ioss_pci_disable_pc(iface->idev);
	if (rc) {
		ioss_dev_err(iface->idev, "Failed to disable PCI power collapse");
		iface->state = IOSS_IF_ST_ERROR;
		return;
	}

	iface->state = IOSS_IF_ST_ONLINE;
}

static void ioss_iface_set_offline(struct ioss_interface *iface)
{
	int rc;

	if (iface->state != IOSS_IF_ST_ONLINE)
		return;

	ioss_dev_log(iface->idev, "Bringing down %s", iface->name);

	rc = ioss_pci_enable_pc(iface->idev);
	if (rc) {
		ioss_dev_err(iface->idev, "Failed to enable PCI power collapse");
		iface->state = IOSS_IF_ST_ERROR;
		return;
	}

	rc = ioss_net_disable_channels(iface);
	if (rc) {
		ioss_dev_err(iface->idev, "Failed to disable channels");
		iface->state = IOSS_IF_ST_ERROR;
		return;
	}

	rc = ioss_net_teardown_events(iface);
	if (rc) {
		ioss_dev_err(iface->idev, "Failed to teardown events");
		iface->state = IOSS_IF_ST_ERROR;
		return;
	}

	rc = ioss_ipa_unregister(iface);
	if (rc) {
		ioss_dev_err(iface->idev, "Failed to unregister with IPA");
		iface->state = IOSS_IF_ST_ERROR;
		return;
	}

	rc = ioss_net_free_channels(iface);
	if (rc) {
		ioss_dev_err(iface->idev, "Failed to release channels");
		iface->state = IOSS_IF_ST_ERROR;
		return;
	}

	iface->state = IOSS_IF_ST_OFFLINE;
}

static void ioss_refresh_work(struct work_struct *work)
{
	struct ioss_interface *iface = ioss_refresh_work_to_iface(work);
	struct net_device *net_dev = ioss_iface_to_netdev(iface);

	if (!net_dev)
		return;

	ioss_dev_dbg(iface->idev, "Refreshing interface %s", iface->name);

	if (netif_running(net_dev) && netif_carrier_ok(net_dev))
		ioss_iface_set_online(iface);
	else
		ioss_iface_set_offline(iface);

	__pm_relax(iface->refresh_ws);
}

static void ioss_net_active_work(struct work_struct *work)
{
	ioss_net_check_active(ioss_active_work_to_iface(work));
}

int ioss_net_watch_device(struct ioss_device *idev)
{
	int rc = 0;
	struct ioss_interface *iface;

	ioss_for_each_iface(iface, idev) {
		INIT_WORK(&iface->refresh, ioss_refresh_work);
		iface->net_dev_nb.notifier_call = ioss_net_device_event;

		iface->refresh_ws = wakeup_source_register(&idev->dev, iface->name);
		if (!iface->refresh_ws) {
			ioss_dev_err(idev, "Failed to register refresh wake source");
			goto err_register;
		}

		INIT_DELAYED_WORK(&iface->check_active, ioss_net_active_work);

		iface->active_ws = wakeup_source_register(&idev->dev, iface->name);
		if (!iface->active_ws) {
			ioss_dev_err(idev, "Failed to register active wake source");
			goto err_register;
		}

		ioss_dev_log(idev, "Watching interface %s", iface->name);

		rc = register_netdevice_notifier(&iface->net_dev_nb);
		if (rc) {
			ioss_dev_err(iface->idev,
				"Failed to register netdev notifier for %s",
				iface->name);
			goto err_register;
		}

		ioss_dev_log(idev, "Watching interface %s", iface->name);
	}

	return 0;

err_register:
	list_for_each_entry(iface, &idev->interfaces, node) {
		(void) unregister_netdevice_notifier(&iface->net_dev_nb);

		flush_work(&iface->refresh);
		wakeup_source_unregister(iface->refresh_ws);
		iface->refresh_ws = NULL;

		cancel_delayed_work_sync(&iface->check_active);
		wakeup_source_unregister(iface->active_ws);
		iface->active_ws = NULL;
	}

	return rc;
}

int ioss_net_unwatch_device(struct ioss_device *idev)
{
	int rc = 0;
	struct ioss_interface *iface;

	ioss_for_each_iface(iface, idev) {
		ioss_dev_log(idev, "Unwatching interface %s", iface->name);

		rc |= unregister_netdevice_notifier(&iface->net_dev_nb);
		if (rc) {
			ioss_dev_err(iface->idev,
				"Failed to unregister netdev notifier for %s",
				iface->name);
			continue;
		}

		flush_work(&iface->refresh);
		wakeup_source_unregister(iface->refresh_ws);
		iface->refresh_ws = NULL;

		cancel_delayed_work_sync(&iface->check_active);
		wakeup_source_unregister(iface->active_ws);
		iface->active_ws = NULL;
	}

	return 0;
}

int ioss_net_link_device(struct ioss_device *idev)
{
	struct net *net;
	struct net_device *net_dev;

	if (idev->net_dev)
		return 0;

	rtnl_lock();
	for_each_net(net) {
		for_each_netdev(net, net_dev) {
			if (net_dev->dev.parent == idev->dev.parent) {
				idev->net_dev = net_dev;
				break;
			}
		}
	}
	rtnl_unlock();

	if (!idev->net_dev)
		return -ENOENT;

	ioss_dev_log(idev, "Linked to net device %s", idev->net_dev->name);

	return 0;
}
