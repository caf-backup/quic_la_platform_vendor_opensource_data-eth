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

void ioss_iface_queue_refresh(struct ioss_interface *iface, bool flush)
{
	queue_work(iface->idev->root->wq, &iface->refresh);

	if (flush)
		flush_work(&iface->refresh);
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

	ioss_iface_queue_refresh(iface, false);
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

	ioss_iface_queue_refresh(iface, false);
}

static void ioss_net_event_generic(struct ioss_interface *iface,
		unsigned long event, void *ptr)
{
	struct net_device *net_dev = netdev_notifier_info_to_dev(ptr);

	ioss_dev_log(iface->idev, "Generic event for %s", net_dev->name);

	ioss_iface_queue_refresh(iface, false);
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

static bool disable_tcm;
module_param(disable_tcm, bool, S_IRUSR | S_IWUSR | S_IRGRP | S_IWGRP);
MODULE_PARM_DESC(disable_tcm, "Disable use of LLCC TCM memory allocator");

static int ioss_net_select_llcc_config(struct ioss_channel *ch)
{
	u32 ring_size;
	size_t mem_need = ch->config.ring_size * ch->config.buff_size;
	size_t mem_size;

	if (disable_tcm) {
		ioss_dev_cfg(ch->iface->idev,
			"Not allocating TCM since it is disabled in IOSS");
		return -ENOMEM;
	}

	mem_size = ioss_llcc_alctr.get(mem_need);

	ioss_dev_cfg(ch->iface->idev,
		"Requested %u bytes of LLCC, received %u bytes",
		mem_need, mem_size);

	if (!mem_size)
		return -ENOMEM;

	ring_size = mem_size / ch->config.buff_size;

	ioss_dev_cfg(ch->iface->idev,
		"Calculated ring size of %u with LLCC buffer size of %u bytes",
		ring_size, ch->config.buff_size);

	ch->config.ring_size = ring_size;
	ch->config.buff_alctr = &ioss_llcc_alctr;

	return 0;
}

static void ioss_net_select_channel_config(struct ioss_channel *ch)
{
	u32 link_speed = ch->iface->link_speed;
	u32 max_ddr_bw = ch->iface->idev->root->max_ddr_bandwidth;

	ch->config = ch->default_config;

	if (ch->direction == IOSS_CH_DIR_TX && link_speed > max_ddr_bw)
		ioss_net_select_llcc_config(ch);
}

static void ioss_net_deselect_channel_config(struct ioss_channel *ch)
{
	if (ch->config.buff_alctr == &ioss_llcc_alctr)
		ioss_llcc_alctr.put(
			ch->config.ring_size * ch->config.buff_size);

	ch->config = ch->default_config;
}

static int __ioss_net_alloc_channel(struct ioss_channel *ch)
{
	int rc;

	ioss_dev_dbg(ioss_ch_dev(ch),
			"Allocating channel for %s", ch->iface->name);

	ioss_net_select_channel_config(ch);

	rc = ioss_dev_op(ioss_ch_dev(ch), request_channel, ch);
	if (rc) {
		ioss_dev_err(ioss_ch_dev(ch),
			"Failed to alloc channel for %s", ch->iface->name);
		ioss_net_deselect_channel_config(ch);
		return rc;
	}

	ch->allocated = true;

	ioss_dev_log(ioss_ch_dev(ch), "Allocated channel %d for interface %s",
			ch->id, ch->iface->name);

	rc = ioss_debugfs_add_channel(ch);
	if (rc) {
		ioss_dev_err(ioss_ch_dev(ch), "Failed to create debugfs nodes");
		goto err_debugfs;
	}

	return 0;

err_debugfs:
	ioss_dev_op(ioss_ch_dev(ch), release_channel, ch);
	ch->allocated = false;
	ioss_net_deselect_channel_config(ch);
	return rc;
}

static int __ioss_net_free_channel(struct ioss_channel *ch)
{
	int rc;
	int id = ch->id;
	struct ioss_device *idev = ioss_ch_dev(ch);

	ioss_debugfs_remove_channel(ch);

	ioss_dev_dbg(idev,
		"Releasing channel %d for %s", id, ch->iface->name);

	rc = ioss_dev_op(idev, release_channel, ch);
	if (rc) {
		ioss_dev_err(idev, "Failed to release channel %d", id);
		return rc;
	}

	ch->allocated = false;

	ioss_net_deselect_channel_config(ch);

	ioss_dev_log(ch->iface->idev,
		"Released channel %d on interface %s", id, ch->iface->name);

	return 0;
}

static int __alloc_channel_action(struct list_head *node)
{
	return __ioss_net_alloc_channel(
			container_of(node, struct ioss_channel, node));
}

static void __alloc_channel_revert(struct list_head *node)
{
	(void) __ioss_net_free_channel(
			container_of(node, struct ioss_channel, node));
}

static int ioss_net_alloc_channels(struct ioss_interface *iface)
{
	ioss_dev_dbg(iface->idev, "Allocating channels for %s", iface->name);

	return ioss_list_iter_action(&iface->channels,
			__alloc_channel_action, __alloc_channel_revert);
}

static int ioss_net_free_channels(struct ioss_interface *iface)
{
	int rc = 0;
	struct ioss_channel *ch;

	ioss_dev_dbg(iface->idev, "Releasing all channels for %s", iface->name);

	ioss_for_each_channel(ch, iface)
		rc |= __ioss_net_free_channel(ch);

	return rc;
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

static int __enable_channel_action(struct list_head *node)
{
	return __ioss_net_enable_channel(
			container_of(node, struct ioss_channel, node));
}

static void __enable_channel_revert(struct list_head *node)
{
	(void) __ioss_net_disable_channel(
			container_of(node, struct ioss_channel, node));
}

static int ioss_net_enable_channels(struct ioss_interface *iface)
{
	ioss_dev_dbg(iface->idev, "Enabling channels for %s", iface->name);

	return ioss_list_iter_action(&iface->channels,
			__enable_channel_action, __enable_channel_revert);
}

static int ioss_net_disable_channels(struct ioss_interface *iface)
{
	int rc = 0;
	struct ioss_channel *ch;

	ioss_dev_dbg(iface->idev, "Disabling all channels for %s", iface->name);

	ioss_for_each_channel(ch, iface)
		rc |= __ioss_net_disable_channel(ch);

	return rc;
}

static int __ioss_net_setup_event(struct ioss_channel *ch)
{
	int rc;
	struct ioss_device *idev = ioss_ch_dev(ch);

	ioss_dev_dbg(ch->iface->idev,
			"Setting up event for channel %d", ch->id);

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
	return rc;
}

static int __ioss_net_teardown_event(struct ioss_channel *ch)
{
	int rc1, rc2;
	struct ioss_device *idev = ioss_ch_dev(ch);

	ioss_dev_dbg(ch->iface->idev,
			"Tearing down event for channel %d", ch->id);

	rc1 = ioss_dev_op(idev, disable_event, ch);
	if (rc1)
		ioss_dev_err(ch->iface->idev,
			"Failed to disable event for channel %d", ch->id);
	else
		ch->event.enabled = false;

	rc2 = ioss_dev_op(idev, release_event, ch);
	if (rc2)
		ioss_dev_err(ch->iface->idev,
			"Failed to dealloc event for channel %d", ch->id);
	else
		ch->event.allocated = false;

	if (rc1 || rc2)
		return -EFAULT;

	ioss_dev_log(ch->iface->idev,
		"Teared down event for channel %d", ch->id);

	return 0;
}

static int __setup_event_action(struct list_head *node)
{
	return __ioss_net_setup_event(
			container_of(node, struct ioss_channel, node));
}

static void __setup_event_revert(struct list_head *node)
{
	(void) __ioss_net_teardown_event(
			container_of(node, struct ioss_channel, node));
}

static int ioss_net_setup_events(struct ioss_interface *iface)
{
	ioss_dev_dbg(iface->idev, "Setting up all device events");

	return ioss_list_iter_action(&iface->channels,
			__setup_event_action, __setup_event_revert);
}

static int ioss_net_teardown_events(struct ioss_interface *iface)
{
	int rc = 0;
	struct ioss_channel *ch;

	ioss_dev_dbg(iface->idev, "Tearing down all device events");

	ioss_for_each_channel(ch, iface)
		rc |= __ioss_net_teardown_event(ch);

	return rc;
}

static void ioss_iface_set_online(struct ioss_interface *iface)
{
	int rc;

	if (iface->state != IOSS_IF_ST_OFFLINE) {
		ioss_dev_dbg(iface->idev,
			"Interface %s state is %s; required is %s",
			iface->name, if_st_s(iface),
			ioss_if_state_name(IOSS_IF_ST_OFFLINE));
		return;
	}

	ioss_dev_log(iface->idev, "Bringing up %s", iface->name);

	rc = ioss_net_alloc_channels(iface);
	if (rc) {
		ioss_dev_err(iface->idev, "Failed to allocate channels");
		goto err_alloc_channels;
	}

	rc = ioss_ipa_register(iface);
	if (rc) {
		ioss_dev_err(iface->idev, "Failed to register with IPA");
		goto err_ipa_register;
	}

	rc = ioss_net_setup_events(iface);
	if (rc) {
		ioss_dev_err(iface->idev, "Failed to setup events");
		goto err_setup_events;
	}

	rc = ioss_net_enable_channels(iface);
	if (rc) {
		ioss_dev_err(iface->idev, "Failed to enable channels");
		goto err_enable_channels;
	}

	rc = ioss_pci_disable_pc(iface->idev);
	if (rc) {
		ioss_dev_err(iface->idev, "Failed to disable PCI power collapse");
		goto err_disable_pc;
	}

	iface->state = IOSS_IF_ST_ONLINE;

	return;

err_disable_pc:
	ioss_net_disable_channels(iface);
err_enable_channels:
	ioss_net_teardown_events(iface);
err_setup_events:
	ioss_ipa_unregister(iface);
err_ipa_register:
	ioss_net_free_channels(iface);
err_alloc_channels:
	iface->state = IOSS_IF_ST_ERROR;

	return;
}

static void ioss_iface_set_offline(struct ioss_interface *iface)
{
	int rc;

	if (iface->state != IOSS_IF_ST_ONLINE) {
		ioss_dev_dbg(iface->idev,
			"Interface %s state is %s; required is %s",
			iface->name, if_st_s(iface),
			ioss_if_state_name(IOSS_IF_ST_ONLINE));
		return;
	}

	ioss_dev_log(iface->idev, "Bringing down %s", iface->name);

	iface->state = IOSS_IF_ST_OFFLINE;

	rc = ioss_pci_enable_pc(iface->idev);
	if (rc) {
		ioss_dev_err(iface->idev, "Failed to enable PCI power collapse");
		iface->state = IOSS_IF_ST_ERROR;
	}

	rc = ioss_net_disable_channels(iface);
	if (rc) {
		ioss_dev_err(iface->idev, "Failed to disable channels");
		iface->state = IOSS_IF_ST_ERROR;
	}

	rc = ioss_net_teardown_events(iface);
	if (rc) {
		ioss_dev_err(iface->idev, "Failed to teardown events");
		iface->state = IOSS_IF_ST_ERROR;
	}

	rc = ioss_ipa_unregister(iface);
	if (rc) {
		ioss_dev_err(iface->idev, "Failed to unregister with IPA");
		iface->state = IOSS_IF_ST_ERROR;
	}

	rc = ioss_net_free_channels(iface);
	if (rc) {
		ioss_dev_err(iface->idev, "Failed to release channels");
		iface->state = IOSS_IF_ST_ERROR;
	}
}

static u32 __fetch_ethtool_link_speed(struct net_device *net_dev)
{
	int rc;
	struct ethtool_link_ksettings link_ksettings;

	rtnl_lock();
	rc = __ethtool_get_link_ksettings(net_dev, &link_ksettings);
	rtnl_unlock();

	if (!rc)
		return link_ksettings.base.speed;
	else
		return 0;
}

static void ioss_refresh_work(struct work_struct *work)
{
	struct ioss_interface *iface = ioss_refresh_work_to_iface(work);
	struct net_device *net_dev = ioss_iface_to_netdev(iface);
	struct ioss_device *idev = ioss_iface_dev(iface);
	struct device *dev = &idev->dev;

	if (!net_dev)
		return;

	ioss_dev_dbg(idev, "Refreshing interface %s", iface->name);

	iface->link_speed = __fetch_ethtool_link_speed(net_dev);

	if (netif_running(net_dev) && netif_carrier_ok(net_dev)
	    && !(dev->offline))
		ioss_iface_set_online(iface);
	else
		ioss_iface_set_offline(iface);

	ioss_dev_log(idev,
		"Interface %s state is %s", iface->name, if_st_s(iface));
}

static void ioss_net_active_work(struct work_struct *work)
{
	ioss_net_check_active(ioss_active_work_to_iface(work));
}

int ioss_net_watch_device(struct ioss_device *idev)
{
	int rc = 0;
	struct ioss_interface *iface;

	rc = ioss_debugfs_add_idev(idev);
	if (rc) {
		ioss_dev_err(idev, "Unable to add idev to debugfs");
		return -EFAULT;
	}

	ioss_for_each_iface(iface, idev) {
		INIT_WORK(&iface->refresh, ioss_refresh_work);
		iface->net_dev_nb.notifier_call = ioss_net_device_event;

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
	}

	return 0;

err_register:
	list_for_each_entry(iface, &idev->interfaces, node) {
		(void) unregister_netdevice_notifier(&iface->net_dev_nb);

		flush_work(&iface->refresh);

		cancel_delayed_work_sync(&iface->check_active);
		wakeup_source_unregister(iface->active_ws);
		iface->active_ws = NULL;
	}

	ioss_debugfs_remove_idev(idev);

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

		cancel_delayed_work_sync(&iface->check_active);
		wakeup_source_unregister(iface->active_ws);
		iface->active_ws = NULL;
	}

	ioss_debugfs_remove_idev(idev);

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

	ioss_dev_log(idev, "Linked to net device %s", net_dev->name);

	memset(&idev->drv_info, 0, sizeof(idev->drv_info));

	if (net_dev->ethtool_ops && net_dev->ethtool_ops->get_drvinfo)
		net_dev->ethtool_ops->get_drvinfo(net_dev, &idev->drv_info);

	ioss_dev_cfg(idev, "addr: %s, driver: %s %s, firmware: %s, erom: %s",
			idev->drv_info.bus_info,
			idev->drv_info.driver, idev->drv_info.version,
			idev->drv_info.fw_version, idev->drv_info.erom_version);

	return 0;
}
