/* SPDX-License-Identifier: GPL-2.0-only
 * Copyright (c) 2021, The Linux Foundation. All rights reserved.
 */

#include "ioss_i.h"

/* Wake lock duration to allow the device to settle after a resume */
#define IOSS_RESUME_SETTLE_MS 5000

static int ioss_bus_match(struct device *dev, struct device_driver *drv)
{
	struct device *real_dev = dev->parent;
	struct ioss_driver *idrv = to_ioss_driver(drv);
	struct ioss_device *idev = to_ioss_device(dev);

	if (dev->type != &ioss_idev_type)
		return false;

	ioss_dev_dbg(idev, "Matching against %s", idrv->name);

	/* If a match function is provided by the IOSS driver, use that for
	 * matching the device driver with the IOSS driver. Otherwise use a
	 * simple name matching against the IOSS driver name.
	 */
	return idrv->match ?
			idrv->match(real_dev) :
			!strcmp(idrv->name, real_dev->driver->name);
}

static int ioss_bus_probe(struct device *dev)
{
	int rc;
	struct ioss_device *idev = to_ioss_device(dev);

	ioss_dev_log(idev, "Initializing device for offload");

	device_init_wakeup(dev, true);

	rc = ioss_net_link_device(idev);
	if (rc) {
		ioss_dev_err(idev, "Failed to link to net device");
		return rc;
	}

	rc = ioss_dev_op(idev, open_device, idev);
	if (rc) {
		ioss_dev_err(idev, "Failed to open device");
		goto err_open;
	}

	rc = ioss_net_watch_device(idev);
	if (rc) {
		ioss_dev_err(idev, "Failed to watch interfaces");
		goto err_watch;
	}

	return 0;

err_watch:
	ioss_dev_op(idev, close_device, idev);
err_open:
	return -EFAULT;
}

static int ioss_bus_remove(struct device *dev)
{
	int rc;
	struct ioss_device *idev = to_ioss_device(dev);

	ioss_dev_log(idev, "De-initializing device");

	rc = ioss_net_unwatch_device(idev);
	if (rc) {
		ioss_dev_err(idev, "Failed to unwatch device");
		return rc;
	}

	rc = ioss_dev_op(idev, close_device, idev);
	if (rc) {
		ioss_dev_err(idev, "Failed to close device");
		return rc;
	}

	device_init_wakeup(dev, false);

	return 0;
}

static int __ioss_bus_suspend_idev(struct device *dev, pm_message_t state)
{
	struct ioss_device *idev = to_ioss_device(dev);

	ioss_dev_log(idev, "Suspending device");

	return 0;
}

static int __ioss_bus_resume_idev(struct device *dev)
{
	bool need_refresh = false;
	bool was_suspended = true;
	struct ioss_interface *iface;
	struct ioss_device *idev = to_ioss_device(dev);

	ioss_dev_log(idev, "Resuming device");

	if (dev->offline) {
		dev->offline = 0;
		need_refresh = true;
	}

	ioss_for_each_iface(iface, idev) {
		if (iface->state == IOSS_IF_ST_ONLINE)
			was_suspended = false;

		if (need_refresh)
			ioss_iface_queue_refresh(iface, false);
	}

	if (was_suspended)
		pm_wakeup_dev_event(dev, IOSS_RESUME_SETTLE_MS, false);

	return 0;
}

static int __ioss_bus_online_idev(struct device *dev)
{
	struct ioss_device *idev;
	struct ioss_interface *iface;

	dev->offline = 0;
	idev = to_ioss_device(dev);

	ioss_for_each_iface(iface, idev)
		ioss_iface_queue_refresh(iface, true);

	ioss_dev_log(idev, "Online device");

	return 0;
}

static int __ioss_bus_offline_idev(struct device *dev)
{
	struct ioss_device *idev;
	struct ioss_interface *iface;

	dev->offline = 1;
	idev = to_ioss_device(dev);

	ioss_for_each_iface(iface, idev)
		ioss_iface_queue_refresh(iface, true);

	ioss_dev_log(idev, "Offline device");

	return 0;
}

static int ioss_bus_suspend(struct device *dev, pm_message_t state)
{
	if (dev->type == &ioss_idev_type)
		return __ioss_bus_suspend_idev(dev, state);

	return 0;
}

static int ioss_bus_resume(struct device *dev)
{
	if (dev->type == &ioss_idev_type)
		return __ioss_bus_resume_idev(dev);

	return 0;
}

static int ioss_bus_online(struct device *dev)
{
	if (dev->type == &ioss_idev_type)
		return __ioss_bus_online_idev(dev);

	return 0;
}

static int ioss_bus_offline(struct device *dev)
{
	if (dev->type == &ioss_idev_type)
		return __ioss_bus_offline_idev(dev);

	return 0;
}

struct device_type ioss_idev_type = {
	.name = "ioss_device",
};

struct device_type ioss_iface_type = {
	.name = "ioss_interface",
};

struct bus_type ioss_bus = {
	.name = "ioss",
	.match = ioss_bus_match,
	.probe = ioss_bus_probe,
	.remove = ioss_bus_remove,
	.suspend = ioss_bus_suspend,
	.resume = ioss_bus_resume,
	.online = ioss_bus_online,
	.offline = ioss_bus_offline,
};

int ioss_bus_register_driver(struct ioss_driver *idrv)
{
	idrv->drv.name = idrv->name;
	idrv->drv.bus = &ioss_bus;

	/* Init drv */
	/* Register driver */

	return driver_register(&idrv->drv);
}

void ioss_bus_unregister_driver(struct ioss_driver *idrv)
{
	driver_unregister(&idrv->drv);
}

struct ioss_device *ioss_bus_alloc_idev(struct ioss *ioss, struct device *dev)
{
	struct ioss_device *idev;

	idev = kzalloc(sizeof(*idev), GFP_KERNEL);
	if (!idev) {
		ioss_log_err(NULL, "Failed to alloc ioss device");
		return NULL;
	}

	idev->root = ioss;
	mutex_init(&idev->pm_lock);
	refcount_set(&idev->pm_refcnt, 0);
	INIT_LIST_HEAD(&idev->interfaces);

	idev->dev.parent = dev;
	idev->dev.bus = &ioss_bus;
	idev->dev.type = &ioss_idev_type;

	return idev;
}

void ioss_bus_free_idev(struct ioss_device *idev)
{
	struct ioss_interface *iface, *tmp_iface;

	/* Free interfaces and channels */
	list_for_each_entry_safe(iface, tmp_iface, &idev->interfaces, node) {
		struct ioss_channel *ch, *tmp_ch;

		list_for_each_entry_safe(ch, tmp_ch, &iface->channels, node) {
			list_del(&ch->node);
			kzfree(ch->ioss_priv);
			kzfree(ch);
		}

		list_del(&iface->node);
		kzfree(iface->ioss_priv);
		kzfree(iface);
	}
	mutex_destroy(&idev->pm_lock);
	kzfree(idev);
}

int ioss_bus_register_idev(struct ioss_device *idev)
{
	if (ioss_of_parse(idev)) {
		ioss_dev_err(idev, "Failed to parse devicetree");
		return -EINVAL;
	}

	return device_register(&idev->dev);
}

void ioss_bus_unregister_idev(struct ioss_device *idev)
{
	device_unregister(&idev->dev);
}

int ioss_bus_register_iface(struct ioss_interface *iface,
		struct net_device *net_dev)
{
	dev_hold(net_dev);

	iface->dev.parent = &net_dev->dev;
	iface->dev.bus = &ioss_bus;
	iface->dev.type = &ioss_iface_type;

	dev_set_name(&iface->dev, "%s-%s",
			dev_name(&iface->idev->dev), net_dev->name);

	return device_register(&iface->dev);
}

void ioss_bus_unregister_iface(struct ioss_interface *iface)
{
	struct net_device *net_dev = ioss_iface_to_netdev(iface);

	device_unregister(&iface->dev);
	iface->dev.parent = NULL;
	dev_put(net_dev);
}
