/* SPDX-License-Identifier: GPL-2.0-only
 * Copyright (c) 2021, The Linux Foundation. All rights reserved.
 */

#include "ioss_i.h"

static int ioss_bus_match(struct device *dev, struct device_driver *drv)
{
	struct device *real_dev = dev->parent;
	struct ioss_driver *idrv = to_ioss_driver(drv);
	struct ioss_device *idev = to_ioss_device(dev);

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

	return 0;
}

static int ioss_bus_suspend(struct device *dev, pm_message_t state)
{
	struct ioss_device *idev = to_ioss_device(dev);

	ioss_dev_log(idev, "Suspending device");

	return 0;
}

static int ioss_bus_resume(struct device *dev)
{
	struct ioss_device *idev = to_ioss_device(dev);

	ioss_dev_log(idev, "Resuming device");

	return 0;
}

static int ioss_bus_online(struct device *dev)
{
	struct ioss_device *idev = to_ioss_device(dev);

	ioss_dev_log(idev, "Online device");

	return 0;
}

static int ioss_bus_offline(struct device *dev)
{
	struct ioss_device *idev = to_ioss_device(dev);

	ioss_dev_log(idev, "Offline device");

	return 0;
}

struct device_type ioss_pci_dev = {
	.name = "ioss-pci",
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

struct ioss_device *ioss_bus_alloc_device(struct ioss *ioss, struct device *dev)
{
	struct ioss_device *idev;

	idev = kzalloc(sizeof(*idev), GFP_KERNEL);
	if (!idev) {
		ioss_log_err(NULL, "Failed to alloc ioss device");
		return NULL;
	}

	idev->root = ioss;
	idev->dev.parent = dev;
	idev->dev.bus = &ioss_bus;
	mutex_init(&idev->pm_lock);
	refcount_set(&idev->pm_refcnt, 0);
	return idev;
}

void ioss_bus_free_device(struct ioss_device *idev)
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

int ioss_bus_register_device(struct ioss_device *idev)
{
	INIT_LIST_HEAD(&idev->interfaces);

	if (ioss_of_parse(idev)) {
		ioss_dev_err(idev, "Failed to parse devicetree");
		return -EINVAL;
	}

	return device_register(&idev->dev);
}

void ioss_bus_unregister_device(struct ioss_device *idev)
{
	device_unregister(&idev->dev);
}

static int __match_real_dev(struct device *dev, const void *data)
{
	struct device *ioss_dev = dev;
	const struct device *real_dev = data;

	return ioss_dev->parent == real_dev;
}

struct ioss_device *ioss_bus_find_dev(struct device *real_dev)
{
	struct device *ioss_dev =
		bus_find_device(&ioss_bus, NULL, real_dev, __match_real_dev);

	return ioss_dev ? to_ioss_device(ioss_dev) : NULL;
}
