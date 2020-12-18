/* SPDX-License-Identifier: GPL-2.0-only
 * Copyright (c) 2021, The Linux Foundation. All rights reserved.
 */

#include <linux/pci.h>
#include <linux/device.h>
#include <linux/platform_device.h>

#include "ioss_i.h"

int __ioss_pci_register_driver(struct ioss_driver *idrv, struct module *owner)
{
	ioss_log_cfg(NULL, "Registering PCI driver %s", idrv->name);

	idrv->drv.owner = owner;

	/* Init PCI driver attributes here */

	return ioss_bus_register_driver(idrv);
}
EXPORT_SYMBOL(__ioss_pci_register_driver);

void ioss_pci_unregister_driver(struct ioss_driver *idrv)
{
	ioss_log_cfg(NULL, "Unregistering PCI driver %s", idrv->name);

	ioss_bus_unregister_driver(idrv);
}
EXPORT_SYMBOL(ioss_pci_unregister_driver);

static int ioss_pci_add_device(struct pci_dev *pdev, struct ioss *ioss)
{
	int rc;
	struct ioss_device *idev;

	ioss_log_cfg(NULL, "Adding device %s", dev_name(&pdev->dev));

	idev = ioss_bus_alloc_device(ioss, &pdev->dev);
	if (!idev)
		return -ENOMEM;

	idev->dev.type = &ioss_pci_dev;
	dev_set_name(&idev->dev, "pci:%s", dev_name(idev->dev.parent));

	rc = ioss_bus_register_device(idev);
	if (rc) {
		ioss_dev_err(idev, "Failed to register device with ioss bus");
		ioss_bus_free_device(idev);
		return rc;
	}

	return 0;
}

static int ioss_pci_remove_device(struct pci_dev *pdev, struct ioss *ioss)
{
	struct ioss_device *idev = ioss_bus_find_dev(&pdev->dev);

	if (!idev)
		return -ENODEV;

	ioss_dev_log(idev, "Removing device %s", dev_name(idev->dev.parent));

	ioss_bus_unregister_device(idev);
	ioss_bus_free_device(idev);

	return 0;
}

static int pci_bus_notification(struct notifier_block *nb,
		unsigned long action, void *data)
{
	struct pci_dev *pdev = to_pci_dev(data);
	struct ioss *ioss = container_of(nb, typeof(*ioss), pci_bus_nb);
	struct device *dev = &pdev->dev;

	ioss_log_dbg(NULL, "PCIe bus notif: %lu device: %s, driver: %s",
			action, dev_name(dev), dev_driver_string(dev));

	switch (action) {
	case BUS_NOTIFY_BOUND_DRIVER:
		ioss_pci_add_device(pdev, ioss);
		break;
	case BUS_NOTIFY_UNBIND_DRIVER:
		ioss_pci_remove_device(pdev, ioss);
		break;
	}

	return NOTIFY_OK;
}

static int __pcie_walk_add_device(struct device *dev, void *data)
{
	struct ioss *ioss = data;

	ioss_log_dbg(NULL, "PCIe walk add device: %s, driver: %s",
			dev_name(dev), dev_driver_string(dev));

	/* Call BUS_NOTIFY_BOUND_DRIVER if the device is already bound to a
	 * driver.
	 */
	if (dev->driver)
		pci_bus_notification(&ioss->pci_bus_nb,
				BUS_NOTIFY_BOUND_DRIVER, dev);

	return 0;
}

int ioss_pci_start(struct ioss *ioss)
{
	int rc;

	ioss_log_cfg(NULL, "Starting PCI");

	ioss->pci_bus_nb.notifier_call = pci_bus_notification;
	rc = bus_register_notifier(&pci_bus_type, &ioss->pci_bus_nb);
	if (rc) {
		ioss_log_err(NULL, "Failed to register PCI bus notifier");
		return rc;
	}

	/* Manually scan all existing PCI devices */
	bus_for_each_dev(&pci_bus_type, NULL, ioss, __pcie_walk_add_device);

	return 0;
}

static int __pcie_walk_del_device(struct device *dev, void *data)
{
	struct ioss *ioss = data;

	ioss_log_dbg(NULL, "PCIe walk del device: %s, driver: %s",
			dev_name(dev), dev_driver_string(dev));

	if (dev->driver)
		pci_bus_notification(&ioss->pci_bus_nb,
				BUS_NOTIFY_UNBIND_DRIVER, dev);

	return 0;
}

void ioss_pci_stop(struct ioss *ioss)
{
	ioss_log_cfg(NULL, "Stopping PCI");

	bus_unregister_notifier(&pci_bus_type, &ioss->pci_bus_nb);

	/* Unregister all devices. Drivers will be unregistered when
	 * the glue drivers are unloaded.
	 */
	bus_for_each_dev(&pci_bus_type, NULL, ioss, __pcie_walk_del_device);
}
