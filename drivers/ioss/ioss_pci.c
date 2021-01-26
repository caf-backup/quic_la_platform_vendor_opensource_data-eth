/* SPDX-License-Identifier: GPL-2.0-only
 * Copyright (c) 2021, The Linux Foundation. All rights reserved.
 */

#include <linux/pci.h>
#include <linux/device.h>
#include <linux/platform_device.h>

#include <linux/msm_pcie.h>

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

static int ioss_pci_suspend_handler(struct device *dev)
{
	int rc;

	/* When offload is started, PCI power collapse is already disabled by
	 * the ioss_iface_set_online() api. Nonetheless, we still need to do
	 * a dummy PCI config space save so that the PCIe framework will not by
	 * itself perform a config space save-restore.
	 */

	ioss_log_dbg(NULL,
		   "Device suspend performing dummy config space save");

	rc = pci_save_state(to_pci_dev(dev));

	if (rc)
		ioss_log_err(NULL, "Device suspend failed");
	else
		ioss_log_dbg(NULL, "Device suspend complete");

	return rc;
}

static int ioss_pci_resume_handler(struct device *dev)
{

	/* During suspend, RC power collapse would not have happened if offload
	 * was started. Ignore resume callback since the device does not need
	 * to be re-initialized.
	 */

	ioss_log_dbg(NULL,
		"Device resume performing nop");

	return 0;
}

/* MSM PCIe driver invokes only suspend and resume callbacks, other operations
 * can be ignored unless we see a client requiring the feature.
 */

static const struct dev_pm_ops ioss_pci_pm_ops = {
	.suspend = ioss_pci_suspend_handler,
	.resume = ioss_pci_resume_handler,
};

int ioss_pci_enable_pc(struct ioss_device *idev)
{
	int rc;
	struct device *dev = ioss_to_real_dev(idev);
	struct pci_dev *pci_dev = to_pci_dev(dev);

	rc = msm_pcie_pm_control(MSM_PCIE_ENABLE_PC,
		pci_dev->bus->number, pci_dev, NULL, MSM_PCIE_CONFIG_INVALID);

	if (rc) {
		ioss_dev_err(idev,
			"Failed to enable MSM PCIe power collapse");
		return rc;
	}

	ioss_dev_log(idev, "Enabled MSM PCIe power collapse");

	mutex_lock(&idev->pm_lock);
	/* Revert Hijack pm_ops */
	if (refcount_dec_and_test(&idev->pm_refcnt))
		dev->driver->pm = idev->pm_ops_real;
	mutex_unlock(&idev->pm_lock);

	return rc;
}

int ioss_pci_disable_pc(struct ioss_device *idev)
{
	int rc;
	struct device *dev = ioss_to_real_dev(idev);
	struct pci_dev *pci_dev = to_pci_dev(dev);

	rc = msm_pcie_pm_control(MSM_PCIE_DISABLE_PC,
		pci_dev->bus->number, pci_dev, NULL, MSM_PCIE_CONFIG_INVALID);

	if (rc) {
		ioss_dev_log(idev,
			"Failed to disable MSM PCIe power collapse");
		return rc;
	}

	ioss_dev_log(idev, "Disabled MSM PCIe power collapse");

	mutex_lock(&idev->pm_lock);
	/* Hijack pm_ops */
	if (!refcount_inc_not_zero(&idev->pm_refcnt)) {
		idev->pm_ops_real = dev->driver->pm;
		dev->driver->pm = &ioss_pci_pm_ops;
		refcount_set(&idev->pm_refcnt, 1);
	}
	mutex_unlock(&idev->pm_lock);

	return rc;
}
