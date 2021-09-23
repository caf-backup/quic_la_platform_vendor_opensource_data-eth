// SPDX-License-Identifier: GPL-2.0-only
/* Copyright (c) 2021, The Linux Foundation. All rights reserved.
 */

#ifndef _AQC_IOSS_H_
#define _AQC_IOSS_H_

#include <linux/module.h>
#include <linux/pci.h>
#include <linux/gfp.h>
#include <linux/slab.h>
#include <linux/device.h>
#include <linux/pm_wakeup.h>

#include <linux/msm/ioss.h>
#include <atl_fwd.h>
#include "aqc_regs.h"

struct aqc_ioss_device {
	struct atl_nic *nic;
	struct notifier_block nb;
	struct aqc_ioss_regs regs_save;
#if ATL_FWD_API_VERSION > 3
	struct atl_ext_stats stats;
#endif
};

#endif /* _AQC_IOSS_H_ */
