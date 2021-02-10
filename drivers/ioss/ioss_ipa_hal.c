/* SPDX-License-Identifier: GPL-2.0-only
 * Copyright (c) 2021, The Linux Foundation. All rights reserved.
 */

#include <linux/pci.h>

#include "ioss_i.h"

struct ioss_ipa_map {
	bool (*match_dev)(struct device *real_dev);
	int (*fill_si)(enum ipa_eth_client_type ctype,
				struct ioss_channel *ch);
};

/* Realtek R8125 HAL implementation */

static int __fill_r8125_si(struct ioss_channel *ch,
		struct ipa_eth_realtek_setup_info *rtk)
{
	static const int RTL8125_BAR_MMIO = 2;
	static const int RTL8125_TAIL_PTR_BASE = 0x2800;
	static const int RTL8125_TAIL_PTR_NEXT = 4;

	struct pci_dev *pdev = to_pci_dev(ioss_to_real_dev(ch->iface->idev));

	rtk->bar_addr = pci_resource_start(pdev, RTL8125_BAR_MMIO);
	rtk->bar_size = pci_resource_len(pdev, RTL8125_BAR_MMIO);
	rtk->queue_number = ch->id;

	if (ch->direction == IOSS_CH_DIR_TX)
		rtk->dest_tail_ptr_offs = RTL8125_TAIL_PTR_BASE +
					(ch->id * RTL8125_TAIL_PTR_NEXT);

	return 0;
}

static int fill_r8125_si(enum ipa_eth_client_type ctype,
		struct ioss_channel *ch)
{
	struct ioss_ch_priv *cp = ch->ioss_priv;
	struct ipa_eth_pipe_setup_info *si = &cp->ipa_pi.info;

	return __fill_r8125_si(ch, &si->client_info.rtk);
}

static bool match_r8125(struct device *real_dev)
{
	return (real_dev->bus == &pci_bus_type) &&
		!strcmp(to_pci_driver(real_dev->driver)->name, "r8125");
}

struct ioss_ipa_map ioss_ipa_map_table[IPA_ETH_CLIENT_MAX] = {
	[IPA_ETH_CLIENT_RTK8125B] = { match_r8125, fill_r8125_si },
};

enum ipa_eth_client_type ioss_ipa_hal_get_ctype(struct ioss_interface *iface)
{
	enum ipa_eth_client_type ctype;
	struct device *real_dev = ioss_to_real_dev(iface->idev);

	for (ctype = 0; ctype < IPA_ETH_CLIENT_MAX; ctype++) {
		if (!ioss_ipa_map_table[ctype].match_dev)
			continue;

		if (ioss_ipa_map_table[ctype].match_dev(real_dev))
			break;
	}

	return ctype;
}

int ioss_ipa_hal_fill_si(struct ioss_channel *ch)
{
	enum ipa_eth_client_type ctype = ioss_ipa_hal_get_ctype(ch->iface);

	if (ctype < IPA_ETH_CLIENT_MAX && ioss_ipa_map_table[ctype].fill_si)
		return ioss_ipa_map_table[ctype].fill_si(ctype, ch);

	return -EINVAL;
}
