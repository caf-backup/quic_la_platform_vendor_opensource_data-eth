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

	struct pci_dev *pdev = to_pci_dev(ioss_idev_to_real(ch->iface->idev));

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

/* AQC HAL implementation */
#define AQC_RX_TAIL_PTR_OFFSET 0x00005B10
#define AQC_RX_TAIL_PTR(base, idx) \
	((base) + AQC_RX_TAIL_PTR_OFFSET + ((idx) * 0x20))

#define AQC_RX_HEAD_PTR_OFFSET 0x00005B0C
#define AQC_RX_HEAD_PTR(base, idx) \
	((base) + AQC_RX_HEAD_PTR_OFFSET + ((idx) * 0x20))

#define AQC_TX_TAIL_PTR_OFFSET 0x00007C10
#define AQC_TX_TAIL_PTR(base, idx) \
	((base) + AQC_TX_TAIL_PTR_OFFSET + ((idx) * 0x40))

#define AQC_TX_HEAD_PTR_OFFSET 0x00007C0C
#define AQC_TX_HEAD_PTR(base, idx) \
	((base) + AQC_TX_HEAD_PTR_OFFSET + ((idx) * 0x40))

static int fill_aqc_si(enum ipa_eth_client_type ctype, struct ioss_channel *ch)
{

	struct ioss_ch_priv *cp = ch->ioss_priv;
	struct ipa_eth_pipe_setup_info *si = &cp->ipa_pi.info;
	struct ipa_eth_aqc_setup_info *aqc = &si->client_info.aqc;
	static const int AQC_BAR_MMIO = 0;

	struct pci_dev *pdev = to_pci_dev(ioss_idev_to_real(ch->iface->idev));

	aqc->bar_addr = pci_resource_start(pdev, AQC_BAR_MMIO);
	aqc->aqc_ch = ch->id;

	ioss_dev_log(ch->iface->idev, "AQC: bar=%pap, q=%u\n",
		&aqc->bar_addr, aqc->aqc_ch);

	if (ch->direction == IOSS_CH_DIR_TX) {
		aqc->head_ptr_offs = AQC_TX_HEAD_PTR(0, ch->id);
		aqc->dest_tail_ptr_offs = AQC_TX_TAIL_PTR(0, ch->id);
	} else {
		aqc->head_ptr_offs = AQC_RX_HEAD_PTR(0, ch->id);
		aqc->dest_tail_ptr_offs = AQC_RX_TAIL_PTR(0, ch->id);
	}

	return 0;
}

static bool match_aqc(struct device *real_dev)
{
	return (real_dev->bus == &pci_bus_type) &&
		!strcmp(to_pci_driver(real_dev->driver)->name, "atlantic-fwd");
}

struct ioss_ipa_map ioss_ipa_map_table[IPA_ETH_CLIENT_MAX] = {
	[IPA_ETH_CLIENT_RTK8125B] = { match_r8125, fill_r8125_si },
	[IPA_ETH_CLIENT_AQC107] = { match_aqc, fill_aqc_si },
};

enum ipa_eth_client_type ioss_ipa_hal_get_ctype(struct ioss_interface *iface)
{
	enum ipa_eth_client_type ctype;
	struct device *real_dev = ioss_idev_to_real(iface->idev);

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
