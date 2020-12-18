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

struct ioss_ipa_map ioss_ipa_map_table[IPA_ETH_CLIENT_MAX] = {
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
