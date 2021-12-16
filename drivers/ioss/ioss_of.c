/* SPDX-License-Identifier: GPL-2.0-only
 * Copyright (c) 2021, The Linux Foundation. All rights reserved.
 */

#include <linux/of.h>
#include <linux/device.h>
#include <linux/platform_device.h>

#include "ioss_i.h"

typedef int (*of_parser_t)(struct ioss_device *idev, struct device_node *np);

static int ioss_of_parse_channel(struct ioss_device *idev,
		struct device_node *np)
{
	const char *key;
	struct ioss_channel *ch = NULL;
	struct ioss_interface *iface = &idev->interface;

	ch = kzalloc(sizeof(*ch), GFP_KERNEL);
	if (!ch)
		return -ENOMEM;

	ch->ioss_priv = kzalloc(sizeof(struct ioss_ch_priv), GFP_KERNEL);
	if (!ch->ioss_priv) {
		kfree(ch);
		return -ENOMEM;
	}

	INIT_LIST_HEAD(&ch->node);
	INIT_LIST_HEAD(&ch->desc_mem);
	INIT_LIST_HEAD(&ch->buff_mem);

	ch->iface = iface;

	if (!!of_find_property(np, "qcom,dir-rx", NULL))
		ch->direction = IOSS_CH_DIR_RX;
	else if (!!of_find_property(np, "qcom,dir-tx", NULL))
		ch->direction = IOSS_CH_DIR_TX;
	else
		goto err;

	key = "qcom,ring-size";
	if (of_property_read_u32(np, key, &ch->default_config.ring_size)) {
		ioss_dev_err(idev, "Failed to parse key %s", key);
		goto err;
	}

	key = "qcom,buff-size";
	if (of_property_read_u32(np, key, &ch->default_config.buff_size)) {
		ioss_dev_err(idev, "Failed to parse key %s", key);
		goto err;
	}

	key = "qcom,mod-count-min";
	if (of_property_read_u32(np, key, &ch->event.mod_count_min)) {
		ioss_dev_err(idev, "Failed to parse key %s", key);
		goto err;
	}

	key = "qcom,mod-count-max";
	if (of_property_read_u32(np, key, &ch->event.mod_count_max)) {
		ioss_dev_err(idev, "Failed to parse key %s", key);
		goto err;
	}

	key = "qcom,mod-usecs-min";
	if (of_property_read_u32(np, key, &ch->event.mod_usecs_min)) {
		ioss_dev_err(idev, "Failed to parse key %s", key);
		goto err;
	}

	key = "qcom,mod-usecs-max";
	if (of_property_read_u32(np, key, &ch->event.mod_usecs_max)) {
		ioss_dev_err(idev, "Failed to parse key %s", key);
		goto err;
	}

	if (!!of_find_property(np, "qcom,rx-filter-be", NULL))
		ch->filter_types |= IOSS_RXF_F_BE;

	if (!!of_find_property(np, "qcom,rx-filter-ip", NULL))
		ch->filter_types |= IOSS_RXF_F_IP;

	ch->default_config.desc_alctr = &ioss_default_alctr;
	ch->default_config.buff_alctr = &ioss_default_alctr;

	list_add_tail(&ch->node, &iface->channels);

	return 0;

err:
	kfree(ch->ioss_priv);
	kfree(ch);

	return -EINVAL;
}

static int ioss_of_parse_v2(struct ioss_device *idev, struct device_node *np)
{
	int i, count;
	const char *key;
	struct ioss_interface *iface = &idev->interface;

	iface->ioss_priv = kzalloc(sizeof(struct ioss_iface_priv), GFP_KERNEL);
	if (!iface->ioss_priv)
		return -ENOMEM;

	key = "qcom,ioss_instance";
	if (of_property_read_u32(np, key, &iface->instance_id)) {
		ioss_dev_log(idev, "Failed to parse key %s", key);
		goto err;
	}

	/* Parse channels */
	key = "qcom,ioss_channels";
	count = of_count_phandle_with_args(np, "qcom,ioss_channels", NULL);
	if (count < 0) {
		ioss_dev_err(idev, "Failed to parse key %s", key);
		goto err;
	}

	/* Get channels */
	for (i = 0; i < count; i++) {
		struct device_node *n = of_parse_phandle(np,
						"qcom,ioss_channels", i);

		if (ioss_of_parse_channel(idev, n)) {
			ioss_dev_err(idev, "Failed to parse channel[%d]", i);
			goto err;
		}
	}

	if (!!of_find_property(np, "qcom,ioss-wol-phy", NULL))
		idev->wol.wolopts |= WAKE_PHY;

	if (!!of_find_property(np, "qcom,ioss-wol-magic", NULL))
		idev->wol.wolopts |= WAKE_MAGIC;

	return 0;

err:
	{
		struct ioss_channel *ch, *tmp_ch;

		list_for_each_entry_safe(ch, tmp_ch, &iface->channels, node) {
			list_del(&ch->node);
			kzfree(ch->ioss_priv);
			kzfree(ch);
		}
	}

	kfree(iface->ioss_priv);

	return -EINVAL;
}

static const struct of_device_id ioss_dev_match_table[] = {
	{ .compatible = "qcom,ioss-v2-device", .data = ioss_of_parse_v2, },
	{},
};

static int __ioss_of_parse(struct ioss_device *idev, struct device_node *np)
{
	const struct of_device_id *match =
		of_match_node(ioss_dev_match_table, np);

	if (match) {
		of_parser_t parser = match->data;

		return parser(idev, np);
	}

	return -EINVAL;
}

int ioss_of_parse(struct ioss_device *idev)
{
	const char *key;
	struct device_node *of_root;
	struct platform_device *pdev;
	struct device_node *np = dev_of_node(idev->dev.parent);

	if (!np)
		return -EINVAL;

	/* Get ioss root */
	key = "qcom,ioss";
	of_root = of_parse_phandle(np, key, 0);
	if (!of_root) {
		ioss_dev_dbg(idev, "DT prop %s not found, skipping.", key);
		return -ENOENT;
	}

	pdev = ioss_find_dev_from_of_node(of_root);
	if (!pdev) {
		ioss_dev_err(idev, "Failed to find ioss root node");
		return -EFAULT;
	}

	if (idev->root->pdev != pdev) {
		ioss_dev_dbg(idev, "Device belongs to a different root");
		return -ENOENT;
	}

	return __ioss_of_parse(idev, np);
}
