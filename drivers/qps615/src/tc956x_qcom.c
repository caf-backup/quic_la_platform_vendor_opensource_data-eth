// SPDX-License-Identifier: GPL-2.0-only
// Copyright (c) 2021, The Linux Foundation. All rights reserved.

#include <linux/kernel.h>
#include <linux/device.h>
#include <linux/pinctrl/consumer.h>

#include "tc956xmac.h"

struct tc956x_qcom_priv {
	struct pinctrl *pinctrl;
	struct pinctrl_state *pinctrl_default;
};

int tc956x_platform_probe(struct tc956xmac_priv *priv,
			  struct tc956xmac_resources *res)
{
	int ret = 0;
	struct tc956x_qcom_priv *qpriv;

	dev_dbg(priv->device, "QPS615 platform probing has started\n");

	qpriv = kzalloc(sizeof(*qpriv), GFP_KERNEL);
	if (!qpriv) {
		dev_dbg(priv->device, "Failed to allocate memory for qpriv, exiting\n");
		return -ENOMEM;
	}

	priv->plat_priv = qpriv;

	qpriv->pinctrl = devm_pinctrl_get(priv->device);
	if (IS_ERR_OR_NULL(qpriv->pinctrl)) {
		dev_err(priv->device, "Failed to get pinctrl handle\n");
		goto clean_up;
	}

	qpriv->pinctrl_default = pinctrl_lookup_state(qpriv->pinctrl, PINCTRL_STATE_DEFAULT);
	if (IS_ERR_OR_NULL(qpriv->pinctrl_default)) {
		dev_err(priv->device, "Failed to look up 'default' pinctrl state\n");
		goto clean_up;
	}

	ret = pinctrl_select_state(qpriv->pinctrl, qpriv->pinctrl_default);
	if (ret) {
		dev_err(priv->device, "Failed to select the 'default' pincrl state\n");
		goto clean_up;
	}

	dev_info(priv->device, "QPS615 platform probing has finished successfully\n");
	return 0;

clean_up:
	if (qpriv->pinctrl)
		devm_pinctrl_put(qpriv->pinctrl);
	kzfree(qpriv);
	priv->plat_priv = NULL;
	return -EINVAL;
}

int tc956x_platform_remove(struct tc956xmac_priv *priv)
{
	struct tc956x_qcom_priv *qpriv = (struct tc956x_qcom_priv *)priv->plat_priv;

	dev_dbg(priv->device, "Freeing QPS615 platform resources\n");

	devm_pinctrl_put(qpriv->pinctrl);
	kzfree(priv->plat_priv);
	priv->plat_priv = NULL;

	return 0;
}

int tc956x_platform_suspend(struct tc956xmac_priv *priv)
{
	return 0;
}

int tc956x_platform_resume(struct tc956xmac_priv *priv)
{
	return 0;
}
