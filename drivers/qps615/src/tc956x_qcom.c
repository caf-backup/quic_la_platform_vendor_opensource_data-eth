// SPDX-License-Identifier: GPL-2.0-only
// Copyright (c) 2021, The Linux Foundation. All rights reserved.

#include <linux/kernel.h>
#include <linux/device.h>
#include <linux/pinctrl/consumer.h>
#include <linux/regulator/consumer.h>
#include <linux/of_irq.h>

#include "tc956xmac.h"

struct tc956x_qcom_priv {
	struct pinctrl *pinctrl;
	struct pinctrl_state *pinctrl_default;
	struct regulator *phy_supply;
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
		goto err_pinctrl_get;
	}

	qpriv->pinctrl_default = pinctrl_lookup_state(qpriv->pinctrl, PINCTRL_STATE_DEFAULT);
	if (IS_ERR_OR_NULL(qpriv->pinctrl_default)) {
		dev_err(priv->device, "Failed to look up 'default' pinctrl state\n");
		goto err_pinctrl_lookup_state;
	}

	ret = pinctrl_select_state(qpriv->pinctrl, qpriv->pinctrl_default);
	if (ret) {
		dev_err(priv->device, "Failed to select the 'default' pincrl state\n");
		goto err_pinctrl_select_state;
	}

	res->wol_irq = of_irq_get_byname(priv->device->of_node, "wol_irq");
	if (res->wol_irq <= 0) {
		dev_err(priv->device, "Failed to get 'wol_irq' IRQ with error %d\n", res->wol_irq);
		goto err_get_irq_byname;
	}

	dev_dbg(priv->device, "Successfully found WOL IRQ number %d\n", res->wol_irq);

	ret = irq_set_irq_wake(res->wol_irq, 1);
	if (unlikely(ret)) {
		dev_err(priv->device, "Failed to set WOL IRQ %d as wake up capable with error %d\n", res->wol_irq, ret);
		goto err_set_irq_wake;
	}

	qpriv->phy_supply = devm_regulator_get(priv->device, "phy");
	if (IS_ERR(qpriv->phy_supply)) {
			dev_err(priv->device, "Failed to acquire supply 'phy-supply': %d\n", ret);
			goto err_regulator_get;
	}

	ret = regulator_enable(qpriv->phy_supply);
	if (ret) {
		dev_err(priv->device, "Failed to enable phy supply: %d\n", ret);
		goto err_regulator_enable;
	}

	dev_info(priv->device, "QPS615 platform probing has finished successfully\n");

	return 0;

err_regulator_enable:
	devm_regulator_put(qpriv->phy_supply);

err_regulator_get:
	irq_set_irq_wake(res->wol_irq, 0);

err_set_irq_wake:
err_get_irq_byname:
err_pinctrl_select_state:
err_pinctrl_lookup_state:
	devm_pinctrl_put(qpriv->pinctrl);

err_pinctrl_get:
	kzfree(qpriv);
	priv->plat_priv = NULL;
	return -EINVAL;
}

int tc956x_platform_remove(struct tc956xmac_priv *priv)
{
	struct tc956x_qcom_priv *qpriv = (struct tc956x_qcom_priv *)priv->plat_priv;

	dev_dbg(priv->device, "Freeing QPS615 platform resources\n");

	regulator_disable(qpriv->phy_supply);
	devm_regulator_put(qpriv->phy_supply);

	irq_set_irq_wake(priv->wol_irq, 0);
	devm_pinctrl_put(qpriv->pinctrl);
	kzfree(priv->plat_priv);
	priv->plat_priv = NULL;

	return 0;
}

int tc956x_platform_suspend(struct tc956xmac_priv *priv)
{
	struct tc956x_qcom_priv *qpriv = (struct tc956x_qcom_priv *)priv->plat_priv;

	if(priv->wolopts == 0)
		regulator_disable(qpriv->phy_supply);

	return 0;
}

int tc956x_platform_resume(struct tc956xmac_priv *priv)
{
	int ret;
	struct tc956x_qcom_priv *qpriv = (struct tc956x_qcom_priv *)priv->plat_priv;

	ret = regulator_enable(qpriv->phy_supply);
	if (ret) {
		dev_err(priv->device, "Failed to enable phy supply: %d\n", ret);
		return ret;
	}

	return 0;
}
