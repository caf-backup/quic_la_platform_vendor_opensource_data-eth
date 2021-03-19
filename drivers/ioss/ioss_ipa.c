/* SPDX-License-Identifier: GPL-2.0-only
 * Copyright (c) 2021, The Linux Foundation. All rights reserved.
 */

#include <linux/etherdevice.h>

#include "ioss_i.h"

static void ioss_ipa_notify_cb(void *priv,
					enum ipa_dp_evt_type evt,
					unsigned long data)
{
	struct ioss_channel *ch = priv;
	struct sk_buff *skb = (struct sk_buff *)data;
	struct net_device *net_dev = ch->iface->idev->net_dev;

	if (evt != IPA_RECEIVE)
		return;

	skb->protocol = eth_type_trans(skb, net_dev);

	netif_rx_ni(skb);
}

static int ioss_ipa_fill_pipe_info(struct ioss_channel *ch,
		struct ipa_eth_client_pipe_info *pi)
{
	struct ioss_mem *desc_mem;
	struct ioss_mem *buff_mem;
	struct ipa_eth_buff_smmu_map *sm;
	struct ipa_eth_pipe_setup_info *si = &pi->info;

	pi->dir = (ch->direction == IOSS_CH_DIR_TX) ?
			IPA_ETH_PIPE_DIR_TX : IPA_ETH_PIPE_DIR_RX;

	desc_mem = list_first_entry_or_null(
			&ch->desc_mem, typeof(*desc_mem), node);
	if (!desc_mem) {
		ioss_dev_err(ch->iface->idev, "Descriptor memory not found");
		return -EINVAL;
	}

	si->is_transfer_ring_valid = true;
	si->transfer_ring_base = desc_mem->daddr;
	si->transfer_ring_sgt = &desc_mem->sgt;
	si->transfer_ring_size = desc_mem->size;

	si->data_buff_list_size = ch->config.ring_size;
	si->data_buff_list = sm = kcalloc(si->data_buff_list_size,
			sizeof(*si->data_buff_list), GFP_KERNEL);
	if (!sm) {
		ioss_dev_err(ch->iface->idev,
			"Kmalloc failed for data buff list");
		return -EINVAL;
	}
	si->fix_buffer_size = ch->config.buff_size;

	list_for_each_entry(buff_mem, &ch->buff_mem, node) {
		sm->iova = buff_mem->daddr;
		sm->pa = ch->config.buff_alctr->pa(ioss_ch_dev(ch),
				buff_mem->addr, buff_mem->daddr,
				ch->config.buff_alctr);
		sm++;
	}

	if (pi->dir == IPA_ETH_PIPE_DIR_RX) {
		si->notify = ioss_ipa_notify_cb;
		si->priv = ch;
	}

	if (ioss_ipa_hal_fill_si(ch)) {
		ioss_dev_err(ch->iface->idev,
			"Failed to fill IPA pipe setup info");
		return -EINVAL;
	}

	return 0;
}

static void ioss_ipa_fill_eth_hdrs(struct ioss_interface *iface)
{
	struct ioss_iface_priv *ifp = iface->ioss_priv;
	struct ipa_eth_intf_info *ii = &ifp->ipa_ii;

	union ioss_ipa_eth_hdr *hdr_v4 = &ifp->ipa_hdr_v4;
	union ioss_ipa_eth_hdr *hdr_v6 = &ifp->ipa_hdr_v6;

	struct ipa_eth_hdr_info *hi_v4 = &ii->hdr[0];
	struct ipa_eth_hdr_info *hi_v6 = &ii->hdr[1];

	/* IPv4 */
	memcpy(hdr_v4->l2.h_source, iface->net_dev->dev_addr, ETH_ALEN);
	hdr_v4->l2.h_proto = htons(ETH_P_IP);

	hi_v4->hdr = (u8 *)hdr_v4;
	hi_v4->hdr_len = ETH_HLEN;
	hi_v4->hdr_type = IPA_HDR_L2_ETHERNET_II;

	/* IPv6 */
	memcpy(hdr_v6->l2.h_source, iface->net_dev->dev_addr, ETH_ALEN);
	hdr_v6->l2.h_proto = htons(ETH_P_IPV6);

	hi_v6->hdr = (u8 *)hdr_v6;
	hi_v6->hdr_len = ETH_HLEN;
	hi_v6->hdr_type = IPA_HDR_L2_ETHERNET_II;
}

static void ioss_ipa_fill_vlan_hdrs(struct ioss_interface *iface)
{
	struct ioss_iface_priv *ifp = iface->ioss_priv;
	struct ipa_eth_intf_info *ii = &ifp->ipa_ii;

	union ioss_ipa_eth_hdr *hdr_v4 = &ifp->ipa_hdr_v4;
	union ioss_ipa_eth_hdr *hdr_v6 = &ifp->ipa_hdr_v6;

	struct ipa_eth_hdr_info *hi_v4 = &ii->hdr[0];
	struct ipa_eth_hdr_info *hi_v6 = &ii->hdr[1];

	/* IPv4 */
	memcpy(hdr_v4->vlan.h_source, iface->net_dev->dev_addr, ETH_ALEN);
	hdr_v4->vlan.h_vlan_proto = htons(ETH_P_8021Q);
	hdr_v4->vlan.h_vlan_encapsulated_proto = htons(ETH_P_IP);

	hi_v4->hdr = (u8 *)hdr_v4;
	hi_v4->hdr_len = VLAN_ETH_HLEN;
	hi_v4->hdr_type = IPA_HDR_L2_802_1Q;

	/* IPv6 */
	memcpy(hdr_v6->vlan.h_source, iface->net_dev->dev_addr, ETH_ALEN);
	hdr_v6->vlan.h_vlan_proto = htons(ETH_P_8021Q);
	hdr_v6->vlan.h_vlan_encapsulated_proto = htons(ETH_P_IPV6);

	hi_v6->hdr = (u8 *)hdr_v6;
	hi_v6->hdr_len = VLAN_ETH_HLEN;
	hi_v6->hdr_type = IPA_HDR_L2_802_1Q;
}

static int ioss_ipa_fill_hdrs(struct ioss_interface *iface)
{
	bool ipa_vlan_mode = false;

	if (ipa_is_vlan_mode(IPA_VLAN_IF_EMAC, &ipa_vlan_mode)) {
		ioss_dev_err(iface->idev, "Failed to get IPA vlan mode");
		return -EINVAL;
	}

	if (ipa_vlan_mode)
		ioss_ipa_fill_vlan_hdrs(iface);
	else
		ioss_ipa_fill_eth_hdrs(iface);

	return 0;
}

static u32 __fetch_ethtool_link_speed(struct net_device *net_dev)
{
	int rc;
	struct ethtool_link_ksettings link_ksettings;

	rtnl_lock();
	rc = __ethtool_get_link_ksettings(net_dev, &link_ksettings);
	rtnl_unlock();

	if (!rc)
		return link_ksettings.base.speed;
	else
		return 0;
}

static int ioss_ipa_vote_bw(struct ioss_interface *iface)
{
	struct ipa_eth_perf_profile profile;
	struct ioss_iface_priv *ifp = iface->ioss_priv;
	struct ipa_eth_client *ec = &ifp->ipa_ec;
	u32 link_speed = __fetch_ethtool_link_speed(iface->net_dev);

	ioss_dev_dbg(iface->idev, "Voting IPA bandwidth");

	if (!link_speed) {
		ioss_dev_err(iface->idev,
				"Failed to retrieve ethernet link speed");
		return -EFAULT;
	}

	memset(&profile, 0, sizeof(profile));
	profile.max_supported_bw_mbps = link_speed;

	if (ipa_eth_client_set_perf_profile(ec, &profile)) {
		ioss_dev_err(iface->idev,
				"Failed to set IPA perf profile");
		return -EINVAL;
	}

	return 0;
}

static int __ioss_ipa_msg(struct net_device *net_dev, bool connect)
{
	struct ipa_ecm_msg msg;

	memset(&msg, 0, sizeof(msg));
	snprintf(msg.name, sizeof(msg.name), "%s", net_dev->name);
	msg.ifindex = net_dev->ifindex;

	return connect ?
		ipa_eth_client_conn_evt(&msg) :
		ipa_eth_client_disconn_evt(&msg);
}

static int ioss_ipa_msg_connect(struct net_device *net_dev)
{
	return __ioss_ipa_msg(net_dev, true);
}

static int ioss_ipa_msg_disconnect(struct net_device *net_dev)
{
	return __ioss_ipa_msg(net_dev, false);
}

int ioss_ipa_register(struct ioss_interface *iface)
{
	int i;
	int ch_count;
	struct ioss_iface_priv *ifp = iface->ioss_priv;
	struct ipa_eth_client *ec = &ifp->ipa_ec;
	struct ipa_eth_intf_info *ii = &ifp->ipa_ii;
	struct ioss_channel *ch;

	ec->priv = iface;
	ec->inst_id = iface->instance_id;
	ec->traffic_type = IPA_ETH_PIPE_BEST_EFFORT;
	ec->client_type = ioss_ipa_hal_get_ctype(iface);

	if (ec->client_type == IPA_ETH_CLIENT_MAX) {
		ioss_dev_err(iface->idev, "Failed to determine client type");
		return -EFAULT;
	}

	INIT_LIST_HEAD(&ec->pipe_list);

	ch_count = 0;
	ioss_for_each_channel(ch, iface) {
		struct ioss_ch_priv *cp = ch->ioss_priv;

		cp->ipa_pi.client_info = ec;

		if (ioss_ipa_fill_pipe_info(ch, &cp->ipa_pi)) {
			ioss_dev_err(iface->idev, "Failed to fill pipe info");
			return -EFAULT;
		}

		list_add_tail(&cp->ipa_pi.link, &ec->pipe_list);
		ch_count++;
	}
	ii->pipe_hdl_list_size = ch_count;

	ii->pipe_hdl_list = kcalloc(ii->pipe_hdl_list_size,
				sizeof(*ii->pipe_hdl_list), GFP_KERNEL);
	if (!ii->pipe_hdl_list) {
		ioss_dev_err(iface->idev, "Failed to alloc pipe hdl list");
		return -EINVAL;
	}

	ii->netdev_name = iface->net_dev->name;

	if (ioss_ipa_fill_hdrs(iface)) {
		ioss_dev_err(iface->idev, "Failed to fill partial headers");
		return -EINVAL;
	}

	/* connect pipes */
	if (ipa_eth_client_conn_pipes(ec)) {
		ioss_dev_err(iface->idev, "Failed to connect pipes");
		return -EINVAL;
	}

	/* vote for bw */
	if (ioss_ipa_vote_bw(iface)) {
		ioss_dev_err(iface->idev, "Failed to vote for bandwidth");
		return -EINVAL;
	}

	/* Retrieve output from conn_pipes call */
	i = 0;
	ioss_for_each_channel(ch, iface) {
		struct ioss_ch_priv *cp = ch->ioss_priv;
		struct ipa_eth_client_pipe_info *pi = &cp->ipa_pi;
		struct ipa_eth_pipe_setup_info *si = &pi->info;

		ch->event.paddr = si->db_pa;
		ch->event.data = si->db_val;

		ii->pipe_hdl_list[i++] = pi->pipe_hdl;
	}

	/* register interface */
	if (ipa_eth_client_reg_intf(ii)) {
		ioss_dev_err(iface->idev, "Failed to register interface");
		return -EINVAL;
	}

	/* send ecm msg */
	if (ioss_ipa_msg_connect(iface->net_dev)) {
		ioss_dev_err(iface->idev, "Failed to send connect message");
		return -EINVAL;
	}

	iface->registered = true;

	return 0;
}

int ioss_ipa_unregister(struct ioss_interface *iface)
{
	int rc;
	struct ioss_channel *ch;
	struct ioss_iface_priv *ifp = iface->ioss_priv;
	struct ipa_eth_client *ec = &ifp->ipa_ec;
	struct ipa_eth_intf_info *ii = &ifp->ipa_ii;
	union ioss_ipa_eth_hdr *hdr_v4 = &ifp->ipa_hdr_v4;
	union ioss_ipa_eth_hdr *hdr_v6 = &ifp->ipa_hdr_v6;

	/* connect pipes */
	rc = ipa_eth_client_disconn_pipes(ec);
	if (rc) {
		ioss_dev_err(iface->idev, "Failed to disconnect pipes");
		return rc;
	}

	/* unregister interface */
	rc = ipa_eth_client_unreg_intf(ii);
	if (rc) {
		ioss_dev_err(iface->idev, "Failed to unregister interface");
		return rc;
	}

	/* send ecm msg */
	rc = ioss_ipa_msg_disconnect(iface->net_dev);
	if (rc) {
		ioss_dev_err(iface->idev, "Failed to send disconnect message");
		return rc;
	}

	memset(hdr_v4, 0, sizeof(*hdr_v4));
	memset(hdr_v6, 0, sizeof(*hdr_v6));

	kfree(ii->pipe_hdl_list);
	memset(ii, 0, sizeof(*ii));

	ioss_for_each_channel(ch, iface) {
		struct ioss_ch_priv *cp = ch->ioss_priv;

		ch->event.paddr = 0;
		ch->event.data = 0;

		memset(&cp->ipa_pi, 0, sizeof(cp->ipa_pi));
	}

	memset(ec, 0, sizeof(*ec));

	iface->registered = false;

	return 0;
}
