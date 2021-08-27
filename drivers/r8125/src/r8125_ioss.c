/* SPDX-License-Identifier: GPL-2.0-only
 * Copyright (c) 2021, The Linux Foundation. All rights reserved.
 */

#include <linux/pci.h>

#include <linux/module.h>
#include <linux/device.h>
#include <linux/pm_wakeup.h>
#include <net/rtnetlink.h>

#include <linux/msm/ioss.h>

#include "r8125.h"
#include "r8125_lib.h"

#define MODC_UNIT_MASK 0x3000
#define MODC_UNIT_SHIFT 12

#define MODC_VAL_MASK 0x0F00
#define MODC_VAL_SHIFT 8

#define TC_MODE_MASK 0x0C00
#define TC_MODE_SHIFT 10

#define TIMER_MASK 0x00FF
#define TIMER_UNIT 2048

#define to_tp(idev) (((struct r8125_ioss_device *)((idev)->private))->_tp)

enum RTL8125_registers_extra {
	R8125_TX_NEW_CTRL = 0x203E,
	R8125_TX_DESC_NEW_MOD = 0x0400,
	R8125_INT_MITI_V2_1_RX = 0x0A08,
	R8125_TDU_STATUS = 0x0D08,
	R8125_RDU_STATUS = 0x0D0A,
	R8125_PLA_TXQ0_IDLE_CREDIT = 0x2500,
	R8125_PLA_TXQ1_IDLE_CREDIT = 0x2504,
	R8125_RSS_KEY = 0x4600,
	R8125_RSS_I_TABLE = 0x4700,
};

struct __rtl8125_regs {
	ktime_t begin_ktime;
	ktime_t end_ktime;
	u64 duration_ns;

	u32 txq0_dsc_st_addr_0;
	u32 txq0_dsc_st_addr_2;
	u32 txq1_dsc_st_addr_0;
	u32 txq1_dsc_st_addr_2;
	u8 tppoll;
	u32 tcr;
	u8 command_register;
	u8 tx_desc_new_mod;

	u32 rxq0_dsc_st_addr_0;
	u32 rxq0_dsc_st_addr_2;
	u32 rxq1_dsc_st_addr_0;
	u32 rxq1_dsc_st_addr_2;
	u16 rms;
	u32 rcr;

	u32 phy_status;
	u16 cplus_cmd;

	u16 sw0_tail_ptr;
	u16 next_hwq0_clo_ptr;
	u16 sw1_tail_ptr;
	u16 next_hwq1_clo_ptr;
	u16 tc_mode;

	u16 int_miti_rxq0;
	u16 int_miti_txq0;
	u16 int_miti_rxq1;
	u16 int_miti_txq1;
	u8 int_config;
	u32 imr_new;
	u32 isr_new;

	u8 tdu_status;
	u16 rdu_status;

	u32 pla_tx_q0_idle_credit;
	u32 pla_tx_q1_idle_credit;

	u32 rss_ctrl;
	u8 rss_key[RTL8125_RSS_KEY_SIZE];
	u8 rss_i_table[RTL8125_MAX_INDIRECTION_TABLE_ENTRIES];
	u16 rss_queue_num_sel_r;
};

struct r8125_ioss_device {
	struct ioss_device *idev;
	struct rtl8125_private *_tp;
	struct notifier_block nb;
	struct __rtl8125_regs regs_save;
};

static int r8125_notifier_cb(struct notifier_block *nb,
		unsigned long action, void *data)
{
	struct r8125_ioss_device *rdev =
			container_of(nb, typeof(*rdev), nb);

	switch (action) {
	case RTL8125_NOTIFY_RESET_PREPARE:
		ioss_dev_log(rdev->idev, "RTL8125 reset prepare");
		break;
	case RTL8125_NOTIFY_RESET_COMPLETE:
		ioss_dev_log(rdev->idev, "RTL8125 reset complete");
		break;
	}

	return NOTIFY_DONE;
}

static int r8125_ioss_open_device(struct ioss_device *idev)
{
	struct r8125_ioss_device *rdev;

	ioss_dev_dbg(idev, "%s", __func__);

	rdev = kzalloc(sizeof(*rdev), GFP_KERNEL);
	if (!rdev)
		return -ENOMEM;

	rdev->idev = idev;
	rdev->_tp = netdev_priv(idev->net_dev);

	rdev->nb.notifier_call = r8125_notifier_cb;
	if (rtl8125_register_notifier(idev->net_dev, &rdev->nb)) {
		ioss_dev_err(idev, "Failed to register with r8125 notifier");
		goto err_notif;
	}

	idev->private = rdev;

	return 0;

err_notif:
	kzfree(rdev);

	return -EFAULT;
}

static int r8125_ioss_close_device(struct ioss_device *idev)
{
	struct r8125_ioss_device *rdev = idev->private;

	ioss_dev_dbg(idev, "%s", __func__);

	rtl8125_unregister_notifier(idev->net_dev, &rdev->nb);
	kzfree(rdev);

	return 0;
}

static int r8125_ioss_request_channel(struct ioss_channel *ch)
{
	int i;
	int rc = 0;
	enum rtl8125_channel_dir direction =
			(ch->direction == IOSS_CH_DIR_RX) ?
				RTL8125_CH_DIR_RX : RTL8125_CH_DIR_TX;
	struct rtl8125_ring *ring;

	ioss_dev_log(ch->iface->idev, "%s, ring_size=%d, buf_size=%d, dir=%d",
			__func__, ch->config.ring_size, ch->config.buff_size,
			direction);

	ring = rtl8125_request_ring(ioss_ch_dev(ch)->net_dev,
			ch->config.ring_size, ch->config.buff_size,
			direction, RTL8125_CONTIG_BUFS, NULL);
	if (!ring) {
		ioss_dev_err(ch->iface->idev, "Failed to request ring");
		return -EFAULT;
	}

	rc = ioss_channel_add_desc_mem(ch,
			ring->desc_addr, ring->desc_daddr, ring->desc_size);
	if (rc) {
		ioss_dev_err(ch->iface->idev, "Failed to add desc mem");
		goto err_add_desc;
	}

	for (i = 0; i < ring->ring_size; i++) {
		struct rtl8125_buf *buff = &ring->bufs[i];

		rc = ioss_channel_add_buff_mem(ch,
				buff->addr, buff->dma_addr, buff->size);
		if (rc) {
			ioss_dev_err(ch->iface->idev, "Failed to add buff mem");
			goto err_add_buff;
		}
	}

	ch->id = ring->queue_num;
	ch->private = ring;

	return 0;

err_add_buff:
	for (i = 0; i < ring->ring_size; i++)
		ioss_channel_del_buff_mem(ch, ring->bufs[i].addr);

	ioss_channel_del_desc_mem(ch, ring->desc_addr);

err_add_desc:
	rtl8125_release_ring(ring);

	ch->id = -1;
	ch->private = NULL;

	return rc;
}

static int r8125_ioss_release_channel(struct ioss_channel *ch)
{
	int i;
	struct rtl8125_ring *ring = ch->private;

	ioss_dev_log(ch->iface->idev, "Release ring %d", ring->queue_num);

	ioss_channel_del_desc_mem(ch, ring->desc_addr);

	for (i = 0; i < ring->ring_size; i++)
		ioss_channel_del_buff_mem(ch, ring->bufs[i].addr);

	rtl8125_release_ring(ring);

	ch->id = -1;
	ch->private = NULL;

	return 0;
}

static int r8125_ioss_enable_channel(struct ioss_channel *ch)
{
	struct rtl8125_ring *ring = ch->private;

	return rtl8125_enable_ring(ring);
}

static int r8125_ioss_disable_channel(struct ioss_channel *ch)
{
	struct rtl8125_ring *ring = ch->private;

	rtl8125_disable_ring(ring);

	return 0;
}

static int r8125_ioss_request_event(struct ioss_channel *ch)
{
	int rc;
	int mod;
	struct rtl8125_ring *ring = ch->private;

	ioss_dev_log(ch->iface->idev, "Request EVENT: paddr=%pap, DATA: %llu",
		&ch->event.paddr, ch->event.data);

	if (ioss_channel_map_event(ch))
		return -EFAULT;

	rc = rtl8125_request_event(ring, MSIX_event_type,
					ch->event.daddr, ch->event.data);
	if (rc) {
		ioss_dev_err(ch->iface->idev, "Failed to request event");
		goto err_req_event;
	}

	/* Each mod unit is 2048 ns (~2 uS). */
	mod = ch->event.mod_usecs_max / 2;

	ioss_dev_log(ch->iface->idev, "EVENT: mod=%d", mod);

	rc = rtl8125_set_ring_intr_mod(ring, mod);
	if (rc) {
		ioss_dev_err(ch->iface->idev,
			"Failed to set interrupt moderation");
		goto err_intr_mod;
	}

	return 0;

err_intr_mod:
	rtl8125_release_event(ring);
err_req_event:
	ioss_channel_unmap_event(ch);

	return -EFAULT;
}

static int r8125_ioss_release_event(struct ioss_channel *ch)
{
	struct rtl8125_ring *ring = ch->private;

	ioss_dev_log(ch->iface->idev, "Release EVENT: daddr=%pad, DATA: %llu",
			&ch->event.daddr, ch->event.data);

	rtl8125_release_event(ring);
	ioss_channel_unmap_event(ch);

	return 0;
}

static int __r8125_ioss_enable_filters(struct ioss_channel *ch)
{
	struct rtl8125_ring *ring = ch->private;
	struct net_device *net_dev = ioss_ch_dev(ch)->net_dev;
	enum ioss_filter_types filters = ch->filter_types;

	ioss_dev_log(ch->iface->idev, "Enabling filters %d", filters);

	if (!filters)
		return 0;

	if (ch->direction != IOSS_CH_DIR_RX)
		return -EFAULT;

	if (filters & IOSS_RXF_F_IP) {
		ioss_dev_log(ch->iface->idev, "Enabling RSS filter");

		if (rtl8125_rss_redirect(net_dev, 0, ring)) {
			ioss_dev_err(ch->iface->idev,
					"Failed to install rss filter");
			return -EFAULT;
		}

		filters &= ~IOSS_RXF_F_IP;
	}

	if (filters) {
		ioss_dev_err(ch->iface->idev, "Unsupported filters requested");
		rtl8125_rss_reset(net_dev);
		return -EFAULT;
	}

	return 0;
}

static int __r8125_ioss_disable_filters(struct ioss_channel *ch)
{
	struct net_device *net_dev = ioss_ch_dev(ch)->net_dev;
	enum ioss_filter_types filters = ch->filter_types;

	ioss_dev_log(ch->iface->idev, "Disabling filters %d", filters);

	if (!filters)
		return 0;

	if (ch->direction != IOSS_CH_DIR_RX)
		return -EFAULT;

	if (filters & IOSS_RXF_F_IP) {
		ioss_dev_log(ch->iface->idev, "Disabling RSS filter");

		if (rtl8125_rss_reset(net_dev)) {
			ioss_dev_err(ch->iface->idev, "Failed to reset rss filter");
			return -EFAULT;
		}

		filters &= ~IOSS_RXF_F_IP;
	}

	return 0;
}

static int r8125_ioss_enable_event(struct ioss_channel *ch)
{
	int rc;
	struct rtl8125_ring *ring = ch->private;

	rc = rtl8125_enable_event(ring);
	if (rc) {
		ioss_dev_err(ch->iface->idev, "Failed to enable event");
		return rc;
	}

	rc = __r8125_ioss_enable_filters(ch);
	if (rc) {
		ioss_dev_err(ch->iface->idev, "Failed to enable filters");
		rtl8125_disable_event(ring);
		return rc;
	}

	return 0;
}

static int r8125_ioss_disable_event(struct ioss_channel *ch)
{
	int rc;
	struct rtl8125_ring *ring = ch->private;

	rc = __r8125_ioss_disable_filters(ch);
	if (rc) {
		ioss_dev_err(ch->iface->idev, "Failed to disable filters");
		return rc;
	}

	rc = rtl8125_disable_event(ring);
	if (rc) {
		ioss_dev_err(ch->iface->idev, "Failed to disable event");
		return rc;
	}

	return 0;
}

static int r8125_save_regs(struct ioss_device *idev,
		void **regs, size_t *size)
{
	struct r8125_ioss_device *rtldev = idev->private;
	struct rtl8125_private *tp = rtldev->_tp;
	struct __rtl8125_regs *rtl_regs = &rtldev->regs_save;
	int i;

	rtl_regs->begin_ktime = ktime_get();

	rtl_regs->txq0_dsc_st_addr_0 = RTL_R32(tp, TxDescStartAddrLow);
	rtl_regs->txq0_dsc_st_addr_2 = RTL_R32(tp, TxDescStartAddrHigh);
	rtl_regs->txq1_dsc_st_addr_0 = RTL_R32(tp, TNPDS_Q1_LOW_8125);
	rtl_regs->txq1_dsc_st_addr_2 = RTL_R32(tp, (TNPDS_Q1_LOW_8125 + 4));
	rtl_regs->tppoll = RTL_R8(tp, TPPOLL_8125);
	rtl_regs->tcr = RTL_R32(tp, TxConfig);
	rtl_regs->command_register = RTL_R8(tp, ChipCmd);
	rtl_regs->tx_desc_new_mod = RTL_R8(tp, R8125_TX_DESC_NEW_MOD);

	rtl_regs->rxq0_dsc_st_addr_0 = RTL_R32(tp, RxDescAddrLow);
	rtl_regs->rxq0_dsc_st_addr_2 = RTL_R32(tp, RxDescAddrHigh);
	rtl_regs->rxq1_dsc_st_addr_0 = RTL_R32(tp, RDSAR_Q1_LOW_8125);
	rtl_regs->rxq1_dsc_st_addr_2 = RTL_R32(tp, (RDSAR_Q1_LOW_8125 + 4));
	rtl_regs->rms = RTL_R16(tp, RxMaxSize);
	rtl_regs->rcr = RTL_R32(tp, RxConfig);

	rtl_regs->phy_status = RTL_R32(tp, PHYstatus);
	rtl_regs->cplus_cmd = RTL_R16(tp, CPlusCmd);

	rtl_regs->sw0_tail_ptr = RTL_R16(tp, SW_TAIL_PTR0_8125);
	rtl_regs->next_hwq0_clo_ptr = RTL_R16(tp, HW_CLO_PTR0_8125);
	rtl_regs->sw1_tail_ptr = RTL_R16(tp, (SW_TAIL_PTR0_8125 + 4));
	rtl_regs->next_hwq1_clo_ptr = RTL_R16(tp, (HW_CLO_PTR0_8125 + 4));
	rtl_regs->tc_mode = RTL_R16(tp, R8125_TX_NEW_CTRL);

	rtl_regs->int_miti_rxq0 = RTL_R16(tp, INT_MITI_V2_0_RX);
	rtl_regs->int_miti_txq0 = RTL_R16(tp, INT_MITI_V2_0_TX);
	rtl_regs->int_miti_rxq1 = RTL_R16(tp, R8125_INT_MITI_V2_1_RX);
	rtl_regs->int_miti_txq1 = RTL_R16(tp, INT_MITI_V2_1_TX);
	rtl_regs->int_config = RTL_R8(tp, INT_CFG0_8125);
	rtl_regs->imr_new = RTL_R32(tp, IMR_V2_CLEAR_REG_8125);
	rtl_regs->isr_new = RTL_R32(tp, ISR_V2_8125);

	rtl_regs->tdu_status = RTL_R8(tp, R8125_TDU_STATUS);
	rtl_regs->rdu_status = RTL_R16(tp, R8125_RDU_STATUS);

	rtl_regs->pla_tx_q0_idle_credit = RTL_R32(tp,
						R8125_PLA_TXQ0_IDLE_CREDIT);
	rtl_regs->pla_tx_q1_idle_credit = RTL_R32(tp,
						R8125_PLA_TXQ1_IDLE_CREDIT);

	rtl_regs->rss_ctrl = RTL_R32(tp, RSS_CTRL_8125);
	for (i = 0; i < RTL8125_RSS_KEY_SIZE; i++)
		rtl_regs->rss_key[i] = RTL_R8(tp, R8125_RSS_KEY + i);

	for (i = 0; i < RTL8125_MAX_INDIRECTION_TABLE_ENTRIES; i++)
		rtl_regs->rss_i_table[i] = RTL_R8(tp, R8125_RSS_I_TABLE + i);

	rtl_regs->rss_queue_num_sel_r = RTL_R16(tp, Q_NUM_CTRL_8125);

	rtl_regs->end_ktime = ktime_get();

	rtl_regs->duration_ns =
		ktime_to_ns(ktime_sub(rtl_regs->end_ktime,
					rtl_regs->begin_ktime));

	if (regs)
		*regs = rtl_regs;

	if (size)
		*size = sizeof(*rtl_regs);

	return 0;
}

#if IOSS_API_VER >= 3
static u64 __get_stats_data(const char *name, u64 data[], const u8 *strings_data, int scount)
{
	int i = 0;
	const char (*strings)[ETH_GSTRING_LEN] = (typeof(strings))strings_data;

	/* iterate through strings[], find matchging index */
	for (i = 0; i < scount; i++) {
		if (strcmp(name, strings[i]) == 0)
			return data[i];
	}

	return 0;
}

static int r8125_ioss_device_statistics(struct ioss_device *idev,
					struct ioss_device_stats *statistics)
{
	u64 *data;
	u8 *strings;
	int strings_count = 0;
	struct ethtool_stats stats;
	const struct ethtool_ops *ops = idev->net_dev->ethtool_ops;

	if (ops == NULL ||
		ops->get_sset_count == NULL ||
		ops->get_ethtool_stats == NULL ||
		ops->get_strings == NULL)
			return -EOPNOTSUPP;

	strings_count = ops->get_sset_count(idev->net_dev, ETH_SS_STATS);

	data = kcalloc(strings_count, sizeof(u64), GFP_KERNEL);
	if (!data)
		return -ENOMEM;

	strings = kcalloc(strings_count, ETH_GSTRING_LEN, GFP_KERNEL);
	if (!strings) {
		kfree(data);
		return -ENOMEM;
	}

	memset(&stats, 0, sizeof(stats));
	stats.n_stats = strings_count;

	rtnl_lock();
	ops->get_ethtool_stats(idev->net_dev, &stats, data);
	rtnl_unlock();

	ops->get_strings(idev->net_dev, ETH_SS_STATS, strings);

	statistics->emac_tx_packets =
		__get_stats_data("tx_packets", data, strings, strings_count);
	statistics->emac_rx_packets =
		__get_stats_data("rx_packets", data, strings, strings_count);
	statistics->emac_tx_errors =
		__get_stats_data("tx_errors", data, strings, strings_count);
	statistics->emac_rx_errors =
		__get_stats_data("rx_errors", data, strings, strings_count);
	statistics->emac_rx_drops =
		__get_stats_data("rx_missed", data, strings, strings_count);

	kfree(data);
	kfree(strings);

	return 0;
}

static int r8125_ioss_channel_statistics(struct ioss_channel *ch,
					 struct ioss_channel_stats *statistics)
{
	return 0;
}

static void get_ch_mod(struct ioss_channel *ch,
		       struct ioss_channel_status *status)
{
	struct rtl8125_private *tp = to_tp(ch->iface->idev);

	u16 ch_mod_reg = 0;
	u16 modc_unit = 0;
	u16 modc_val = 0;

	const u16 PKT_UNIT[4] = {1, 2, 4, 16};

	ch_mod_reg = (ch->direction == IOSS_CH_DIR_RX) ?
		RTL_R16(tp, (INT_MITI_V2_0_RX + (ch->id * 8))) :
		RTL_R16(tp, (INT_MITI_V2_0_TX + (ch->id * 8)));

	modc_unit = (ch_mod_reg & MODC_UNIT_MASK) >> MODC_UNIT_SHIFT;
	modc_val = (ch_mod_reg & MODC_VAL_MASK) >> MODC_VAL_SHIFT;

	status->interrupt_modc = modc_val * PKT_UNIT[modc_unit];
	status->interrupt_modt = (ch_mod_reg & TIMER_MASK) * TIMER_UNIT;
}

static void get_ch_enabled(struct ioss_channel *ch,
			   struct ioss_channel_status *status)
{
	struct rtl8125_private *tp = to_tp(ch->iface->idev);
	struct rtl8125_ring *ring = ch->private;

	if (ch->direction == IOSS_CH_DIR_RX)
		status->enabled = ring->enabled;
	else {
		u16 tx_new_ctrl1 = 0;
		u16 tc_mode = 0;

		tx_new_ctrl1 = RTL_R16(tp, R8125_TX_NEW_CTRL);
		tc_mode = (tx_new_ctrl1 & TC_MODE_MASK) >> TC_MODE_SHIFT;
		if (tc_mode == 1 || (tc_mode == 0 && ch->id == 0))
			status->enabled = true;
	}
}

static void get_ch_ring_size(struct ioss_channel *ch,
			     struct ioss_channel_status *status)
{
	struct rtl8125_ring *ring = ch->private;
	void *desc_mem = ring->desc_addr;

	u32 opts1 = (ch->direction == IOSS_CH_DIR_RX) ?
		((struct RxDescV3 *)desc_mem)[ring->ring_size-1].RxDescNormalDDWord4.opts1 :
		((struct TxDesc *)desc_mem)[ring->ring_size-1].opts1;

	/* Verify ring_size by checking if last descriptor is at End-of-Ring */
	if (opts1 & cpu_to_le32(RingEnd))
		status->ring_size = ring->ring_size;
}

static void get_ch_head_tail_ptr(struct ioss_channel *ch,
				 struct ioss_channel_status *status)
{
	if (ch->direction == IOSS_CH_DIR_TX) {
		struct rtl8125_private *tp = to_tp(ch->iface->idev);

		status->head_ptr = RTL_R16(tp, (SW_TAIL_PTR0_8125 + (ch->id * 4)));
		status->tail_ptr = RTL_R16(tp, (HW_CLO_PTR0_8125 + (ch->id * 4)));
	}
}

static int r8125_ioss_channel_status(struct ioss_channel *ch,
				     struct ioss_channel_status *status)
{
	get_ch_mod(ch, status);
	get_ch_enabled(ch, status);
	get_ch_ring_size(ch, status);
	get_ch_head_tail_ptr(ch, status);

	return 0;
}
#endif

static struct ioss_driver_ops r8125_ioss_ops = {
	.open_device = r8125_ioss_open_device,
	.close_device = r8125_ioss_close_device,

	.request_channel = r8125_ioss_request_channel,
	.release_channel = r8125_ioss_release_channel,

	.enable_channel = r8125_ioss_enable_channel,
	.disable_channel = r8125_ioss_disable_channel,

	.request_event = r8125_ioss_request_event,
	.release_event = r8125_ioss_release_event,

	.enable_event = r8125_ioss_enable_event,
	.disable_event = r8125_ioss_disable_event,

	.save_regs = r8125_save_regs,

#if IOSS_API_VER >= 3
	.get_device_statistics = r8125_ioss_device_statistics,
	.get_channel_statistics = r8125_ioss_channel_statistics,
	.get_channel_status = r8125_ioss_channel_status,
#endif
};

static bool r8125_driver_match(struct device *dev)
{
	ioss_log_dbg(NULL, "MATCH %s", dev_name(dev));

	/* Just match the driver name */
	return (dev->bus == &pci_bus_type) &&
		!strcmp(to_pci_driver(dev->driver)->name, MODULENAME);
}

static struct ioss_driver r8125_ioss_drv = {
	.name = MODULENAME "_ioss",
	.match = r8125_driver_match,
	.ops = &r8125_ioss_ops,
	.filter_types = IOSS_RXF_F_IP,
};

static int __init r8125_ioss_init(void)
{
	return ioss_pci_register_driver(&r8125_ioss_drv);

}
module_init(r8125_ioss_init);

static void __exit r8125_ioss_exit(void)
{
	ioss_pci_unregister_driver(&r8125_ioss_drv);
}
module_exit(r8125_ioss_exit);

MODULE_LICENSE("GPL v2");
MODULE_DESCRIPTION("Realtek R8125 IOSS Glue Driver");
