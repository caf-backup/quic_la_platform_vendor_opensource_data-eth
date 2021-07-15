/*
 * TC956x IPA I/F layer
 *
 * tc956x_ipa_intf.c
 *
 * Copyright (C) 2021 Toshiba Electronic Devices & Storage Corporation
 *
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2, or (at your option)
 * any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301, USA.
 */

/*! History:
 *  20 Jan 2021 : Initial Version
 *  VERSION     : 00-01
 *
 *  15 Mar 2021 : Base lined
 *  VERSION     : 01-00
 *
 *  05 Jul 2021 : 1. Used Systick handler instead of Driver kernel timer to process transmitted Tx descriptors.
 *                2. XFI interface support and module parameters for selection of Port0 and Port1 interface
 *  VERSION     : 01-00-01
 */

#include <linux/dma-mapping.h>
#include "common.h"
#include "tc956xmac.h"
#include "tc956xmac_ioctl.h"
#ifdef TC956X
#include "dwxgmac2.h"
#endif
#include "tc956x_ipa_intf.h"

#define IPA_INTF_MAJOR_VERSION 0
#define IPA_INTF_MINOR_VERSION 1

/* 0x20004000 to 0x2000401C is for Port0, 0x20004020 to 0x2000403C is for Port1 */
#define SRAM_TX_PCIE_ADDR_LOC	0x44000

/* 0x20004040 to 0x2000405C is for Port0, 0x20004060 to 0x2000407C is for Port1 */
#define SRAM_RX_PCIE_ADDR_LOC	0x44040

#define CM3_PCIE_REGION_LOW_BOUND	0x60000000
#define CM3_PCIE_REGION_UP_BOUND	0xC0000000

/* At 10Gbps speed, only 72 entries can be parsed */
#define MAX_PARSABLE_FRP_ENTRIES 72

#define IPA_MAX_BUFFER_SIZE (9*1024) /* 9KBytes */
#define IPA_MAX_DESC_CNT    512
#define MAX_WDT		0xFF

extern int tc956xmac_rx_parser_configuration(struct tc956xmac_priv *);
/*!
 * \brief This API will return the version of IPA I/F maintained by Toshiba
 *	  The API will check for NULL pointers
 *
 * \param[in] ndev : TC956x netdev data structure
 *
 * \return : Correct Major and Minor number of the IPA I/F version
 *	     Major Number = Minor Number = 0xFF incase ndev is NULL or
 *	     tc956xmac_priv extracted from ndev is NULL
 */

struct tc956x_ipa_version get_ipa_intf_version(struct net_device *ndev)
{
	struct tc956x_ipa_version version;

	version.major = 0xFF;
	version.minor = 0xFF;

	if (!ndev) {
		pr_err("%s: ERROR: Invalid netdevice pointer\n", __func__);
		return version;
	}

	version.major = IPA_INTF_MAJOR_VERSION;
	version.minor = IPA_INTF_MINOR_VERSION;

	return version;
}
EXPORT_SYMBOL_GPL(get_ipa_intf_version);

/*!
 * \brief This API will store the client private structure inside TC956x private structure.
 *	  The API will check for NULL pointers. client_priv == NULL will be considered as a valid argument
 *
 * \param[in] ndev : TC956x netdev data structure
 * \param[in]  client_priv : Client private data structure
 *
 * \return : 0 on success
 *	     -ENODEV if ndev is NULL, tc956xmac_priv extracted from ndev is NULL
 */

int set_client_priv_data(struct net_device *ndev, void *client_priv)
{
	struct tc956xmac_priv *priv;

	if (!ndev) {
		pr_err("%s: ERROR: Invalid netdevice pointer\n", __func__);
		return -ENODEV;
	}

	priv = netdev_priv(ndev);
	if (!priv) {
		pr_err("%s: ERROR: Invalid private data pointer\n", __func__);
		return -ENODEV;
	}

	priv->client_priv = client_priv;

	return 0;
}
EXPORT_SYMBOL_GPL(set_client_priv_data);

/*!
 * \brief This API will return the client private data structure
 *	  The API will check for NULL pointers
 *
 * \param[in] ndev : TC956x netdev data structure
 *
 * \return : Pointer to the client private data structure
 *	     NULL if ndev or tc956xmac_priv extracted from ndev is NULL
 */

void* get_client_priv_data(struct net_device *ndev)
{
	struct tc956xmac_priv *priv;

	if (!ndev) {
		pr_err("%s: ERROR: Invalid netdevice pointer\n", __func__);
		return NULL;
	}

	priv = netdev_priv(ndev);
	if (!priv) {
		pr_err("%s: ERROR: Invalid private data pointer\n", __func__);
		return NULL;
	}

	return priv->client_priv;
}
EXPORT_SYMBOL_GPL(get_client_priv_data);

static void free_ipa_tx_resources(struct net_device *ndev, struct channel_info *channel)
{
	struct tc956xmac_priv *priv = netdev_priv(ndev);
	struct tc956xmac_tx_queue *tx_q = &priv->tx_queue[channel->channel_num];
	u32 i;

	for (i = 0; i < channel->desc_cnt; i++) {
		dma_unmap_single(priv->device, tx_q->tx_offload_skbuff_dma[i],
					 channel->buf_size, DMA_TO_DEVICE);

		if (tx_q->tx_offload_skbuff[i])
			dev_kfree_skb_any(tx_q->tx_offload_skbuff[i]);

		channel->buff_pool_addr.buff_pool_dma_addrs_base[i] = 0;
		channel->buff_pool_addr.buff_pool_va_addrs_base[i] = NULL;
	}

	dma_free_coherent(priv->device, channel->desc_size * channel->desc_cnt,
				channel->desc_addr.desc_virt_addrs_base, tx_q->dma_tx_phy);

	kfree(tx_q->tx_offload_skbuff);
	kfree(tx_q->tx_offload_skbuff_dma);

}

static void free_ipa_rx_resources(struct net_device *ndev, struct channel_info *channel)
{
	struct tc956xmac_priv *priv = netdev_priv(ndev);
	struct tc956xmac_rx_queue *rx_q = &priv->rx_queue[channel->channel_num];
	u32 i;

	for (i = 0; i < channel->desc_cnt; i++) {
		dma_unmap_single(priv->device, rx_q->rx_offload_skbuff_dma[i],
					 channel->buf_size, DMA_FROM_DEVICE);

		if (rx_q->rx_offload_skbuff[i])
			dev_kfree_skb_any(rx_q->rx_offload_skbuff[i]);

		channel->buff_pool_addr.buff_pool_dma_addrs_base[i] = 0;
		channel->buff_pool_addr.buff_pool_va_addrs_base[i] = NULL;
	}

	dma_free_coherent(priv->device, channel->desc_size * channel->desc_cnt,
				channel->desc_addr.desc_virt_addrs_base, rx_q->dma_rx_phy);

	kfree(rx_q->rx_offload_skbuff);
	kfree(rx_q->rx_offload_skbuff_dma);

}

static int find_free_tx_channel(struct net_device *ndev, struct channel_info *channel)
{
	struct tc956xmac_priv *priv = netdev_priv(ndev);
	u32 ch;
	struct tc956xmac_tx_queue *tx_q;

	for (ch = 0; ch < MAX_TX_QUEUES_TO_USE; ch++) {
		/* Find a free channel to use for IPA */
		if (priv->plat->tx_dma_ch_owner[ch] == NOT_USED) {
			channel->channel_num = ch;
			break;
		}
	}

	if (ch >= MAX_TX_QUEUES_TO_USE) {
		netdev_err(priv->dev, "%s: ERROR: No valid Tx channel available\n", __func__);
		return -EINVAL;
	}

	priv->plat->tx_dma_ch_owner[ch] = USE_IN_OFFLOADER;

	tx_q = &priv->tx_queue[ch];
	tx_q->priv_data = priv;

	return 0;
}

static int find_free_rx_channel(struct net_device *ndev, struct channel_info *channel)
{
	struct tc956xmac_priv *priv = netdev_priv(ndev);
	u32 ch;
	struct tc956xmac_rx_queue *rx_q;

	for (ch = 0; ch < MAX_RX_QUEUES_TO_USE; ch++) {
		/* Find a free channel to use for IPA */
		if (priv->plat->rx_dma_ch_owner[ch] == NOT_USED) {
			channel->channel_num = ch;
			break;
		}
	}

	if (ch >= MAX_RX_QUEUES_TO_USE) {
		netdev_err(priv->dev, "%s: ERROR: No valid Rx channel available\n", __func__);
		return -EINVAL;
	}

	priv->plat->rx_dma_ch_owner[ch] = USE_IN_OFFLOADER;

	rx_q = &priv->rx_queue[ch];
	rx_q->priv_data = priv;

	return 0;
}

static int alloc_ipa_tx_resources(struct net_device *ndev, struct channel_info *channel, gfp_t flags)
{
	struct tc956xmac_priv *priv = netdev_priv(ndev);
	struct tc956xmac_tx_queue *tx_q;
	struct sk_buff *skb;
	u32 i;
	int ret = -EINVAL;

	ret = find_free_tx_channel(ndev, channel);

	if (ret)
		return ret;

	tx_q = &priv->tx_queue[channel->channel_num];

	channel->desc_addr.desc_virt_addrs_base = dma_alloc_coherent(priv->device, 
								channel->desc_size * channel->desc_cnt,
								&tx_q->dma_tx_phy, flags);

	if (!channel->desc_addr.desc_virt_addrs_base) {
		netdev_err(priv->dev, "%s: ERROR: allocating memory\n", __func__);
		goto err_mem;
	}

	tx_q->dma_tx = channel->desc_addr.desc_virt_addrs_base;
	tx_q->tx_offload_skbuff_dma = kcalloc(channel->desc_cnt,
				      sizeof(*tx_q->tx_offload_skbuff_dma), flags);
	if (!tx_q->tx_offload_skbuff_dma) {

		netdev_err(priv->dev, "%s: ERROR: allocating memory\n", __func__);
		goto err_mem;
	}

	tx_q->tx_offload_skbuff = kcalloc(channel->desc_cnt, sizeof(struct sk_buff *), flags);
	if (!tx_q->tx_offload_skbuff) {
		netdev_err(priv->dev, "%s: ERROR: allocating memory\n", __func__);
		goto err_mem;
	}

	for (i = 0; i < channel->desc_cnt; i++) {
		skb = __netdev_alloc_skb_ip_align(priv->dev, channel->buf_size, flags);

		if (!skb) {
			netdev_err(priv->dev,
					"%s: Rx init fails; skb is NULL\n", __func__);
			goto err_mem;
		}

		tx_q->tx_offload_skbuff[i] = skb;
		tx_q->tx_offload_skbuff_dma[i] = dma_map_single(priv->device, skb->data,
							channel->buf_size, DMA_TO_DEVICE);

		if (dma_mapping_error(priv->device, tx_q->tx_offload_skbuff_dma[i])) {
			netdev_err(priv->dev, "%s: DMA mapping error\n", __func__);
			dev_kfree_skb_any(skb);
			goto err_mem;
		}

		channel->buff_pool_addr.buff_pool_va_addrs_base[i] = (void *)tx_q->tx_offload_skbuff[i]->data;
		channel->buff_pool_addr.buff_pool_dma_addrs_base[i] = tx_q->tx_offload_skbuff_dma[i];

	}
	channel->desc_addr.desc_dma_addrs_base = tx_q->dma_tx_phy;
	return 0;

err_mem:
	free_ipa_tx_resources(ndev, channel);
	return -ENOMEM;
}

static int alloc_ipa_rx_resources(struct net_device *ndev, struct channel_info *channel, gfp_t flags)
{
	struct tc956xmac_priv *priv = netdev_priv(ndev);
	struct tc956xmac_rx_queue *rx_q;
	struct sk_buff *skb;
	u32 i;
	int ret = -EINVAL;

	ret = find_free_rx_channel(ndev, channel);

	if (ret)
		return ret;

	rx_q = &priv->rx_queue[channel->channel_num];

	channel->desc_addr.desc_virt_addrs_base = dma_alloc_coherent(priv->device, channel->desc_size * channel->desc_cnt,
								&rx_q->dma_rx_phy, flags);

	if (!channel->desc_addr.desc_virt_addrs_base) {
		netdev_err(priv->dev, "%s: ERROR: allocating memory\n", __func__);
		goto err_mem;
	}

	rx_q->dma_rx = channel->desc_addr.desc_virt_addrs_base;
	rx_q->rx_offload_skbuff_dma = kcalloc(channel->desc_cnt,
				      sizeof(*rx_q->rx_offload_skbuff_dma), flags);

	if (!rx_q->rx_offload_skbuff_dma) {

		netdev_err(priv->dev, "%s: ERROR: allocating memory\n", __func__);
		goto err_mem;
	}

	rx_q->rx_offload_skbuff = kcalloc(channel->desc_cnt, sizeof(struct sk_buff *), flags);
	if (!rx_q->rx_offload_skbuff) {
		netdev_err(priv->dev, "%s: ERROR: allocating memory\n", __func__);
		goto err_mem;
	}

	for (i = 0; i < channel->desc_cnt; i++) {
		skb = __netdev_alloc_skb_ip_align(priv->dev, channel->buf_size, flags);

		if (!skb) {
			netdev_err(priv->dev,
					"%s: Rx init fails; skb is NULL\n", __func__);
			goto err_mem;
		}

		rx_q->rx_offload_skbuff[i] = skb;
		rx_q->rx_offload_skbuff_dma[i] = dma_map_single(priv->device, skb->data,
							channel->buf_size, DMA_FROM_DEVICE);

		if (dma_mapping_error(priv->device, rx_q->rx_offload_skbuff_dma[i])) {
			netdev_err(priv->dev, "%s: DMA mapping error\n", __func__);
			dev_kfree_skb_any(skb);
			goto err_mem;
		}

		channel->buff_pool_addr.buff_pool_va_addrs_base[i] = (void *)rx_q->rx_offload_skbuff[i]->data;
		channel->buff_pool_addr.buff_pool_dma_addrs_base[i] = rx_q->rx_offload_skbuff_dma[i];

	}

	channel->desc_addr.desc_dma_addrs_base = rx_q->dma_rx_phy;
	return 0;

err_mem:
	free_ipa_rx_resources(ndev, channel);
	return -ENOMEM;
}

static void tc956xmac_init_ipa_tx_ch(struct tc956xmac_priv *priv, struct channel_info *channel)
{
	u32 i;
	u32 chan = channel->channel_num;
	struct tc956xmac_tx_queue *tx_q = &priv->tx_queue[chan];

	for (i = 0; i < channel->desc_cnt; i++) {

		struct dma_desc *p;

		p = tx_q->dma_tx + i;

		tc956xmac_clear_desc(priv, p);
		tc956xmac_set_desc_addr(priv, p, channel->buff_pool_addr.buff_pool_dma_addrs_base[i]);
	}

	tc956xmac_init_chan(priv, priv->ioaddr, priv->plat->dma_cfg, chan);
	tc956xmac_init_tx_chan(priv, priv->ioaddr, priv->plat->dma_cfg,
				tx_q->dma_tx_phy, chan);

	tx_q->tx_tail_addr = tx_q->dma_tx_phy;
	tc956xmac_set_tx_tail_ptr(priv, priv->ioaddr,
				       tx_q->tx_tail_addr, chan);

	tc956xmac_set_tx_ring_len(priv, priv->ioaddr, channel->desc_cnt - 1, chan);

	tc956xmac_set_mtl_tx_queue_weight(priv, priv->hw,
					priv->plat->tx_queues_cfg[chan].weight, chan);

}

static void tc956xmac_init_ipa_rx_ch(struct tc956xmac_priv *priv, struct channel_info *channel)
{
	u32 i;
	u32 chan = channel->channel_num;
	struct tc956xmac_rx_queue *rx_q = &priv->rx_queue[chan];

	for (i = 0; i < channel->desc_cnt; i++) {
		struct dma_desc *p;

		p = rx_q->dma_rx + i;

		tc956xmac_init_rx_desc(priv, &rx_q->dma_rx[i],
					priv->use_riwt, priv->mode,
					(i == channel->desc_cnt - 1),
					channel->buf_size);

		tc956xmac_set_desc_addr(priv, p, channel->buff_pool_addr.buff_pool_dma_addrs_base[i]);
	}

	tc956xmac_init_chan(priv, priv->ioaddr, priv->plat->dma_cfg, chan);
	tc956xmac_init_rx_chan(priv, priv->ioaddr, priv->plat->dma_cfg,
				    rx_q->dma_rx_phy, chan);

	rx_q->rx_tail_addr = rx_q->dma_rx_phy +
				 (channel->desc_cnt * sizeof(struct dma_desc));
	tc956xmac_set_rx_tail_ptr(priv, priv->ioaddr, rx_q->rx_tail_addr, chan);

	tc956xmac_set_rx_ring_len(priv, priv->ioaddr, (channel->desc_cnt - 1), chan);
	tc956xmac_set_dma_bfsize(priv, priv->ioaddr, channel->buf_size, chan);

}

static void dealloc_ipa_tx_resources(struct net_device *ndev, struct channel_info *channel)
{
	struct tc956xmac_priv *priv = netdev_priv(ndev);
	struct tc956xmac_tx_queue *tx_q;
	u32 ch = channel->channel_num;

	priv->plat->tx_dma_ch_owner[ch] = NOT_USED;

	tx_q = &priv->tx_queue[ch];
	tx_q->priv_data = NULL;

	free_ipa_tx_resources(ndev, channel);

	tx_q->dma_tx = NULL;

}

static void dealloc_ipa_rx_resources(struct net_device *ndev, struct channel_info *channel)
{
	struct tc956xmac_priv *priv = netdev_priv(ndev);
	struct tc956xmac_rx_queue *rx_q;
	u32 ch = channel->channel_num;

	priv->plat->rx_dma_ch_owner[ch] = NOT_USED;

	rx_q = &priv->rx_queue[ch];
	rx_q->priv_data = NULL;

	free_ipa_rx_resources(ndev, channel);

	rx_q->dma_rx = NULL;
}


/*!
 * \brief API to allocate a channel for IPA  Tx/Rx datapath,
 *	  allocate memory and buffers for the DMA channel, setup the
 *	  descriptors and configure the the require registers and
 *	  mark the channel as used by IPA in the TC956x driver
 *
 *	  The API will check for NULL pointers and Invalid arguments such as,
 *	  out of bounds buf size > 9K bytes, descriptor count > 512
 *
 * \param[in] ndev : TC956x netdev data structure.
 * \param[in] desc_cnt : No. of required descriptors for the Tx/Rx Channel
 * \param[in] ch_dir : CH_DIR_RX for Rx Channel, CH_DIR_TX for Tx Channel
 * \param[in] buf_size : Data buffer size
 * \param[in] flags : flags for memory allocation. Same as gfp_t?
 * \param[in] mem_ops : If NULL, use default flags for memory allocation.
 *			otherwise use the function pointers provided for
 *			descriptor and buffer allocation
 * \param[in] client_ch_priv : To store in channel_info and pass it to mem_ops
 *
 * \return channel_info : Allocate memory for channel_info structure and initialize the structure members
 *			  NULL on fail
 * \remarks :In case of Tx, only TDES0 and TDES1 will be updated with buffer addresses. TDES2 and TDES3
 *	    must be updated by the offloading driver.
 */
struct channel_info* request_channel(struct net_device *ndev, unsigned int desc_cnt,
					enum channel_dir ch_dir, unsigned int buf_size,
					unsigned long flags, struct mem_ops *mem_ops,
					void *client_ch_priv)
{
	struct channel_info *channel;
	struct tc956xmac_priv *priv;
	struct tc956xmac_tx_queue *tx_q;
	struct tc956xmac_rx_queue *rx_q;

	if (!ndev) {
		pr_err("%s: ERROR: Invalid netdevice pointer\n", __func__);
		return NULL;
	}

	priv = netdev_priv(ndev);
	if (!priv) {
		pr_err("%s: ERROR: Invalid private data pointer\n", __func__);
		return NULL;
	}

	if (desc_cnt > IPA_MAX_DESC_CNT) {
		netdev_err(priv->dev, "%s: ERROR: Descriptor count greater than %d\n", __func__, IPA_MAX_DESC_CNT);
		return NULL;
	}

	if (buf_size > IPA_MAX_BUFFER_SIZE) {
		netdev_err(priv->dev, "%s: ERROR: Buffer size greater than %d bytes\n", __func__, IPA_MAX_BUFFER_SIZE);

		return NULL;
	}

	channel = kzalloc(sizeof(*channel), GFP_KERNEL);
	if (!channel) {
		netdev_err(priv->dev, "%s: ERROR: allocating memory\n", __func__);
		return NULL;
	}

	channel->buf_size = buf_size;
	channel->client_ch_priv = client_ch_priv;
	channel->desc_cnt = desc_cnt;
	channel->desc_size = sizeof(struct dma_desc);
	channel->direction = ch_dir;
	channel->mem_ops = mem_ops;


	channel->buff_pool_addr.buff_pool_va_addrs_base = kcalloc(desc_cnt, sizeof(void *), (gfp_t)flags);

	if (!channel->buff_pool_addr.buff_pool_va_addrs_base) {
		netdev_err(priv->dev, "%s: ERROR: allocating memory\n", __func__);
		goto err_buff_mem_alloc;
	}

	channel->buff_pool_addr.buff_pool_dma_addrs_base = kcalloc(desc_cnt, sizeof(dma_addr_t), (gfp_t)flags);

	if (!channel->buff_pool_addr.buff_pool_dma_addrs_base) {
		netdev_err(priv->dev, "%s: ERROR: allocating memory\n", __func__);
		goto err_buff_dma_mem_alloc;
	}

	if (mem_ops) {
		/*if mem_ops is a valid, memory resrouces will be allocated by IPA */

		if (mem_ops->alloc_descs) {
			mem_ops->alloc_descs(ndev, channel->desc_size, NULL, (gfp_t)flags, mem_ops, channel);
		} else {
			netdev_err(priv->dev,
				"%s: ERROR: mem_ops is valid but alloc_descs is invalid\n", __func__);
			goto err_invalid_mem_ops;
		}

		if (mem_ops->alloc_buf) {
			mem_ops->alloc_buf(ndev, channel->desc_size, NULL, (gfp_t)flags, mem_ops, channel);
		} else {
			netdev_err(priv->dev,
				"%s: ERROR: mem_ops is valid but alloc_buff is invalid\n", __func__);

			if (mem_ops->free_descs)
				mem_ops->free_descs(ndev, NULL, sizeof(struct dma_desc), NULL, mem_ops, channel);

			goto err_invalid_mem_ops;
		}

		if (ch_dir == CH_DIR_TX) {
			find_free_tx_channel(ndev, channel);
			tx_q = &priv->tx_queue[channel->channel_num];
			tx_q->dma_tx = channel->desc_addr.desc_virt_addrs_base;
			tx_q->dma_tx_phy = channel->desc_addr.desc_dma_addrs_base;
		} else if (ch_dir == CH_DIR_RX) {
			find_free_rx_channel(ndev, channel);
			rx_q = &priv->rx_queue[channel->channel_num];
			rx_q->dma_rx = channel->desc_addr.desc_virt_addrs_base;
			rx_q->dma_rx_phy = channel->desc_addr.desc_dma_addrs_base;
		} else {
			netdev_err(priv->dev,
					"%s: ERROR: Invalid channel direction\n", __func__);
			goto err_invalid_ch_dir;
		}
	} else {
		/* Allocate resources for descriptor and buffer */

		if (ch_dir == CH_DIR_TX) {
			if (alloc_ipa_tx_resources(ndev, channel, (gfp_t)flags)) {
				netdev_err(priv->dev,
						"%s: ERROR: allocating Tx resources\n", __func__);
				goto err_invalid_mem_ops;
			}
		} else if (ch_dir == CH_DIR_RX) {
			if (alloc_ipa_rx_resources(ndev, channel, (gfp_t)flags)) {
				netdev_err(priv->dev,
						"%s: ERROR: allocating Rx resources\n", __func__);
				goto err_invalid_mem_ops;
			}
		} else {
			netdev_err(priv->dev,
					"%s: ERROR: Invalid channel direction\n", __func__);

			goto err_invalid_ch_dir;
		}

	}

	/* Configure DMA registers */
	if (ch_dir == CH_DIR_TX) {
		tc956xmac_init_ipa_tx_ch(priv, channel);
		tc956xmac_stop_tx(priv, priv->ioaddr, channel->channel_num);
	} else if (ch_dir == CH_DIR_RX) {
		tc956xmac_init_ipa_rx_ch(priv, channel);
		tc956xmac_stop_rx(priv, priv->ioaddr, channel->channel_num);
	} else {
		netdev_err(priv->dev,
				"%s: ERROR: Invalid channel direction\n", __func__);

		goto err_invalid_ch_dir;
	}

	return channel;

err_invalid_ch_dir:
err_invalid_mem_ops:
err_buff_dma_mem_alloc:
	kfree(channel->buff_pool_addr.buff_pool_va_addrs_base);
err_buff_mem_alloc:
	channel->desc_addr.desc_dma_addrs_base = 0;
	kfree(channel);

	return NULL;

}
EXPORT_SYMBOL_GPL(request_channel);


/*!
 * \brief Release the resources associated with the channel
 *	  and mark the channel as free in the TC956x driver,
 *	  reset the descriptors and registers
 *
 *	  The API will check for NULL pointers and Invalid arguments such as non IPA channel
 *
 * \param[in] ndev : TC956x netdev data structure
 * \param[in] channel : Pointer to structure containing channel_info that needs to be released
 *
 * \return : Return 0 on success, -ve value on error
 *	     -EPERM if non IPA channels are accessed
 *	     -ENODEV if ndev is NULL, tc956xmac_priv extracted from ndev is NULL
 *	     -EINVAL if channel pointer or memory buffers in channel pointer are NULL
 *
 * \remarks : DMA Channel has to be stopped prior to invoking this API
 */
int release_channel(struct net_device *ndev, struct channel_info *channel)
{
	struct tc956xmac_priv *priv;
	struct mem_ops *mem_ops;
	struct tc956xmac_tx_queue *tx_q;
	struct tc956xmac_rx_queue *rx_q;

	int ret = -EINVAL;

	if (!ndev) {
		pr_err("%s: ERROR: Invalid netdevice pointer\n", __func__);
		return -ENODEV;
	}

	priv = netdev_priv(ndev);
	if (!priv) {
		pr_err("%s: ERROR: Invalid private data pointer\n", __func__);
		return -ENODEV;
	}

	if (!channel) {
		netdev_err(priv->dev,
				"%s: ERROR: Invalid channel info structure\n", __func__);
		return -EINVAL;
	}

	if ((!channel->desc_addr.desc_virt_addrs_base) || (!channel->desc_addr.desc_dma_addrs_base) ||
		(!channel->buff_pool_addr.buff_pool_dma_addrs_base) || (!channel->buff_pool_addr.buff_pool_va_addrs_base)) {

		netdev_err(priv->dev,
				"%s: ERROR: Invalid memory pointers\n", __func__);
		return -EINVAL;
	}

	if ((channel->direction == CH_DIR_RX &&
		priv->plat->rx_dma_ch_owner[channel->channel_num] != USE_IN_OFFLOADER)) {
		netdev_err(priv->dev,
				"%s: ERROR: Invalid channel\n", __func__);
			return -EPERM;
	}

	if ((channel->direction == CH_DIR_TX &&
		priv->plat->tx_dma_ch_owner[channel->channel_num] != USE_IN_OFFLOADER)) {
		netdev_err(priv->dev,
				"%s: ERROR: Invalid channel\n", __func__);
			return -EPERM;
	}

	priv = netdev_priv(ndev);
	mem_ops = channel->mem_ops;

	if (mem_ops) {
		if (mem_ops->free_descs) {
			mem_ops->free_descs(ndev, NULL, channel->desc_size, NULL, mem_ops, channel);
			ret = 0;
		} else {
			netdev_err(priv->dev,
					"%s: ERROR: mem_ops is valid but free_descs is invalid\n", __func__);
			ret = -EINVAL;
			goto err_free_desc;
		}

		if (mem_ops->free_buf) {
			mem_ops->free_buf(ndev, NULL, channel->desc_size, NULL, mem_ops, channel);
			ret = 0;
		} else {
			netdev_err(priv->dev,
					"%s: ERROR: mem_ops is valid but free_buf is invalid\n", __func__);
			ret = -EINVAL;
			goto err_free_buff;
		}

		if (channel->direction == CH_DIR_TX) {
			priv->plat->tx_dma_ch_owner[channel->channel_num] = NOT_USED;

			tx_q = &priv->tx_queue[channel->channel_num];
			tx_q->priv_data = NULL;
			tx_q->dma_tx = NULL;
		} else if (channel->direction == CH_DIR_RX) {
			priv->plat->rx_dma_ch_owner[channel->channel_num] = NOT_USED;

			rx_q = &priv->rx_queue[channel->channel_num];
			rx_q->priv_data = NULL;
			rx_q->dma_rx = NULL;
		} else {
			netdev_err(priv->dev,
					"%s: ERROR: Invalid channel direction\n", __func__);
			ret = -EINVAL;
			goto err_invalid_ch_dir;
		}

	} else {

		if (channel->direction == CH_DIR_TX) {
			tc956xmac_stop_tx(priv, priv->ioaddr, channel->channel_num);
			dealloc_ipa_tx_resources(ndev, channel);
			ret = 0;
		} else if (channel->direction == CH_DIR_RX) {
			tc956xmac_stop_rx(priv, priv->ioaddr, channel->channel_num);
			dealloc_ipa_rx_resources(ndev, channel);
			ret = 0;
		} else {
			netdev_err(priv->dev,
					"%s: ERROR: Invalid channel direction\n", __func__);
			ret = -EINVAL;
			goto err_invalid_ch_dir;
		}
	}


err_free_desc:
err_free_buff:
err_invalid_ch_dir:
	kfree(channel->buff_pool_addr.buff_pool_va_addrs_base);
	channel->desc_addr.desc_dma_addrs_base = 0;
	kfree(channel);

	return ret;


}
EXPORT_SYMBOL_GPL(release_channel);


/*!
 * \brief Update the location in CM3 SRAM with a PCIe Write Address and
 *	  value for the associated channel. When Tx/Rx interrupts occur,
 *	  the FW will write the value to the PCIe location
 *
 *	  The API will check for NULL pointers and Invalid arguments such as,
 *	  non IPA channel, out of range CM3 accesesible PCIe address
 *
 * \param[in] ndev : TC956x netdev  data structure
 * \param[in] channel : Pointer to channel info containing the channel information
 * \param[in] addr : TAMAP'ed Address location to which the PCIe write is to be performed from CM3 FW
 *
 * \return : O for success if TAMAP'ed address of the PCIe location is within accessible range
 *	     -EPERM if non IPA channels are accessed, out of range PCIe access location for CM3
 *	     -ENODEV if ndev is NULL, tc956xmac_priv extracted from ndev is NULL
 *	     -EINVAL if channel pointer NULL
 *
 * \remarks : TAMAP will be set for 0x6000_0000 - 0xC000_0000 region.
 *	     PCIe write location should be within this region.
 *	     If this API is invoked for a channel without calling release_event(),
 *	     then the PCIe address and value for that channel will be overwritten
 */
int request_event(struct net_device *ndev, struct channel_info *channel, u32 addr)
{
	struct tc956xmac_priv *priv;

	if (!ndev) {
		pr_err("%s: ERROR: Invalid netdevice pointer\n", __func__);
		return -ENODEV;
	}

	priv = netdev_priv(ndev);
	if (!priv) {
		pr_err("%s: ERROR: Invalid private data pointer\n", __func__);
		return -ENODEV;
	}

	if (!channel) {
		netdev_err(priv->dev,
				"%s: ERROR: Invalid channel info structure\n", __func__);
		return -EINVAL;
	}

	if ((channel->direction == CH_DIR_RX &&
		priv->plat->rx_dma_ch_owner[channel->channel_num] != USE_IN_OFFLOADER)) {
		netdev_err(priv->dev,
				"%s: ERROR: Invalid channel\n", __func__);
			return -EPERM;
	}

	if ((channel->direction == CH_DIR_TX &&
		priv->plat->tx_dma_ch_owner[channel->channel_num] != USE_IN_OFFLOADER)) {
		netdev_err(priv->dev,
				"%s: ERROR: Invalid channel\n", __func__);
			return -EPERM;
	}

	if (addr < CM3_PCIE_REGION_LOW_BOUND || addr > CM3_PCIE_REGION_UP_BOUND) {
		netdev_err(priv->dev,
				"%s: ERROR: PCIe address out of range\n", __func__);
		return -EPERM;
	}

	if (channel->direction == CH_DIR_TX) {
#ifdef TC956X
		writel(addr, priv->tc956x_SRAM_pci_base_addr +
			SRAM_TX_PCIE_ADDR_LOC + (priv->port_num * TC956XMAC_CH_MAX * 4) +
			(channel->channel_num * 4));
#endif
	} else if (channel->direction == CH_DIR_RX) {
#ifdef TC956X
		writel(addr, priv->tc956x_SRAM_pci_base_addr +
			SRAM_RX_PCIE_ADDR_LOC + (priv->port_num * TC956XMAC_CH_MAX * 4) +
			(channel->channel_num * 4));
#endif
	} else {
		netdev_err(priv->dev,
				"%s: ERROR: Invalid channel direction\n", __func__);
		return -EINVAL;

	}
	return 0;
}
EXPORT_SYMBOL_GPL(request_event);


/*!
 * \brief Update the location in CM3 SRAM with a PCIe Write Address and
 *	  value for the associated channel to zero
 *
 *	  The API will check for NULL pointers and Invalid arguments such as non IPA channel
 *
 * \param[in] ndev : TC956x netdev data structure
 * \param[in] channel : Pointer to structure containing channel_info that needs to be released
 *
 * \return : Return 0 on success, -ve value on error
 *	     -EPERM if non IPA channels are accessed
 *	     -ENODEV if ndev is NULL, tc956xmac_priv extracted from ndev is NULL
 *	     -EINVAL if channel pointer NULL
 */
int release_event(struct net_device *ndev, struct channel_info *channel)
{
	struct tc956xmac_priv *priv;

	if (!ndev) {
		pr_err("%s: ERROR: Invalid netdevice pointer\n", __func__);
		return -ENODEV;
	}

	priv = netdev_priv(ndev);
	if (!priv) {
		pr_err("%s: ERROR: Invalid private data pointer\n", __func__);
		return -ENODEV;
	}

	if (!channel) {
		netdev_err(priv->dev,
				"%s: ERROR: Invalid channel info structure\n", __func__);
		return -EINVAL;
	}

	if ((channel->direction == CH_DIR_RX &&
		priv->plat->rx_dma_ch_owner[channel->channel_num] != USE_IN_OFFLOADER)) {
		netdev_err(priv->dev,
				"%s: ERROR: Invalid channel\n", __func__);
			return -EPERM;
	}

	if ((channel->direction == CH_DIR_TX &&
		priv->plat->tx_dma_ch_owner[channel->channel_num] != USE_IN_OFFLOADER)) {
		netdev_err(priv->dev,
				"%s: ERROR: Invalid channel\n", __func__);
			return -EPERM;
	}

	if (channel->direction == CH_DIR_TX) {
#ifdef TC956X
		writel(0, priv->tc956x_SRAM_pci_base_addr +
			SRAM_TX_PCIE_ADDR_LOC + (priv->port_num * TC956XMAC_CH_MAX * 4) +
			(channel->channel_num * 4));
#endif

	} else if (channel->direction == CH_DIR_RX) {
#ifdef TC956X
		writel(0, priv->tc956x_SRAM_pci_base_addr +
			SRAM_RX_PCIE_ADDR_LOC + (priv->port_num * TC956XMAC_CH_MAX * 4) +
			(channel->channel_num * 4));
#endif
	} else {
		netdev_err(priv->dev,
				"%s: ERROR: Invalid channel direction\n", __func__);
		return -EINVAL;

	}
	return 0;
}
EXPORT_SYMBOL_GPL(release_event);


/*!
 * \brief Enable interrupt generation for given channel
 *
 * The API will check for NULL pointers and Invalid arguments such as non IPA channel
 *
 * \param[in] ndev : TC956x netdev data structure
 * \param[in] channel : Pointer to structure containing channel_info that needs to be released
 * \return : Return 0 on success, -ve value on error
 *	     -EPERM if non IPA channels are accessed
 *	     -ENODEV if ndev is NULL, tc956xmac_priv extracted from ndev is NULL
 *	     -EINVAL if channel pointer NULL
 */
int enable_event(struct net_device *ndev, struct channel_info *channel)
{
	struct tc956xmac_priv *priv;
	u32 reg;

	if (!ndev) {
		pr_err("%s: ERROR: Invalid netdevice pointer\n", __func__);
		return -ENODEV;
	}

	priv = netdev_priv(ndev);
	if (!priv) {
		pr_err("%s: ERROR: Invalid private data pointer\n", __func__);
		return -ENODEV;
	}

	if (!channel) {
		netdev_err(priv->dev,
				"%s: ERROR: Invalid channel info structure\n", __func__);
		return -EINVAL;
	}

	if ((channel->direction == CH_DIR_RX &&
		priv->plat->rx_dma_ch_owner[channel->channel_num] != USE_IN_OFFLOADER)) {
		netdev_err(priv->dev,
				"%s: ERROR: Invalid channel\n", __func__);
			return -EPERM;
	}

	if ((channel->direction == CH_DIR_TX &&
		priv->plat->tx_dma_ch_owner[channel->channel_num] != USE_IN_OFFLOADER)) {
		netdev_err(priv->dev,
				"%s: ERROR: Invalid channel\n", __func__);
			return -EPERM;
	}

	if (channel->direction == CH_DIR_TX) {
#ifdef TC956X
		if (priv->port_num == RM_PF0_ID) {
			reg = readl(priv->ioaddr + INTMCUMASK0);
			reg &= ~(1 << (INTMCUMASK_TX_CH0 + channel->channel_num));
			writel(reg, priv->ioaddr + INTMCUMASK0);
		}

		if (priv->port_num == RM_PF1_ID) {
			reg = readl(priv->ioaddr + INTMCUMASK1);
			reg &= ~(1 << (INTMCUMASK_TX_CH0 + channel->channel_num));
			writel(reg, priv->ioaddr + INTMCUMASK1);
		}
#endif

	} else if (channel->direction == CH_DIR_RX) {
#ifdef TC956X
		if (priv->port_num == RM_PF0_ID) {
			reg = readl(priv->ioaddr + INTMCUMASK0);
			reg &= ~(1 << (INTMCUMASK_RX_CH0 + channel->channel_num));
			writel(reg, priv->ioaddr + INTMCUMASK0);
		}

		if (priv->port_num == RM_PF1_ID) {
			reg = readl(priv->ioaddr + INTMCUMASK1);
			reg &= ~(1 << (INTMCUMASK_RX_CH0 + channel->channel_num));
			writel(reg, priv->ioaddr + INTMCUMASK1);
		}
#endif

	} else {
		netdev_err(priv->dev,
				"%s: ERROR: Invalid channel direction\n", __func__);
		return -EINVAL;

	}
	return 0;
}
EXPORT_SYMBOL_GPL(enable_event);

/*!
 * \brief Disable interrupt generation for given channel
 *
 *	  The API will check for NULL pointers and Invalid arguments such as non IPA channel
 *
 * \param[in] ndev : TC956x netdev data structure
 * \param[in] channel : Pointer to structure containing channel_info that needs to be released
 * \return : Return 0 on success, -ve value on error
 *	     -EPERM if non IPA channels are accessed
 *	     -ENODEV if ndev is NULL, tc956xmac_priv extracted from ndev is NULL
 *	     -EINVAL if channel pointer NULL
 */
int disable_event(struct net_device *ndev, struct channel_info *channel)
{
	struct tc956xmac_priv *priv;
	u32 reg;

	if (!ndev) {
		pr_err("%s: ERROR: Invalid netdevice pointer\n", __func__);
		return -ENODEV;
	}

	priv = netdev_priv(ndev);
	if (!priv) {
		pr_err("%s: ERROR: Invalid private data pointer\n", __func__);
		return -ENODEV;
	}

	if (!channel) {
		netdev_err(priv->dev,
				"%s: ERROR: Invalid channel info structure\n", __func__);
		return -EINVAL;
	}

	if ((channel->direction == CH_DIR_RX &&
		priv->plat->rx_dma_ch_owner[channel->channel_num] != USE_IN_OFFLOADER)) {
		netdev_err(priv->dev,
				"%s: ERROR: Invalid channel\n", __func__);
			return -EPERM;
	}

	if ((channel->direction == CH_DIR_TX &&
		priv->plat->tx_dma_ch_owner[channel->channel_num] != USE_IN_OFFLOADER)) {
		netdev_err(priv->dev,
				"%s: ERROR: Invalid channel\n", __func__);
			return -EPERM;
	}

	if (channel->direction == CH_DIR_TX) {
		if (priv->port_num == RM_PF0_ID) {
			reg = readl(priv->ioaddr + INTMCUMASK0);
			reg |= (1 << (INTMCUMASK_TX_CH0 + channel->channel_num));
			writel(reg, priv->ioaddr + INTMCUMASK0);
		}

		if (priv->port_num == RM_PF1_ID) {
			reg = readl(priv->ioaddr + INTMCUMASK1);
			reg |= (1 << (INTMCUMASK_TX_CH0 + channel->channel_num));
			writel(reg, priv->ioaddr + INTMCUMASK1);
		}

	} else if (channel->direction == CH_DIR_RX) {
		if (priv->port_num == RM_PF0_ID) {
			reg = readl(priv->ioaddr + INTMCUMASK0);
			reg |= (1 << (INTMCUMASK_RX_CH0 + channel->channel_num));
			writel(reg, priv->ioaddr + INTMCUMASK0);
		}

		if (priv->port_num == RM_PF1_ID) {
			reg = readl(priv->ioaddr + INTMCUMASK1);
			reg |= (1 << (INTMCUMASK_RX_CH0 + channel->channel_num));
			writel(reg, priv->ioaddr + INTMCUMASK1);
		}

	} else {
		netdev_err(priv->dev,
				"%s: ERROR: Invalid channel direction\n", __func__);
		return -EINVAL;

	}
	return 0;
}
EXPORT_SYMBOL_GPL(disable_event);

/*!
 * \brief Control the Rx DMA interrupt generation by modfying the Rx WDT timer
 *
 *	  The API will check for NULL pointers and Invalid arguments such as,
 *	  non IPA channel, event moderation for Tx path
 *
 * \param[in] ndev : TC956x netdev data structure
 * \param[in] channel : Pointer to structure containing channel_info that needs to be released
 * \param[in] wdt : Watchdog timeout value in clock cycles
 *
 * \return : Return 0 on success, -ve value on error
 *	     -EPERM if non IPA channels are accessed, IPA Tx channel
 *	     -ENODEV if ndev is NULL, tc956xmac_priv extracted from ndev is NULL
 *	     -EINVAL if channel pointer NULL
 */
int set_event_mod(struct net_device *ndev, struct channel_info *channel, unsigned int wdt)
{
	struct tc956xmac_priv *priv;

	if (!ndev) {
		pr_err("%s: ERROR: Invalid netdevice pointer\n", __func__);
		return -ENODEV;
	}

	priv = netdev_priv(ndev);
	if (!priv) {
		pr_err("%s: ERROR: Invalid private data pointer\n", __func__);
		return -ENODEV;
	}

	if (!channel) {
		netdev_err(priv->dev,
				"%s: ERROR: Invalid channel info structure\n", __func__);
		return -EINVAL;
	}

	if ((priv->plat->rx_dma_ch_owner[channel->channel_num] != USE_IN_OFFLOADER) ||
		channel->direction == CH_DIR_TX) {

		netdev_err(priv->dev,
				"%s: ERROR: Invalid channel\n", __func__);
		return -EPERM;
	}

	if (wdt > MAX_WDT) {
		netdev_err(priv->dev,
				"%s: ERROR: Timeout value Out of range\n", __func__);
		return -EINVAL;
	}
#ifdef TC956X
	writel(wdt & XGMAC_RWT, priv->ioaddr + XGMAC_DMA_CH_Rx_WATCHDOG(channel->channel_num));
#endif

	return 0;
}
EXPORT_SYMBOL_GPL(set_event_mod);

/*!
 * \brief This API will configure the FRP table with the parameters passed through rx_filter_info.
 *
 *	  The API will check for NULL pointers and Invalid arguments such as non IPA channel,
 *	  number of filter entries > 72
 *
 * \param[in] ndev : TC956x netdev data structure
 * \param[in] filter_params: filter_params containig the parameters based on which packet will pass or drop
 * \return : Return 0 on success, -ve value on error
 *	     -ENODEV if ndev is NULL, tc956xmac_priv extracted from ndev is NULL
 *	     -EINVAL filter_params, if number of entries > 72
 *
 * \remarks : The entries should be prepared considering the filtering and routing to CortexA also
 *	      MAC Rx will be stopped while updating FRP table dynamically.
 */
int set_rx_filter(struct net_device *ndev, struct rx_filter_info *filter_params)
{
	struct tc956xmac_priv *priv;
	struct tc956xmac_rx_parser_cfg *cfg;
	u32 ret = -EINVAL;

	if (!ndev) {
		pr_err("%s: ERROR: Invalid netdevice pointer\n", __func__);
		return -ENODEV;
	}

	priv = netdev_priv(ndev);
	if (!priv) {
		pr_err("%s: ERROR: Invalid private data pointer\n", __func__);
		return -ENODEV;
	}

	if (!filter_params) {
		netdev_err(priv->dev,
				"%s: ERROR: Invalid filter parameters structure\n", __func__);
		return -EINVAL;
	}

	if (filter_params->npe > MAX_PARSABLE_FRP_ENTRIES) {
		netdev_err(priv->dev,
				"%s: ERROR: No. of FRP entries exceed maximum parsable entries of %d\n",
				__func__, MAX_PARSABLE_FRP_ENTRIES);
		return -EINVAL;
	}

	cfg = &priv->plat->rxp_cfg;

	cfg->nve = filter_params->nve;
	cfg->npe = filter_params->npe;
	memcpy(cfg->entries, filter_params->entries, filter_params->nve * sizeof(filter_params->entries[0]));

	priv->plat->rxp_cfg.enable = true;
	ret = tc956xmac_rx_parser_configuration(priv);

	return ret;

}
EXPORT_SYMBOL_GPL(set_rx_filter);

/*!
 * \brief This API will clear the FRP filters and route all packets to RxCh0
 *
 *	 The API will check for NULL pointers
 *
 * \param[in] ndev : TC956x netdev data structure
 * \return : Return 0 on success, -ve value on error
 *	     -ENODEV if ndev is NULL, tc956xmac_priv extracted from ndev is NULL
 *
 * \remarks : MAC Rx will be stopped while updating FRP table dynamically.

 */
int clear_rx_filter(struct net_device *ndev)
{
	struct tc956xmac_priv *priv;
	struct tc956xmac_rx_parser_cfg *cfg;
	struct rxp_filter_entry filter_entries;
	u32 ret = -EINVAL;

	if (!ndev) {
		pr_err("%s: ERROR: Invalid netdevice pointer\n", __func__);
		return -ENODEV;
	}

	priv = netdev_priv(ndev);
	if (!priv) {
		pr_err("%s: ERROR: Invalid private data pointer\n", __func__);
		return -ENODEV;
	}
#ifdef TC956X
	/* Create FRP entries to route all packets to RxCh0 */
	filter_entries.match_data = 0x00000000;
	filter_entries.match_en = 0x00000000;
	filter_entries.af = 1;
	filter_entries.rf = 0;
	filter_entries.im = 0;
	filter_entries.nc = 0;
	filter_entries.res1 = 0;
	filter_entries.frame_offset = 0;
	filter_entries.res2 = 0;
	filter_entries.ok_index = 0;
	filter_entries.res3 = 0;
	filter_entries.dma_ch_no = 1;
	filter_entries.res4 = 0;
#endif

	cfg = &priv->plat->rxp_cfg;

	cfg->nve = 1;
	cfg->npe = 1;

	memcpy(cfg->entries, &filter_entries, cfg->nve * sizeof(struct rxp_filter_entry));

	ret = tc956xmac_rx_parser_configuration(priv);

	return ret;
}
EXPORT_SYMBOL_GPL(clear_rx_filter);

/*!
 * \brief Start the DMA channel. channel_dir member variable
 *	  will be used to start the Tx/Rx channel
 *
 *	  The API will check for NULL pointers and Invalid arguments such as non IPA channel
 *
 * \param[in] ndev : TC956x netdev data structure
 * \param[in] channel : Pointer to structure containing channel_info that needs to be released
 *
 * \return : Return 0 on success, -ve value on error
 *	     -EPERM if non IPA channels are accessed
 *	     -ENODEV if ndev is NULL, tc956xmac_priv extracted from ndev is NULL
 *	     -EINVAL if channel pointer NULL

 */
int start_channel(struct net_device *ndev, struct channel_info *channel)
{
	struct tc956xmac_priv *priv;

	if (!ndev) {
		pr_err("%s: ERROR: Invalid netdevice pointer\n", __func__);
		return -ENODEV;
	}

	priv = netdev_priv(ndev);
	if (!priv) {
		pr_err("%s: ERROR: Invalid private data pointer\n", __func__);
		return -ENODEV;
	}

	if (!channel) {
		netdev_err(priv->dev,
				"%s: ERROR: Invalid channel info structure\n", __func__);
		return -EINVAL;
	}

	if ((channel->direction == CH_DIR_RX &&
		priv->plat->rx_dma_ch_owner[channel->channel_num] != USE_IN_OFFLOADER)) {
		netdev_err(priv->dev,
				"%s: ERROR: Invalid channel\n", __func__);
			return -EPERM;
	}

	if ((channel->direction == CH_DIR_TX &&
		priv->plat->tx_dma_ch_owner[channel->channel_num] != USE_IN_OFFLOADER)) {
		netdev_err(priv->dev,
				"%s: ERROR: Invalid channel\n", __func__);
			return -EPERM;
	}

	if (channel->direction == CH_DIR_TX) {
		netdev_dbg(priv->dev, "DMA Tx process started in channel = %d\n", channel->channel_num);
		tc956xmac_start_tx(priv, priv->ioaddr, channel->channel_num);
	} else if (channel->direction == CH_DIR_RX) {
		netdev_dbg(priv->dev, "DMA Rx process started in channel = %d\n", channel->channel_num);
		tc956xmac_start_rx(priv, priv->ioaddr, channel->channel_num);
	} else {
		netdev_err(priv->dev,
				"%s: ERROR: Invalid channel\n", __func__);
		return -EPERM;
	}

	return 0;
}
EXPORT_SYMBOL_GPL(start_channel);

/*!
 * \brief Stop the DMA channel. channel_dir member variable will be
 *	  used to stop the Tx/Rx channel. In case of Rx, clear the
 *	  MTL queue associated with the channel and this will result in packet drops
 *
 *	  The API will check for NULL pointers and Invalid arguments such as non IPA channel
 *
 * \param[in] ndev : TC956x netdev data structure
 * \param[in] channel : Pointer to structure containing channel_info that needs to be released
 *
 * \return : Return 0 on success, -ve value on error
 *	     -EPERM if non IPA channels are accessed
 *	     -ENODEV if ndev is NULL, tc956xmac_priv extracted from ndev is NULL
 *	     -EINVAL if channel pointer  NULL
 */
int stop_channel(struct net_device *ndev, struct channel_info *channel)
{
	struct tc956xmac_priv *priv;

	if (!ndev) {
		pr_err("%s: ERROR: Invalid netdevice pointer\n", __func__);
		return -ENODEV;
	}

	priv = netdev_priv(ndev);
	if (!priv) {
		pr_err("%s: ERROR: Invalid private data pointer\n", __func__);
		return -ENODEV;
	}

	if (!channel) {
		netdev_err(priv->dev,
				"%s: ERROR: Invalid channel info structure\n", __func__);
		return -EINVAL;
	}

	if ((channel->direction == CH_DIR_RX &&
		priv->plat->rx_dma_ch_owner[channel->channel_num] != USE_IN_OFFLOADER)) {
		netdev_err(priv->dev,
				"%s: ERROR: Invalid channel\n", __func__);
			return -EPERM;
	}

	if ((channel->direction == CH_DIR_TX &&
		priv->plat->tx_dma_ch_owner[channel->channel_num] != USE_IN_OFFLOADER)) {
		netdev_err(priv->dev,
				"%s: ERROR: Invalid channel\n", __func__);
			return -EPERM;
	}

	if (channel->direction == CH_DIR_TX) {
		netdev_dbg(priv->dev, "DMA Tx process stopped in channel = %d\n", channel->channel_num);
		tc956xmac_stop_tx(priv, priv->ioaddr, channel->channel_num);
	} else if (channel->direction == CH_DIR_RX) {
		netdev_dbg(priv->dev, "DMA Rx process stopped in channel = %d\n", channel->channel_num);
		tc956xmac_stop_rx(priv, priv->ioaddr, channel->channel_num);
	} else {
		netdev_err(priv->dev,
				"%s: ERROR: Invalid channel\n", __func__);
		return -EPERM;
	}

	return 0;
}
EXPORT_SYMBOL_GPL(stop_channel);

/*!
 * \brief This API will print EMAC-IPA offload DMA channel stats
 *
 * \details This function will read and prints DMA Descriptor stats
 * used by IPA.
 *
 * \param[in] ndev : TC956x netdev data structure.
 *
 * \return : Return 0 on success, -ve value on error
 *           -ENODEV if ndev is NULL, tc956xmac_priv extracted from ndev is NULL
 */
int read_ipa_desc_stats(struct net_device *ndev)
{
	int chno = 0;
	struct tc956xmac_priv *priv;

	if (!ndev) {
		pr_err("%s: ERROR: Invalid netdevice pointer\n", __func__);
		return -ENODEV;
	}

	priv = netdev_priv(ndev);
	if (!priv) {
		pr_err("%s: ERROR: Invalid private data pointer\n", __func__);
		return -ENODEV;
	}

	/* TX DMA Descriptors Status for all channels */
	for (chno = 0; chno < priv->plat->tx_queues_to_use; chno++) {

		if (priv->plat->tx_dma_ch_owner[chno] != USE_IN_OFFLOADER)
			continue;

		netdev_info(priv->dev, "%s : txch_status[%d] : 0x%08x", __func__, chno, readl(priv->ioaddr + XGMAC_DMA_CH_STATUS(chno)));
		netdev_info(priv->dev, "%s : txch_control[%d] : 0x%08x", __func__, chno, readl(priv->ioaddr + XGMAC_DMA_CH_TX_CONTROL(chno)));
		netdev_info(priv->dev, "%s : txch_desc_list_haddr[%d] : 0x%08x", __func__, chno, readl(priv->ioaddr + XGMAC_DMA_CH_TxDESC_HADDR(chno)));
		netdev_info(priv->dev, "%s : txch_desc_list_laddr[%d] : 0x%08x", __func__, chno, readl(priv->ioaddr + XGMAC_DMA_CH_TxDESC_LADDR(chno)));
		netdev_info(priv->dev, "%s : txch_desc_ring_len[%d] : 0x%08x", __func__, chno, readl(priv->ioaddr + XGMAC_DMA_CH_TX_CONTROL2(chno)));
		netdev_info(priv->dev, "%s : txch_desc_curr_haddr[%d] : 0x%08x", __func__, chno, readl(priv->ioaddr + XGMAC_DMA_CH_Cur_TxDESC_HADDR(chno)));
		netdev_info(priv->dev, "%s : txch_desc_curr_laddr[%d] : 0x%08x", __func__, chno, readl(priv->ioaddr + XGMAC_DMA_CH_Cur_TxDESC_LADDR(chno)));
		netdev_info(priv->dev, "%s : txch_desc_tail[%d] : 0x%08x", __func__, chno, readl(priv->ioaddr + XGMAC_DMA_CH_TxDESC_TAIL_LPTR(chno)));
		netdev_info(priv->dev, "%s : txch_desc_buf_haddr[%d] : 0x%08x", __func__, chno, readl(priv->ioaddr + XGMAC_DMA_CH_Cur_TxBuff_HADDR(chno)));
		netdev_info(priv->dev, "%s : txch_desc_buf_laddr[%d] : 0x%08x", __func__, chno, readl(priv->ioaddr + XGMAC_DMA_CH_Cur_TxBuff_LADDR(chno)));
		netdev_info(priv->dev, "%s : txch_dma_interrupt_en[%d] : 0x%08x", __func__, chno, readl(priv->ioaddr + XGMAC_DMA_CH_INT_EN(chno)));
	}

	/* RX DMA Descriptors Status for all channels */
	for (chno = 0; chno < TC956XMAC_CH_MAX; chno++) {

		if (priv->plat->rx_dma_ch_owner[chno] != USE_IN_OFFLOADER)
			continue;

		netdev_info(priv->dev, "%s : rxch_status[%d] : 0x%08x", __func__, chno, readl(priv->ioaddr + XGMAC_DMA_CH_STATUS(chno)));
		netdev_info(priv->dev, "%s : rxch_control[%d] : 0x%08x", __func__, chno, readl(priv->ioaddr + XGMAC_DMA_CH_RX_CONTROL(chno)));
		netdev_info(priv->dev, "%s : rxch_desc_list_haddr[%d] : 0x%08x", __func__, chno, readl(priv->ioaddr + XGMAC_DMA_CH_RxDESC_HADDR(chno)));
		netdev_info(priv->dev, "%s : rxch_desc_list_laddr[%d] : 0x%08x", __func__, chno, readl(priv->ioaddr + XGMAC_DMA_CH_RxDESC_LADDR(chno)));
		netdev_info(priv->dev, "%s : rxch_desc_ring_len[%d] : 0x%08x", __func__, chno, readl(priv->ioaddr + XGMAC_DMA_CH_RX_CONTROL2(chno)));
		netdev_info(priv->dev, "%s : rxch_desc_curr_haddr[%d] : 0x%08x", __func__, chno, readl(priv->ioaddr + XGMAC_DMA_CH_Cur_RxDESC_HADDR(chno)));
		netdev_info(priv->dev, "%s : rxch_desc_curr_laddr[%d] : 0x%08x", __func__, chno, readl(priv->ioaddr + XGMAC_DMA_CH_Cur_RxDESC_LADDR(chno)));
		netdev_info(priv->dev, "%s : rxch_desc_tail[%d] : 0x%08x", __func__, chno, readl(priv->ioaddr + XGMAC_DMA_CH_RxDESC_TAIL_LPTR(chno)));
		netdev_info(priv->dev, "%s : rxch_desc_buf_haddr[%d] : 0x%08x", __func__, chno, readl(priv->ioaddr + XGMAC_DMA_CH_Cur_RxBuff_HADDR(chno)));
		netdev_info(priv->dev, "%s : rxch_desc_buf_laddr[%d] : 0x%08x", __func__, chno, readl(priv->ioaddr + XGMAC_DMA_CH_Cur_RxBuff_LADDR(chno)));
		netdev_info(priv->dev, "%s : rxch_dma_interrupt_en[%d] : 0x%08x", __func__, chno, readl(priv->ioaddr + XGMAC_DMA_CH_INT_EN(chno)));
	}

	return 0;
}
EXPORT_SYMBOL_GPL(read_ipa_desc_stats);
