// SPDX-License-Identifier: GPL-2.0-only
/*
################################################################################
#
# r8125 is the Linux device driver released for Realtek 2.5Gigabit Ethernet
# controllers with PCI-Express interface.
#
# Copyright(c) 2021 Realtek Semiconductor Corp. All rights reserved.
#
# This program is free software; you can redistribute it and/or modify it
# under the terms of the GNU General Public License as published by the Free
# Software Foundation; either version 2 of the License, or (at your option)
# any later version.
#
# This program is distributed in the hope that it will be useful, but WITHOUT
# ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or
# FITNESS FOR A PARTICULAR PURPOSE.  See the GNU General Public License for
# more details.
#
# You should have received a copy of the GNU General Public License along with
# this program; if not, see <http://www.gnu.org/licenses/>.
#
# Author:
# Realtek NIC software team <nicfae@realtek.com>
# No. 2, Innovation Road II, Hsinchu Science Park, Hsinchu 300, Taiwan
#
################################################################################
*/

/************************************************************************************
 *  This product is covered by one or more of the following patents:
 *  US6,570,884, US6,115,776, and US6,327,625.
 ***********************************************************************************/

/*
 * This driver is modified from r8169.c in Linux kernel 2.6.18
 */

#include <linux/module.h>
#include <linux/version.h>
#include <linux/pci.h>
#include <linux/netdevice.h>
#include <linux/etherdevice.h>
#include <linux/delay.h>
#include <linux/mii.h>
#include <linux/if_vlan.h>
#include <linux/crc32.h>
#include <linux/interrupt.h>
#include <linux/in.h>
#include <linux/ip.h>
#if LINUX_VERSION_CODE >= KERNEL_VERSION(2,6,22)
#include <linux/ipv6.h>
#include <net/ip6_checksum.h>
#endif
#include <linux/tcp.h>
#include <linux/init.h>
#include <linux/rtnetlink.h>
#include <linux/completion.h>

#if LINUX_VERSION_CODE >= KERNEL_VERSION(2,6,26)
#if LINUX_VERSION_CODE < KERNEL_VERSION(5,4,0)
#include <linux/pci-aspm.h>
#endif
#endif
#if LINUX_VERSION_CODE >= KERNEL_VERSION(2,4,37)
#include <linux/prefetch.h>
#endif

#if LINUX_VERSION_CODE < KERNEL_VERSION(2,6,0)
#define dev_printk(A,B,fmt,args...) printk(A fmt,##args)
#else
#include <linux/dma-mapping.h>
#include <linux/moduleparam.h>
#endif

#if LINUX_VERSION_CODE >= KERNEL_VERSION(2,6,31)
#include <linux/mdio.h>
#endif

#include <asm/io.h>
#include <asm/irq.h>

#include "r8125.h"
#include "rtl_eeprom.h"
#include "rtltool.h"
#include "r8125_firmware.h"

#ifdef ENABLE_R8125_PROCFS
#include <linux/proc_fs.h>
#include <linux/seq_file.h>
#endif

#define FIRMWARE_8125A_3	"rtl_nic/rtl8125a-3.fw"
#define FIRMWARE_8125B_2	"rtl_nic/rtl8125b-2.fw"

/* Maximum number of multicast addresses to filter (vs. Rx-all-multicast).
   The RTL chips use a 64 element hash table based on the Ethernet CRC. */
static const int multicast_filter_limit = 32;

static const struct {
        const char *name;
        const char *fw_name;
} rtl_chip_fw_infos[] = {
        /* PCI-E devices. */
        [CFG_METHOD_2] = {"RTL8125A"				},
        [CFG_METHOD_3] = {"RTL8125A",		FIRMWARE_8125A_3},
        [CFG_METHOD_4] = {"RTL8125B",                       },
        [CFG_METHOD_5] = {"RTL8125B",		FIRMWARE_8125B_2},
        [CFG_METHOD_DEFAULT] = {"Unknown",                  },
};

#define _R(NAME,MAC,RCR,MASK,JumFrameSz) \
    { .name = NAME, .mcfg = MAC, .RCR_Cfg = RCR, .RxConfigMask = MASK, .jumbo_frame_sz = JumFrameSz }

static const struct {
        const char *name;
        u8 mcfg;
        u32 RCR_Cfg;
        u32 RxConfigMask;   /* Clears the bits supported by this chip */
        u32 jumbo_frame_sz;
} rtl_chip_info[] = {
        _R("RTL8125A",
        CFG_METHOD_2,
        BIT_30 | EnableInnerVlan | EnableOuterVlan | (RX_DMA_BURST << RxCfgDMAShift),
        0xff7e5880,
        Jumbo_Frame_9k),

        _R("RTL8125A",
        CFG_METHOD_3,
        BIT_30 | EnableInnerVlan | EnableOuterVlan | (RX_DMA_BURST << RxCfgDMAShift),
        0xff7e5880,
        Jumbo_Frame_9k),

        _R("RTL8125B",
        CFG_METHOD_4,
        BIT_30 | RxCfg_pause_slot_en | EnableInnerVlan | EnableOuterVlan | (RX_DMA_BURST << RxCfgDMAShift),
        0xff7e5880,
        Jumbo_Frame_9k),

        _R("RTL8125B",
        CFG_METHOD_5,
        BIT_30 | RxCfg_pause_slot_en | EnableInnerVlan | EnableOuterVlan | (RX_DMA_BURST << RxCfgDMAShift),
        0xff7e5880,
        Jumbo_Frame_9k),

        _R("Unknown",
        CFG_METHOD_DEFAULT,
        (RX_DMA_BURST << RxCfgDMAShift),
        0xff7e5880,
        Jumbo_Frame_1k)
};
#undef _R


#ifndef PCI_VENDOR_ID_DLINK
#define PCI_VENDOR_ID_DLINK 0x1186
#endif

static struct pci_device_id rtl8125_pci_tbl[] = {
        { PCI_DEVICE(PCI_VENDOR_ID_REALTEK, 0x8125), },
        { PCI_DEVICE(PCI_VENDOR_ID_REALTEK, 0x3000), },
        {0,},
};

MODULE_DEVICE_TABLE(pci, rtl8125_pci_tbl);

static int rx_copybreak = 0;
static int use_dac = 1;
static int timer_count = 0x2600;
static int timer_count_v2 = (0x2600 / 0x100);

static struct {
        u32 msg_enable;
} debug = { -1 };

static unsigned int speed_mode = SPEED_2500;
static unsigned int duplex_mode = DUPLEX_FULL;
static unsigned int autoneg_mode = AUTONEG_ENABLE;
static unsigned int advertising_mode =  ADVERTISED_10baseT_Half |
                                        ADVERTISED_10baseT_Full |
                                        ADVERTISED_100baseT_Half |
                                        ADVERTISED_100baseT_Full |
                                        ADVERTISED_1000baseT_Half |
                                        ADVERTISED_1000baseT_Full |
                                        ADVERTISED_2500baseX_Full;
#ifdef CONFIG_ASPM
static int aspm = 1;
#else
static int aspm = 0;
#endif
#ifdef ENABLE_S5WOL
static int s5wol = 1;
#else
static int s5wol = 0;
#endif
#ifdef ENABLE_S5_KEEP_CURR_MAC
static int s5_keep_curr_mac = 1;
#else
static int s5_keep_curr_mac = 0;
#endif
#ifdef ENABLE_EEE
static int eee_enable = 1;
#else
static int eee_enable = 0;
#endif
#ifdef CONFIG_SOC_LAN
static ulong hwoptimize = HW_PATCH_SOC_LAN;
#else
static ulong hwoptimize = 0;
#endif
#ifdef ENABLE_S0_MAGIC_PACKET
static int s0_magic_packet = 1;
#else
static int s0_magic_packet = 0;
#endif
#ifdef ENABLE_TX_NO_CLOSE
static int tx_no_close_enable = 1;
#else
static int tx_no_close_enable = 0;
#endif
#ifdef ENABLE_PTP_MASTER_MODE
static int enable_ptp_master_mode = 1;
#else
static int enable_ptp_master_mode = 0;
#endif

MODULE_AUTHOR("Realtek and the Linux r8125 crew <netdev@vger.kernel.org>");
MODULE_DESCRIPTION("Realtek RTL8125 2.5Gigabit Ethernet driver");

module_param(speed_mode, uint, 0);
MODULE_PARM_DESC(speed_mode, "force phy operation. Deprecated by ethtool (8).");

module_param(duplex_mode, uint, 0);
MODULE_PARM_DESC(duplex_mode, "force phy operation. Deprecated by ethtool (8).");

module_param(autoneg_mode, uint, 0);
MODULE_PARM_DESC(autoneg_mode, "force phy operation. Deprecated by ethtool (8).");

module_param(advertising_mode, uint, 0);
MODULE_PARM_DESC(advertising_mode, "force phy operation. Deprecated by ethtool (8).");

module_param(aspm, int, 0);
MODULE_PARM_DESC(aspm, "Enable ASPM.");

module_param(s5wol, int, 0);
MODULE_PARM_DESC(s5wol, "Enable Shutdown Wake On Lan.");

module_param(s5_keep_curr_mac, int, 0);
MODULE_PARM_DESC(s5_keep_curr_mac, "Enable Shutdown Keep Current MAC Address.");

module_param(rx_copybreak, int, 0);
MODULE_PARM_DESC(rx_copybreak, "Copy breakpoint for copy-only-tiny-frames");

module_param(use_dac, int, 0);
MODULE_PARM_DESC(use_dac, "Enable PCI DAC. Unsafe on 32 bit PCI slot.");

module_param(timer_count, int, 0);
MODULE_PARM_DESC(timer_count, "Timer Interrupt Interval.");

module_param(eee_enable, int, 0);
MODULE_PARM_DESC(eee_enable, "Enable Energy Efficient Ethernet.");

module_param(hwoptimize, ulong, 0);
MODULE_PARM_DESC(hwoptimize, "Enable HW optimization function.");

module_param(s0_magic_packet, int, 0);
MODULE_PARM_DESC(s0_magic_packet, "Enable S0 Magic Packet.");

module_param(tx_no_close_enable, int, 0);
MODULE_PARM_DESC(tx_no_close_enable, "Enable TX No Close.");

module_param(enable_ptp_master_mode, int, 0);
MODULE_PARM_DESC(enable_ptp_master_mode, "Enable PTP Master Mode.");

#if LINUX_VERSION_CODE > KERNEL_VERSION(2,6,0)
module_param_named(debug, debug.msg_enable, int, 0);
MODULE_PARM_DESC(debug, "Debug verbosity level (0=none, ..., 16=all)");
#endif//LINUX_VERSION_CODE > KERNEL_VERSION(2,6,0)

MODULE_LICENSE("GPL");
#ifdef ENABLE_USE_FIRMWARE_FILE
MODULE_FIRMWARE(FIRMWARE_8125A_3);
MODULE_FIRMWARE(FIRMWARE_8125B_2);
#endif

MODULE_VERSION(RTL8125_VERSION);

#if LINUX_VERSION_CODE < KERNEL_VERSION(4,14,0)
static void rtl8125_esd_timer(unsigned long __opaque);
#else
static void rtl8125_esd_timer(struct timer_list *t);
#endif
/*
#if LINUX_VERSION_CODE < KERNEL_VERSION(4,14,0)
static void rtl8125_link_timer(unsigned long __opaque);
#else
static void rtl8125_link_timer(struct timer_list *t);
#endif
*/

static netdev_tx_t rtl8125_start_xmit(struct sk_buff *skb, struct net_device *dev);
#if LINUX_VERSION_CODE < KERNEL_VERSION(2,6,19)
static irqreturn_t rtl8125_interrupt(int irq, void *dev_instance, struct pt_regs *regs);
#else
static irqreturn_t rtl8125_interrupt(int irq, void *dev_instance);
#endif
#if LINUX_VERSION_CODE < KERNEL_VERSION(2,6,19)
static irqreturn_t rtl8125_interrupt_msix(int irq, void *dev_instance, struct pt_regs *regs);
#else
static irqreturn_t rtl8125_interrupt_msix(int irq, void *dev_instance);
#endif
static void rtl8125_set_rx_mode(struct net_device *dev);
#if LINUX_VERSION_CODE >= KERNEL_VERSION(5,6,0)
static void rtl8125_tx_timeout(struct net_device *dev, unsigned int txqueue);
#else
static void rtl8125_tx_timeout(struct net_device *dev);
#endif
static struct net_device_stats *rtl8125_get_stats(struct net_device *dev);
static int rtl8125_rx_interrupt(struct net_device *, struct rtl8125_private *, struct rtl8125_rx_ring *, napi_budget);
static int rtl8125_tx_interrupt(struct rtl8125_tx_ring *ring, int budget);
static int rtl8125_tx_interrupt_with_vector(struct rtl8125_private *tp, const int message_id, int budget);
static int rtl8125_change_mtu(struct net_device *dev, int new_mtu);
static void rtl8125_down(struct net_device *dev);

static int rtl8125_set_mac_address(struct net_device *dev, void *p);
static void rtl8125_rar_set(struct rtl8125_private *tp, uint8_t *addr);
static void rtl8125_desc_addr_fill(struct rtl8125_private *);
static void rtl8125_tx_desc_init(struct rtl8125_private *tp);
static void rtl8125_rx_desc_init(struct rtl8125_private *tp);

static u32 mdio_direct_read_phy_ocp(struct rtl8125_private *tp, u16 RegAddr);
static u16 rtl8125_get_hw_phy_mcu_code_ver(struct rtl8125_private *tp);
static void rtl8125_phy_power_up(struct net_device *dev);
static void rtl8125_phy_power_down(struct net_device *dev);
static int rtl8125_set_speed(struct net_device *dev, u8 autoneg, u32 speed, u8 duplex, u32 adv);
static bool rtl8125_set_phy_mcu_patch_request(struct rtl8125_private *tp);
static bool rtl8125_clear_phy_mcu_patch_request(struct rtl8125_private *tp);

#ifdef CONFIG_R8125_NAPI
static int rtl8125_poll(napi_ptr napi, napi_budget budget);
#endif

#if LINUX_VERSION_CODE < KERNEL_VERSION(2,6,20)
static void rtl8125_reset_task(void *_data);
#else
static void rtl8125_reset_task(struct work_struct *work);
#endif

static inline struct device *tp_to_dev(struct rtl8125_private *tp)
{
        return &tp->pci_dev->dev;
}

#if ((LINUX_VERSION_CODE < KERNEL_VERSION(4,7,0) && \
     LINUX_VERSION_CODE >= KERNEL_VERSION(4,6,00)))
void ethtool_convert_legacy_u32_to_link_mode(unsigned long *dst,
                u32 legacy_u32)
{
        bitmap_zero(dst, __ETHTOOL_LINK_MODE_MASK_NBITS);
        dst[0] = legacy_u32;
}

bool ethtool_convert_link_mode_to_legacy_u32(u32 *legacy_u32,
                const unsigned long *src)
{
        bool retval = true;

        /* TODO: following test will soon always be true */
        if (__ETHTOOL_LINK_MODE_MASK_NBITS > 32) {
                __ETHTOOL_DECLARE_LINK_MODE_MASK(ext);

                bitmap_zero(ext, __ETHTOOL_LINK_MODE_MASK_NBITS);
                bitmap_fill(ext, 32);
                bitmap_complement(ext, ext, __ETHTOOL_LINK_MODE_MASK_NBITS);
                if (bitmap_intersects(ext, src,
                                      __ETHTOOL_LINK_MODE_MASK_NBITS)) {
                        /* src mask goes beyond bit 31 */
                        retval = false;
                }
        }
        *legacy_u32 = src[0];
        return retval;
}
#endif

#if LINUX_VERSION_CODE < KERNEL_VERSION(3,3,0)

#ifndef LPA_1000FULL
#define LPA_1000FULL            0x0800
#endif

#ifndef LPA_1000HALF
#define LPA_1000HALF            0x0400
#endif

#endif //LINUX_VERSION_CODE < KERNEL_VERSION(3,3,0)

#if LINUX_VERSION_CODE < KERNEL_VERSION(3,4,0)
static inline void eth_hw_addr_random(struct net_device *dev)
{
        random_ether_addr(dev->dev_addr);
}
#endif

#if LINUX_VERSION_CODE < KERNEL_VERSION(2,6,0)
#undef ethtool_ops
#define ethtool_ops _kc_ethtool_ops

struct _kc_ethtool_ops {
        int  (*get_settings)(struct net_device *, struct ethtool_cmd *);
        int  (*set_settings)(struct net_device *, struct ethtool_cmd *);
        void (*get_drvinfo)(struct net_device *, struct ethtool_drvinfo *);
        int  (*get_regs_len)(struct net_device *);
        void (*get_regs)(struct net_device *, struct ethtool_regs *, void *);
        void (*get_wol)(struct net_device *, struct ethtool_wolinfo *);
        int  (*set_wol)(struct net_device *, struct ethtool_wolinfo *);
        u32  (*get_msglevel)(struct net_device *);
        void (*set_msglevel)(struct net_device *, u32);
        int  (*nway_reset)(struct net_device *);
        u32  (*get_link)(struct net_device *);
        int  (*get_eeprom_len)(struct net_device *);
        int  (*get_eeprom)(struct net_device *, struct ethtool_eeprom *, u8 *);
        int  (*set_eeprom)(struct net_device *, struct ethtool_eeprom *, u8 *);
        int  (*get_coalesce)(struct net_device *, struct ethtool_coalesce *);
        int  (*set_coalesce)(struct net_device *, struct ethtool_coalesce *);
        void (*get_ringparam)(struct net_device *, struct ethtool_ringparam *);
        int  (*set_ringparam)(struct net_device *, struct ethtool_ringparam *);
        void (*get_pauseparam)(struct net_device *,
                               struct ethtool_pauseparam*);
        int  (*set_pauseparam)(struct net_device *,
                               struct ethtool_pauseparam*);
        u32  (*get_rx_csum)(struct net_device *);
        int  (*set_rx_csum)(struct net_device *, u32);
        u32  (*get_tx_csum)(struct net_device *);
        int  (*set_tx_csum)(struct net_device *, u32);
        u32  (*get_sg)(struct net_device *);
        int  (*set_sg)(struct net_device *, u32);
        u32  (*get_tso)(struct net_device *);
        int  (*set_tso)(struct net_device *, u32);
        int  (*self_test_count)(struct net_device *);
        void (*self_test)(struct net_device *, struct ethtool_test *, u64 *);
        void (*get_strings)(struct net_device *, u32 stringset, u8 *);
        int  (*phys_id)(struct net_device *, u32);
        int  (*get_stats_count)(struct net_device *);
        void (*get_ethtool_stats)(struct net_device *, struct ethtool_stats *,
                                  u64 *);
} *ethtool_ops = NULL;

#undef SET_ETHTOOL_OPS
#define SET_ETHTOOL_OPS(netdev, ops) (ethtool_ops = (ops))

#endif //LINUX_VERSION_CODE < KERNEL_VERSION(2,6,0)

#if LINUX_VERSION_CODE >= KERNEL_VERSION(3,16,0)
#ifndef SET_ETHTOOL_OPS
#define SET_ETHTOOL_OPS(netdev,ops) \
         ( (netdev)->ethtool_ops = (ops) )
#endif //SET_ETHTOOL_OPS
#endif //LINUX_VERSION_CODE >= KERNEL_VERSION(3,16,0)

//#if LINUX_VERSION_CODE < KERNEL_VERSION(2,6,5)
#ifndef netif_msg_init
#define netif_msg_init _kc_netif_msg_init
/* copied from linux kernel 2.6.20 include/linux/netdevice.h */
static inline u32 netif_msg_init(int debug_value, int default_msg_enable_bits)
{
        /* use default */
        if (debug_value < 0 || debug_value >= (sizeof(u32) * 8))
                return default_msg_enable_bits;
        if (debug_value == 0)   /* no output */
                return 0;
        /* set low N bits */
        return (1 << debug_value) - 1;
}

#endif //LINUX_VERSION_CODE < KERNEL_VERSION(2,6,5)

#if LINUX_VERSION_CODE > KERNEL_VERSION(2,6,22)
static inline void eth_copy_and_sum (struct sk_buff *dest,
                                     const unsigned char *src,
                                     int len, int base)
{
        memcpy (dest->data, src, len);
}
#endif //LINUX_VERSION_CODE > KERNEL_VERSION(2,6,22)

#if LINUX_VERSION_CODE < KERNEL_VERSION(2,6,7)
/* copied from linux kernel 2.6.20 /include/linux/time.h */
/* Parameters used to convert the timespec values: */
#define MSEC_PER_SEC    1000L

/* copied from linux kernel 2.6.20 /include/linux/jiffies.h */
/*
 * Change timeval to jiffies, trying to avoid the
 * most obvious overflows..
 *
 * And some not so obvious.
 *
 * Note that we don't want to return MAX_LONG, because
 * for various timeout reasons we often end up having
 * to wait "jiffies+1" in order to guarantee that we wait
 * at _least_ "jiffies" - so "jiffies+1" had better still
 * be positive.
 */
#define MAX_JIFFY_OFFSET ((~0UL >> 1)-1)

/*
 * Convert jiffies to milliseconds and back.
 *
 * Avoid unnecessary multiplications/divisions in the
 * two most common HZ cases:
 */
static inline unsigned int _kc_jiffies_to_msecs(const unsigned long j)
{
#if HZ <= MSEC_PER_SEC && !(MSEC_PER_SEC % HZ)
        return (MSEC_PER_SEC / HZ) * j;
#elif HZ > MSEC_PER_SEC && !(HZ % MSEC_PER_SEC)
        return (j + (HZ / MSEC_PER_SEC) - 1)/(HZ / MSEC_PER_SEC);
#else
        return (j * MSEC_PER_SEC) / HZ;
#endif
}

static inline unsigned long _kc_msecs_to_jiffies(const unsigned int m)
{
        if (m > _kc_jiffies_to_msecs(MAX_JIFFY_OFFSET))
                return MAX_JIFFY_OFFSET;
#if HZ <= MSEC_PER_SEC && !(MSEC_PER_SEC % HZ)
        return (m + (MSEC_PER_SEC / HZ) - 1) / (MSEC_PER_SEC / HZ);
#elif HZ > MSEC_PER_SEC && !(HZ % MSEC_PER_SEC)
        return m * (HZ / MSEC_PER_SEC);
#else
        return (m * HZ + MSEC_PER_SEC - 1) / MSEC_PER_SEC;
#endif
}
#endif  //LINUX_VERSION_CODE < KERNEL_VERSION(2,6,7)


#if LINUX_VERSION_CODE < KERNEL_VERSION(2,6,11)

/* copied from linux kernel 2.6.12.6 /include/linux/pm.h */
typedef int __bitwise pci_power_t;

/* copied from linux kernel 2.6.12.6 /include/linux/pci.h */
typedef u32 __bitwise pm_message_t;

#define PCI_D0  ((pci_power_t __force) 0)
#define PCI_D1  ((pci_power_t __force) 1)
#define PCI_D2  ((pci_power_t __force) 2)
#define PCI_D3hot   ((pci_power_t __force) 3)
#define PCI_D3cold  ((pci_power_t __force) 4)
#define PCI_POWER_ERROR ((pci_power_t __force) -1)

/* copied from linux kernel 2.6.12.6 /drivers/pci/pci.c */
/**
 * pci_choose_state - Choose the power state of a PCI device
 * @dev: PCI device to be suspended
 * @state: target sleep state for the whole system. This is the value
 *  that is passed to suspend() function.
 *
 * Returns PCI power state suitable for given device and given system
 * message.
 */

pci_power_t pci_choose_state(struct pci_dev *dev, pm_message_t state)
{
        if (!pci_find_capability(dev, PCI_CAP_ID_PM))
                return PCI_D0;

        switch (state) {
        case 0:
                return PCI_D0;
        case 3:
                return PCI_D3hot;
        default:
                printk("They asked me for state %d\n", state);
//      BUG();
        }
        return PCI_D0;
}
#endif  //LINUX_VERSION_CODE < KERNEL_VERSION(2,6,11)

#if LINUX_VERSION_CODE < KERNEL_VERSION(2,6,9)
/**
 * msleep_interruptible - sleep waiting for waitqueue interruptions
 * @msecs: Time in milliseconds to sleep for
 */
#define msleep_interruptible _kc_msleep_interruptible
unsigned long _kc_msleep_interruptible(unsigned int msecs)
{
        unsigned long timeout = _kc_msecs_to_jiffies(msecs);

        while (timeout && !signal_pending(current)) {
                set_current_state(TASK_INTERRUPTIBLE);
                timeout = schedule_timeout(timeout);
        }
        return _kc_jiffies_to_msecs(timeout);
}
#endif  //LINUX_VERSION_CODE < KERNEL_VERSION(2,6,9)

#if LINUX_VERSION_CODE < KERNEL_VERSION(2,6,7)
/* copied from linux kernel 2.6.20 include/linux/sched.h */
#ifndef __sched
#define __sched     __attribute__((__section__(".sched.text")))
#endif

/* copied from linux kernel 2.6.20 kernel/timer.c */
signed long __sched schedule_timeout_uninterruptible(signed long timeout)
{
        __set_current_state(TASK_UNINTERRUPTIBLE);
        return schedule_timeout(timeout);
}

/* copied from linux kernel 2.6.20 include/linux/mii.h */
#undef if_mii
#define if_mii _kc_if_mii
static inline struct mii_ioctl_data *if_mii(struct ifreq *rq)
{
        return (struct mii_ioctl_data *) &rq->ifr_ifru;
}
#endif  //LINUX_VERSION_CODE < KERNEL_VERSION(2,6,7)

struct rtl8125_counters {
        u64 tx_packets;
        u64 rx_packets;
        u64 tx_errors;
        u32 rx_errors;
        u16 rx_missed;
        u16 align_errors;
        u32 tx_one_collision;
        u32 tx_multi_collision;
        u64 rx_unicast;
        u64 rx_broadcast;
        u32 rx_multicast;
        u16 tx_aborted;
        u16 tx_underun;
};

static u32 rtl8125_read_thermal_sensor(struct rtl8125_private *tp)
{
        u16 ts_digout;

        switch (tp->mcfg) {
        case CFG_METHOD_4:
        case CFG_METHOD_5:
                ts_digout = mdio_direct_read_phy_ocp(tp, 0xBD84);
                ts_digout &= 0x3ff;
                break;
        default:
                ts_digout = 0xffff;
                break;
        }

        return ts_digout;
}

#ifdef ENABLE_R8125_PROCFS
/****************************************************************************
*   -----------------------------PROCFS STUFF-------------------------
*****************************************************************************
*/

static struct proc_dir_entry *rtl8125_proc;
static int proc_init_num = 0;

#if LINUX_VERSION_CODE >= KERNEL_VERSION(3,10,0)
static int proc_get_driver_variable(struct seq_file *m, void *v)
{
        struct net_device *dev = m->private;
        struct rtl8125_private *tp = netdev_priv(dev);
        unsigned long flags;

        seq_puts(m, "\nDump Driver Variable\n");

        spin_lock_irqsave(&tp->lock, flags);
        seq_puts(m, "Variable\tValue\n----------\t-----\n");
        seq_printf(m, "MODULENAME\t%s\n", MODULENAME);
        seq_printf(m, "driver version\t%s\n", RTL8125_VERSION);
        seq_printf(m, "mcfg\t%d\n", tp->mcfg);
        seq_printf(m, "chipset\t%d\n", tp->chipset);
        seq_printf(m, "chipset_name\t%s\n", rtl_chip_info[tp->chipset].name);
        seq_printf(m, "mtu\t%d\n", dev->mtu);
        seq_printf(m, "NUM_RX_DESC\t0x%x\n", NUM_RX_DESC);
        seq_printf(m, "cur_rx0\t0x%x\n", tp->rx_ring[0].cur_rx);
        seq_printf(m, "dirty_rx0\t0x%x\n", tp->rx_ring[0].dirty_rx);
        seq_printf(m, "cur_rx1\t0x%x\n", tp->rx_ring[1].cur_rx);
        seq_printf(m, "dirty_rx1\t0x%x\n", tp->rx_ring[1].dirty_rx);
        seq_printf(m, "cur_rx2\t0x%x\n", tp->rx_ring[2].cur_rx);
        seq_printf(m, "dirty_rx2\t0x%x\n", tp->rx_ring[2].dirty_rx);
        seq_printf(m, "cur_rx3\t0x%x\n", tp->rx_ring[3].cur_rx);
        seq_printf(m, "dirty_rx3\t0x%x\n", tp->rx_ring[3].dirty_rx);
        seq_printf(m, "NUM_TX_DESC\t0x%x\n", NUM_TX_DESC);
        seq_printf(m, "cur_tx0\t0x%x\n", tp->tx_ring[0].cur_tx);
        seq_printf(m, "dirty_tx0\t0x%x\n", tp->tx_ring[0].dirty_tx);
        seq_printf(m, "cur_tx1\t0x%x\n", tp->tx_ring[1].cur_tx);
        seq_printf(m, "dirty_tx1\t0x%x\n", tp->tx_ring[1].dirty_tx);
        seq_printf(m, "rx_buf_sz\t0x%x\n", tp->rx_buf_sz);
        seq_printf(m, "esd_flag\t0x%x\n", tp->esd_flag);
        seq_printf(m, "pci_cfg_is_read\t0x%x\n", tp->pci_cfg_is_read);
        seq_printf(m, "rtl8125_rx_config\t0x%x\n", tp->rtl8125_rx_config);
        seq_printf(m, "cp_cmd\t0x%x\n", tp->cp_cmd);
        seq_printf(m, "intr_mask\t0x%x\n", tp->intr_mask);
        seq_printf(m, "timer_intr_mask\t0x%x\n", tp->timer_intr_mask);
        seq_printf(m, "wol_enabled\t0x%x\n", tp->wol_enabled);
        seq_printf(m, "wol_opts\t0x%x\n", tp->wol_opts);
        seq_printf(m, "efuse_ver\t0x%x\n", tp->efuse_ver);
        seq_printf(m, "eeprom_type\t0x%x\n", tp->eeprom_type);
        seq_printf(m, "autoneg\t0x%x\n", tp->autoneg);
        seq_printf(m, "duplex\t0x%x\n", tp->duplex);
        seq_printf(m, "speed\t%d\n", tp->speed);
        seq_printf(m, "advertising\t0x%x\n", tp->advertising);
        seq_printf(m, "eeprom_len\t0x%x\n", tp->eeprom_len);
        seq_printf(m, "cur_page\t0x%x\n", tp->cur_page);
        seq_printf(m, "bios_setting\t0x%x\n", tp->bios_setting);
        seq_printf(m, "features\t0x%x\n", tp->features);
        seq_printf(m, "org_pci_offset_99\t0x%x\n", tp->org_pci_offset_99);
        seq_printf(m, "org_pci_offset_180\t0x%x\n", tp->org_pci_offset_180);
        seq_printf(m, "issue_offset_99_event\t0x%x\n", tp->issue_offset_99_event);
        seq_printf(m, "org_pci_offset_80\t0x%x\n", tp->org_pci_offset_80);
        seq_printf(m, "org_pci_offset_81\t0x%x\n", tp->org_pci_offset_81);
        seq_printf(m, "use_timer_interrrupt\t0x%x\n", tp->use_timer_interrrupt);
        seq_printf(m, "HwIcVerUnknown\t0x%x\n", tp->HwIcVerUnknown);
        seq_printf(m, "NotWrRamCodeToMicroP\t0x%x\n", tp->NotWrRamCodeToMicroP);
        seq_printf(m, "NotWrMcuPatchCode\t0x%x\n", tp->NotWrMcuPatchCode);
        seq_printf(m, "HwHasWrRamCodeToMicroP\t0x%x\n", tp->HwHasWrRamCodeToMicroP);
        seq_printf(m, "sw_ram_code_ver\t0x%x\n", tp->sw_ram_code_ver);
        seq_printf(m, "hw_ram_code_ver\t0x%x\n", tp->hw_ram_code_ver);
        seq_printf(m, "rtk_enable_diag\t0x%x\n", tp->rtk_enable_diag);
        seq_printf(m, "ShortPacketSwChecksum\t0x%x\n", tp->ShortPacketSwChecksum);
        seq_printf(m, "UseSwPaddingShortPkt\t0x%x\n", tp->UseSwPaddingShortPkt);
        seq_printf(m, "RequireAdcBiasPatch\t0x%x\n", tp->RequireAdcBiasPatch);
        seq_printf(m, "AdcBiasPatchIoffset\t0x%x\n", tp->AdcBiasPatchIoffset);
        seq_printf(m, "RequireAdjustUpsTxLinkPulseTiming\t0x%x\n", tp->RequireAdjustUpsTxLinkPulseTiming);
        seq_printf(m, "SwrCnt1msIni\t0x%x\n", tp->SwrCnt1msIni);
        seq_printf(m, "HwSuppNowIsOobVer\t0x%x\n", tp->HwSuppNowIsOobVer);
        seq_printf(m, "HwFiberModeVer\t0x%x\n", tp->HwFiberModeVer);
        seq_printf(m, "HwFiberStat\t0x%x\n", tp->HwFiberStat);
        seq_printf(m, "HwSwitchMdiToFiber\t0x%x\n", tp->HwSwitchMdiToFiber);
        seq_printf(m, "NicCustLedValue\t0x%x\n", tp->NicCustLedValue);
        seq_printf(m, "RequiredSecLanDonglePatch\t0x%x\n", tp->RequiredSecLanDonglePatch);
        seq_printf(m, "HwSuppDashVer\t0x%x\n", tp->HwSuppDashVer);
        seq_printf(m, "DASH\t0x%x\n", tp->DASH);
        seq_printf(m, "dash_printer_enabled\t0x%x\n", tp->dash_printer_enabled);
        seq_printf(m, "HwSuppKCPOffloadVer\t0x%x\n", tp->HwSuppKCPOffloadVer);
        seq_printf(m, "speed_mode\t0x%x\n", speed_mode);
        seq_printf(m, "duplex_mode\t0x%x\n", duplex_mode);
        seq_printf(m, "autoneg_mode\t0x%x\n", autoneg_mode);
        seq_printf(m, "advertising_mode\t0x%x\n", advertising_mode);
        seq_printf(m, "aspm\t0x%x\n", aspm);
        seq_printf(m, "s5wol\t0x%x\n", s5wol);
        seq_printf(m, "s5_keep_curr_mac\t0x%x\n", s5_keep_curr_mac);
        seq_printf(m, "eee_enable\t0x%x\n", tp->eee.eee_enabled);
        seq_printf(m, "hwoptimize\t0x%lx\n", hwoptimize);
        seq_printf(m, "proc_init_num\t0x%x\n", proc_init_num);
        seq_printf(m, "s0_magic_packet\t0x%x\n", s0_magic_packet);
        seq_printf(m, "HwSuppMagicPktVer\t0x%x\n", tp->HwSuppMagicPktVer);
        seq_printf(m, "HwSuppLinkChgWakeUpVer\t0x%x\n", tp->HwSuppLinkChgWakeUpVer);
        seq_printf(m, "HwSuppD0SpeedUpVer\t0x%x\n", tp->HwSuppD0SpeedUpVer);
        seq_printf(m, "D0SpeedUpSpeed\t0x%x\n", tp->D0SpeedUpSpeed);
        seq_printf(m, "HwSuppCheckPhyDisableModeVer\t0x%x\n", tp->HwSuppCheckPhyDisableModeVer);
        seq_printf(m, "HwPkgDet\t0x%x\n", tp->HwPkgDet);
        seq_printf(m, "HwSuppTxNoCloseVer\t0x%x\n", tp->HwSuppTxNoCloseVer);
        seq_printf(m, "EnableTxNoClose\t0x%x\n", tp->EnableTxNoClose);
        seq_printf(m, "NextHwDesCloPtr0\t0x%x\n", tp->tx_ring[0].NextHwDesCloPtr);
        seq_printf(m, "BeginHwDesCloPtr0\t0x%x\n", tp->tx_ring[0].BeginHwDesCloPtr);
        seq_printf(m, "NextHwDesCloPtr1\t0x%x\n", tp->tx_ring[1].NextHwDesCloPtr);
        seq_printf(m, "BeginHwDesCloPtr1\t0x%x\n", tp->tx_ring[1].BeginHwDesCloPtr);
        seq_printf(m, "InitRxDescType\t0x%x\n", tp->InitRxDescType);
        seq_printf(m, "RxDescLength\t0x%x\n", tp->RxDescLength);
        seq_printf(m, "num_rx_rings\t0x%x\n", tp->num_rx_rings);
        seq_printf(m, "num_tx_rings\t0x%x\n", tp->num_tx_rings);
        seq_printf(m, "tot_rx_rings\t0x%x\n", rtl8125_tot_rx_rings(tp));
        seq_printf(m, "tot_tx_rings\t0x%x\n", rtl8125_tot_tx_rings(tp));
        seq_printf(m, "EnableRss\t0x%x\n", tp->EnableRss);
        seq_printf(m, "EnablePtp\t0x%x\n", tp->EnablePtp);
        seq_printf(m, "ptp_master_mode\t0x%x\n", tp->ptp_master_mode);
        seq_printf(m, "min_irq_nvecs\t0x%x\n", tp->min_irq_nvecs);
        seq_printf(m, "irq_nvecs\t0x%x\n", tp->irq_nvecs);
        seq_printf(m, "ring_lib_enabled\t0x%x\n", tp->ring_lib_enabled);
        seq_printf(m, "HwSuppIsrVer\t0x%x\n", tp->HwSuppIsrVer);
        seq_printf(m, "HwCurrIsrVer\t0x%x\n", tp->HwCurrIsrVer);
#ifdef ENABLE_PTP_SUPPORT
        seq_printf(m, "tx_hwtstamp_timeouts\t0x%x\n", tp->tx_hwtstamp_timeouts);
        seq_printf(m, "tx_hwtstamp_skipped\t0x%x\n", tp->tx_hwtstamp_skipped);
#endif
        seq_printf(m, "random_mac\t0x%x\n", tp->random_mac);
        seq_printf(m, "org_mac_addr\t%pM\n", tp->org_mac_addr);
#if LINUX_VERSION_CODE > KERNEL_VERSION(2,6,13)
        seq_printf(m, "perm_addr\t%pM\n", dev->perm_addr);
#endif
        seq_printf(m, "dev_addr\t%pM\n", dev->dev_addr);
        spin_unlock_irqrestore(&tp->lock, flags);

        seq_putc(m, '\n');
        return 0;
}

static int proc_get_tally_counter(struct seq_file *m, void *v)
{
        struct net_device *dev = m->private;
        struct rtl8125_private *tp = netdev_priv(dev);
        struct rtl8125_counters *counters;
        dma_addr_t paddr;
        u32 cmd;
        u32 WaitCnt;
        unsigned long flags;

        seq_puts(m, "\nDump Tally Counter\n");

        //ASSERT_RTNL();

        counters = tp->tally_vaddr;
        paddr = tp->tally_paddr;
        if (!counters) {
                seq_puts(m, "\nDump Tally Counter Fail\n");
                return 0;
        }

        spin_lock_irqsave(&tp->lock, flags);
        RTL_W32(tp, CounterAddrHigh, (u64)paddr >> 32);
        cmd = (u64)paddr & DMA_BIT_MASK(32);
        RTL_W32(tp, CounterAddrLow, cmd);
        RTL_W32(tp, CounterAddrLow, cmd | CounterDump);

        WaitCnt = 0;
        while (RTL_R32(tp, CounterAddrLow) & CounterDump) {
                udelay(10);

                WaitCnt++;
                if (WaitCnt > 20)
                        break;
        }
        spin_unlock_irqrestore(&tp->lock, flags);

        seq_puts(m, "Statistics\tValue\n----------\t-----\n");
        seq_printf(m, "tx_packets\t%lld\n", le64_to_cpu(counters->tx_packets));
        seq_printf(m, "rx_packets\t%lld\n", le64_to_cpu(counters->rx_packets));
        seq_printf(m, "tx_errors\t%lld\n", le64_to_cpu(counters->tx_errors));
        seq_printf(m, "rx_missed\t%lld\n", le64_to_cpu(counters->rx_missed));
        seq_printf(m, "align_errors\t%lld\n", le64_to_cpu(counters->align_errors));
        seq_printf(m, "tx_one_collision\t%lld\n", le64_to_cpu(counters->tx_one_collision));
        seq_printf(m, "tx_multi_collision\t%lld\n", le64_to_cpu(counters->tx_multi_collision));
        seq_printf(m, "rx_unicast\t%lld\n", le64_to_cpu(counters->rx_unicast));
        seq_printf(m, "rx_broadcast\t%lld\n", le64_to_cpu(counters->rx_broadcast));
        seq_printf(m, "rx_multicast\t%lld\n", le64_to_cpu(counters->rx_multicast));
        seq_printf(m, "tx_aborted\t%lld\n", le64_to_cpu(counters->tx_aborted));
        seq_printf(m, "tx_underun\t%lld\n", le64_to_cpu(counters->tx_underun));

        seq_putc(m, '\n');
        return 0;
}

static int proc_get_registers(struct seq_file *m, void *v)
{
        struct net_device *dev = m->private;
        int i, n, max = R8125_MAC_REGS_SIZE;
        u8 byte_rd;
        struct rtl8125_private *tp = netdev_priv(dev);
        void __iomem *ioaddr = tp->mmio_addr;
        unsigned long flags;

        seq_puts(m, "\nDump MAC Registers\n");
        seq_puts(m, "Offset\tValue\n------\t-----\n");

        spin_lock_irqsave(&tp->lock, flags);
        for (n = 0; n < max;) {
                seq_printf(m, "\n0x%02x:\t", n);

                for (i = 0; i < 16 && n < max; i++, n++) {
                        byte_rd = readb(ioaddr + n);
                        seq_printf(m, "%02x ", byte_rd);
                }
        }
        spin_unlock_irqrestore(&tp->lock, flags);

        seq_putc(m, '\n');
        return 0;
}

static int proc_get_pcie_phy(struct seq_file *m, void *v)
{
        struct net_device *dev = m->private;
        int i, n, max = R8125_EPHY_REGS_SIZE/2;
        u16 word_rd;
        struct rtl8125_private *tp = netdev_priv(dev);
        unsigned long flags;

        seq_puts(m, "\nDump PCIE PHY\n");
        seq_puts(m, "\nOffset\tValue\n------\t-----\n ");

        spin_lock_irqsave(&tp->lock, flags);
        for (n = 0; n < max;) {
                seq_printf(m, "\n0x%02x:\t", n);

                for (i = 0; i < 8 && n < max; i++, n++) {
                        word_rd = rtl8125_ephy_read(tp, n);
                        seq_printf(m, "%04x ", word_rd);
                }
        }
        spin_unlock_irqrestore(&tp->lock, flags);

        seq_putc(m, '\n');
        return 0;
}

static int proc_get_eth_phy(struct seq_file *m, void *v)
{
        struct net_device *dev = m->private;
        int i, n, max = R8125_PHY_REGS_SIZE/2;
        u16 word_rd;
        struct rtl8125_private *tp = netdev_priv(dev);
        unsigned long flags;

        seq_puts(m, "\nDump Ethernet PHY\n");
        seq_puts(m, "\nOffset\tValue\n------\t-----\n ");

        spin_lock_irqsave(&tp->lock, flags);
        seq_puts(m, "\n####################page 0##################\n ");
        rtl8125_mdio_write(tp, 0x1f, 0x0000);
        for (n = 0; n < max;) {
                seq_printf(m, "\n0x%02x:\t", n);

                for (i = 0; i < 8 && n < max; i++, n++) {
                        word_rd = rtl8125_mdio_read(tp, n);
                        seq_printf(m, "%04x ", word_rd);
                }
        }
        spin_unlock_irqrestore(&tp->lock, flags);

        seq_putc(m, '\n');
        return 0;
}

static int proc_get_extended_registers(struct seq_file *m, void *v)
{
        struct net_device *dev = m->private;
        int i, n, max = R8125_ERI_REGS_SIZE;
        u32 dword_rd;
        struct rtl8125_private *tp = netdev_priv(dev);
        unsigned long flags;

        seq_puts(m, "\nDump Extended Registers\n");
        seq_puts(m, "\nOffset\tValue\n------\t-----\n ");

        spin_lock_irqsave(&tp->lock, flags);
        for (n = 0; n < max;) {
                seq_printf(m, "\n0x%02x:\t", n);

                for (i = 0; i < 4 && n < max; i++, n+=4) {
                        dword_rd = rtl8125_eri_read(tp, n, 4, ERIAR_ExGMAC);
                        seq_printf(m, "%08x ", dword_rd);
                }
        }
        spin_unlock_irqrestore(&tp->lock, flags);

        seq_putc(m, '\n');
        return 0;
}

static int proc_get_pci_registers(struct seq_file *m, void *v)
{
        struct net_device *dev = m->private;
        int i, n, max = R8125_PCI_REGS_SIZE;
        u32 dword_rd;
        struct rtl8125_private *tp = netdev_priv(dev);
        unsigned long flags;

        seq_puts(m, "\nDump PCI Registers\n");
        seq_puts(m, "\nOffset\tValue\n------\t-----\n ");

        spin_lock_irqsave(&tp->lock, flags);
        for (n = 0; n < max;) {
                seq_printf(m, "\n0x%03x:\t", n);

                for (i = 0; i < 4 && n < max; i++, n+=4) {
                        pci_read_config_dword(tp->pci_dev, n, &dword_rd);
                        seq_printf(m, "%08x ", dword_rd);
                }
        }

        n = 0x110;
        pci_read_config_dword(tp->pci_dev, n, &dword_rd);
        seq_printf(m, "\n0x%03x:\t%08x ", n, dword_rd);
        n = 0x70c;
        pci_read_config_dword(tp->pci_dev, n, &dword_rd);
        seq_printf(m, "\n0x%03x:\t%08x ", n, dword_rd);

        spin_unlock_irqrestore(&tp->lock, flags);

        seq_putc(m, '\n');
        return 0;
}

static int proc_get_temperature(struct seq_file *m, void *v)
{
        struct net_device *dev = m->private;
        struct rtl8125_private *tp = netdev_priv(dev);
        u16 ts_digout, tj, fah;
        unsigned long flags;

        switch (tp->mcfg) {
        case CFG_METHOD_4:
        case CFG_METHOD_5:
                seq_puts(m, "\nChip Temperature\n");
                break;
        default:
                seq_puts(m, "\nThis Chip Does Not Support Dump Temperature\n");
                break;
        }

        spin_lock_irqsave(&tp->lock, flags);
        ts_digout = rtl8125_read_thermal_sensor(tp);
        spin_unlock_irqrestore(&tp->lock, flags);

        tj = ts_digout / 2;
        if (ts_digout <= 512) {
                tj = ts_digout / 2;
                seq_printf(m, "Cel:%d\n", tj);
                fah = tj * (9/5) + 32;
                seq_printf(m, "Fah:%d\n", fah);
        } else {
                tj = (512 - ((ts_digout / 2) - 512)) / 2;
                seq_printf(m, "Cel:-%d\n", tj);
                fah = tj * (9/5) + 32;
                seq_printf(m, "Fah:-%d\n", fah);
        }

        seq_putc(m, '\n');
        return 0;
}
#else

static int proc_get_driver_variable(char *page, char **start,
                                    off_t offset, int count,
                                    int *eof, void *data)
{
        struct net_device *dev = data;
        struct rtl8125_private *tp = netdev_priv(dev);
        unsigned long flags;
        int len = 0;

        len += snprintf(page + len, count - len,
                        "\nDump Driver Driver\n");

        spin_lock_irqsave(&tp->lock, flags);
        len += snprintf(page + len, count - len,
                        "Variable\tValue\n----------\t-----\n");

        len += snprintf(page + len, count - len,
                        "MODULENAME\t%s\n"
                        "driver version\t%s\n"
                        "mcfg\t%d\n"
                        "chipset\t%d\n"
                        "chipset_name\t%s\n"
                        "mtu\t%d\n"
                        "NUM_RX_DESC\t0x%x\n"
                        "cur_rx0\t0x%x\n"
                        "dirty_rx0\t0x%x\n"
                        "cur_rx1\t0x%x\n"
                        "dirty_rx1\t0x%x\n"
                        "cur_rx2\t0x%x\n"
                        "dirty_rx2\t0x%x\n"
                        "cur_rx3\t0x%x\n"
                        "dirty_rx3\t0x%x\n"
                        "NUM_TX_DESC\t0x%x\n"
                        "cur_tx0\t0x%x\n"
                        "dirty_tx0\t0x%x\n"
                        "cur_tx1\t0x%x\n"
                        "dirty_tx1\t0x%x\n"
                        "rx_buf_sz\t0x%x\n"
                        "esd_flag\t0x%x\n"
                        "pci_cfg_is_read\t0x%x\n"
                        "rtl8125_rx_config\t0x%x\n"
                        "cp_cmd\t0x%x\n"
                        "intr_mask\t0x%x\n"
                        "timer_intr_mask\t0x%x\n"
                        "wol_enabled\t0x%x\n"
                        "wol_opts\t0x%x\n"
                        "efuse_ver\t0x%x\n"
                        "eeprom_type\t0x%x\n"
                        "autoneg\t0x%x\n"
                        "duplex\t0x%x\n"
                        "speed\t%d\n"
                        "advertising\t0x%x\n"
                        "eeprom_len\t0x%x\n"
                        "cur_page\t0x%x\n"
                        "bios_setting\t0x%x\n"
                        "features\t0x%x\n"
                        "org_pci_offset_99\t0x%x\n"
                        "org_pci_offset_180\t0x%x\n"
                        "issue_offset_99_event\t0x%x\n"
                        "org_pci_offset_80\t0x%x\n"
                        "org_pci_offset_81\t0x%x\n"
                        "use_timer_interrrupt\t0x%x\n"
                        "HwIcVerUnknown\t0x%x\n"
                        "NotWrRamCodeToMicroP\t0x%x\n"
                        "NotWrMcuPatchCode\t0x%x\n"
                        "HwHasWrRamCodeToMicroP\t0x%x\n"
                        "sw_ram_code_ver\t0x%x\n"
                        "hw_ram_code_ver\t0x%x\n"
                        "rtk_enable_diag\t0x%x\n"
                        "ShortPacketSwChecksum\t0x%x\n"
                        "UseSwPaddingShortPkt\t0x%x\n"
                        "RequireAdcBiasPatch\t0x%x\n"
                        "AdcBiasPatchIoffset\t0x%x\n"
                        "RequireAdjustUpsTxLinkPulseTiming\t0x%x\n"
                        "SwrCnt1msIni\t0x%x\n"
                        "HwSuppNowIsOobVer\t0x%x\n"
                        "HwFiberModeVer\t0x%x\n"
                        "HwFiberStat\t0x%x\n"
                        "HwSwitchMdiToFiber\t0x%x\n"
                        "NicCustLedValue\t0x%x\n"
                        "RequiredSecLanDonglePatch\t0x%x\n"
                        "HwSuppDashVer\t0x%x\n"
                        "DASH\t0x%x\n"
                        "dash_printer_enabled\t0x%x\n"
                        "HwSuppKCPOffloadVer\t0x%x\n"
                        "speed_mode\t0x%x\n"
                        "duplex_mode\t0x%x\n"
                        "autoneg_mode\t0x%x\n"
                        "advertising_mode\t0x%x\n"
                        "aspm\t0x%x\n"
                        "s5wol\t0x%x\n"
                        "s5_keep_curr_mac\t0x%x\n"
                        "eee_enable\t0x%x\n"
                        "hwoptimize\t0x%lx\n"
                        "proc_init_num\t0x%x\n"
                        "s0_magic_packet\t0x%x\n"
                        "HwSuppMagicPktVer\t0x%x\n"
                        "HwSuppLinkChgWakeUpVer\t0x%x\n"
                        "HwSuppD0SpeedUpVer\t0x%x\n"
                        "D0SpeedUpSpeed\t0x%x\n"
                        "HwSuppCheckPhyDisableModeVer\t0x%x\n"
                        "HwPkgDet\t0x%x\n"
                        "HwSuppTxNoCloseVer\t0x%x\n"
                        "EnableTxNoClose\t0x%x\n"
                        "NextHwDesCloPtr0\t0x%x\n"
                        "BeginHwDesCloPtr0\t0x%x\n"
                        "NextHwDesCloPtr1\t0x%x\n"
                        "BeginHwDesCloPtr1\t0x%x\n"
                        "InitRxDescType\t0x%x\n"
                        "RxDescLength\t0x%x\n"
                        "num_rx_rings\t0x%x\n"
                        "num_tx_rings\t0x%x\n"
                        "tot_rx_rings\t0x%x\n"
                        "tot_tx_rings\t0x%x\n"
                        "EnableRss\t0x%x\n"
                        "EnablePtp\t0x%x\n"
                        "ptp_master_mode\t0x%x\n"
                        "min_irq_nvecs\t0x%x\n"
                        "irq_nvecs\t0x%x\n"
                        "ring_lib_enabled\t0x%x\n"
                        "HwSuppIsrVer\t0x%x\n"
                        "HwCurrIsrVer\t0x%x\n"
#ifdef ENABLE_PTP_SUPPORT
                        "tx_hwtstamp_timeouts\t0x%x\n"
                        "tx_hwtstamp_skipped\t0x%x\n"
#endif
                        "random_mac\t0x%x\n"
                        "org_mac_addr\t%pM\n"
#if LINUX_VERSION_CODE > KERNEL_VERSION(2,6,13)
                        "perm_addr\t%pM\n"
#endif
                        "dev_addr\t%pM\n",
                        MODULENAME,
                        RTL8125_VERSION,
                        tp->mcfg,
                        tp->chipset,
                        rtl_chip_info[tp->chipset].name,
                        dev->mtu,
                        NUM_RX_DESC,
                        tp->rx_ring[0].cur_rx,
                        tp->rx_ring[0].dirty_rx,
                        tp->rx_ring[1].cur_rx,
                        tp->rx_ring[1].dirty_rx,
                        tp->rx_ring[2].cur_rx,
                        tp->rx_ring[2].dirty_rx,
                        tp->rx_ring[3].cur_rx,
                        tp->rx_ring[3].dirty_rx,
                        NUM_TX_DESC,
                        tp->tx_ring[0].cur_tx,
                        tp->tx_ring[0].dirty_tx,
                        tp->tx_ring[1].cur_tx,
                        tp->tx_ring[1].dirty_tx,
                        tp->rx_buf_sz,
                        tp->esd_flag,
                        tp->pci_cfg_is_read,
                        tp->rtl8125_rx_config,
                        tp->cp_cmd,
                        tp->intr_mask,
                        tp->timer_intr_mask,
                        tp->wol_enabled,
                        tp->wol_opts,
                        tp->efuse_ver,
                        tp->eeprom_type,
                        tp->autoneg,
                        tp->duplex,
                        tp->speed,
                        tp->advertising,
                        tp->eeprom_len,
                        tp->cur_page,
                        tp->bios_setting,
                        tp->features,
                        tp->org_pci_offset_99,
                        tp->org_pci_offset_180,
                        tp->issue_offset_99_event,
                        tp->org_pci_offset_80,
                        tp->org_pci_offset_81,
                        tp->use_timer_interrrupt,
                        tp->HwIcVerUnknown,
                        tp->NotWrRamCodeToMicroP,
                        tp->NotWrMcuPatchCode,
                        tp->HwHasWrRamCodeToMicroP,
                        tp->sw_ram_code_ver,
                        tp->hw_ram_code_ver,
                        tp->rtk_enable_diag,
                        tp->ShortPacketSwChecksum,
                        tp->UseSwPaddingShortPkt,
                        tp->RequireAdcBiasPatch,
                        tp->AdcBiasPatchIoffset,
                        tp->RequireAdjustUpsTxLinkPulseTiming,
                        tp->SwrCnt1msIni,
                        tp->HwSuppNowIsOobVer,
                        tp->HwFiberModeVer,
                        tp->HwFiberStat,
                        tp->HwSwitchMdiToFiber,
                        tp->NicCustLedValue,
                        tp->RequiredSecLanDonglePatch,
                        tp->HwSuppDashVer,
                        tp->DASH,
                        tp->dash_printer_enabled,
                        tp->HwSuppKCPOffloadVer,
                        speed_mode,
                        duplex_mode,
                        autoneg_mode,
                        advertising_mode,
                        aspm,
                        s5wol,
                        s5_keep_curr_mac,
                        tp->eee.eee_enabled,
                        hwoptimize,
                        proc_init_num,
                        s0_magic_packet,
                        tp->HwSuppMagicPktVer,
                        tp->HwSuppLinkChgWakeUpVer,
                        tp->HwSuppD0SpeedUpVer,
                        tp->D0SpeedUpSpeed,
                        tp->HwSuppCheckPhyDisableModeVer,
                        tp->HwPkgDet,
                        tp->HwSuppTxNoCloseVer,
                        tp->EnableTxNoClose,
                        tp->tx_ring[0].NextHwDesCloPtr,
                        tp->tx_ring[0].BeginHwDesCloPtr,
                        tp->tx_ring[1].NextHwDesCloPtr,
                        tp->tx_ring[1].BeginHwDesCloPtr,
                        tp->InitRxDescType,
                        tp->RxDescLength,
                        tp->num_rx_rings,
                        tp->num_tx_rings,
                        tp->tot_rx_rings,
                        tp->tot_tx_rings,
                        tp->EnableRss,
                        tp->EnablePtp,
                        tp->ptp_master_mode,
                        tp->min_irq_nvecs,
                        tp->irq_nvecs,
                        tp->ring_lib_enabled,
                        tp->HwSuppIsrVer,
                        tp->HwCurrIsrVer,
#ifdef ENABLE_PTP_SUPPORT
                        tp->tx_hwtstamp_timeouts,
                        tp->tx_hwtstamp_skipped,
#endif
                        tp->random_mac,
                        tp->org_mac_addr,
#if LINUX_VERSION_CODE > KERNEL_VERSION(2,6,13)
                        dev->perm_addr,
#endif
                        dev->dev_addr
                       );
        spin_unlock_irqrestore(&tp->lock, flags);

        len += snprintf(page + len, count - len, "\n");

        *eof = 1;
        return len;
}

static int proc_get_tally_counter(char *page, char **start,
                                  off_t offset, int count,
                                  int *eof, void *data)
{
        struct net_device *dev = data;
        struct rtl8125_private *tp = netdev_priv(dev);
        struct rtl8125_counters *counters;
        dma_addr_t paddr;
        u32 cmd;
        u32 WaitCnt;
        unsigned long flags;
        int len = 0;

        len += snprintf(page + len, count - len,
                        "\nDump Tally Counter\n");

        //ASSERT_RTNL();

        counters = tp->tally_vaddr;
        paddr = tp->tally_paddr;
        if (!counters) {
                len += snprintf(page + len, count - len,
                                "\nDump Tally Counter Fail\n");
                goto out;
        }

        spin_lock_irqsave(&tp->lock, flags);
        RTL_W32(tp, CounterAddrHigh, (u64)paddr >> 32);
        cmd = (u64)paddr & DMA_BIT_MASK(32);
        RTL_W32(tp, CounterAddrLow, cmd);
        RTL_W32(tp, CounterAddrLow, cmd | CounterDump);

        WaitCnt = 0;
        while (RTL_R32(tp, CounterAddrLow) & CounterDump) {
                udelay(10);

                WaitCnt++;
                if (WaitCnt > 20)
                        break;
        }
        spin_unlock_irqrestore(&tp->lock, flags);

        len += snprintf(page + len, count - len,
                        "Statistics\tValue\n----------\t-----\n");

        len += snprintf(page + len, count - len,
                        "tx_packets\t%lld\n"
                        "rx_packets\t%lld\n"
                        "tx_errors\t%lld\n"
                        "rx_missed\t%lld\n"
                        "align_errors\t%lld\n"
                        "tx_one_collision\t%lld\n"
                        "tx_multi_collision\t%lld\n"
                        "rx_unicast\t%lld\n"
                        "rx_broadcast\t%lld\n"
                        "rx_multicast\t%lld\n"
                        "tx_aborted\t%lld\n"
                        "tx_underun\t%lld\n",
                        le64_to_cpu(counters->tx_packets),
                        le64_to_cpu(counters->rx_packets),
                        le64_to_cpu(counters->tx_errors),
                        le64_to_cpu(counters->rx_missed),
                        le64_to_cpu(counters->align_errors),
                        le64_to_cpu(counters->tx_one_collision),
                        le64_to_cpu(counters->tx_multi_collision),
                        le64_to_cpu(counters->rx_unicast),
                        le64_to_cpu(counters->rx_broadcast),
                        le64_to_cpu(counters->rx_multicast),
                        le64_to_cpu(counters->tx_aborted),
                        le64_to_cpu(counters->tx_underun)
                       );

        len += snprintf(page + len, count - len, "\n");
out:
        *eof = 1;
        return len;
}

static int proc_get_registers(char *page, char **start,
                              off_t offset, int count,
                              int *eof, void *data)
{
        struct net_device *dev = data;
        int i, n, max = R8125_MAC_REGS_SIZE;
        u8 byte_rd;
        struct rtl8125_private *tp = netdev_priv(dev);
        void __iomem *ioaddr = tp->mmio_addr;
        unsigned long flags;
        int len = 0;

        len += snprintf(page + len, count - len,
                        "\nDump MAC Registers\n"
                        "Offset\tValue\n------\t-----\n");

        spin_lock_irqsave(&tp->lock, flags);
        for (n = 0; n < max;) {
                len += snprintf(page + len, count - len,
                                "\n0x%02x:\t",
                                n);

                for (i = 0; i < 16 && n < max; i++, n++) {
                        byte_rd = readb(ioaddr + n);
                        len += snprintf(page + len, count - len,
                                        "%02x ",
                                        byte_rd);
                }
        }
        spin_unlock_irqrestore(&tp->lock, flags);

        len += snprintf(page + len, count - len, "\n");

        *eof = 1;
        return len;
}

static int proc_get_pcie_phy(char *page, char **start,
                             off_t offset, int count,
                             int *eof, void *data)
{
        struct net_device *dev = data;
        int i, n, max = R8125_EPHY_REGS_SIZE/2;
        u16 word_rd;
        struct rtl8125_private *tp = netdev_priv(dev);
        unsigned long flags;
        int len = 0;

        len += snprintf(page + len, count - len,
                        "\nDump PCIE PHY\n"
                        "Offset\tValue\n------\t-----\n");

        spin_lock_irqsave(&tp->lock, flags);
        for (n = 0; n < max;) {
                len += snprintf(page + len, count - len,
                                "\n0x%02x:\t",
                                n);

                for (i = 0; i < 8 && n < max; i++, n++) {
                        word_rd = rtl8125_ephy_read(tp, n);
                        len += snprintf(page + len, count - len,
                                        "%04x ",
                                        word_rd);
                }
        }
        spin_unlock_irqrestore(&tp->lock, flags);

        len += snprintf(page + len, count - len, "\n");

        *eof = 1;
        return len;
}

static int proc_get_eth_phy(char *page, char **start,
                            off_t offset, int count,
                            int *eof, void *data)
{
        struct net_device *dev = data;
        int i, n, max = R8125_PHY_REGS_SIZE/2;
        u16 word_rd;
        struct rtl8125_private *tp = netdev_priv(dev);
        unsigned long flags;
        int len = 0;

        len += snprintf(page + len, count - len,
                        "\nDump Ethernet PHY\n"
                        "Offset\tValue\n------\t-----\n");

        spin_lock_irqsave(&tp->lock, flags);
        len += snprintf(page + len, count - len,
                        "\n####################page 0##################\n");
        rtl8125_mdio_write(tp, 0x1f, 0x0000);
        for (n = 0; n < max;) {
                len += snprintf(page + len, count - len,
                                "\n0x%02x:\t",
                                n);

                for (i = 0; i < 8 && n < max; i++, n++) {
                        word_rd = rtl8125_mdio_read(tp, n);
                        len += snprintf(page + len, count - len,
                                        "%04x ",
                                        word_rd);
                }
        }
        spin_unlock_irqrestore(&tp->lock, flags);

        len += snprintf(page + len, count - len, "\n");

        *eof = 1;
        return len;
}

static int proc_get_extended_registers(char *page, char **start,
                                       off_t offset, int count,
                                       int *eof, void *data)
{
        struct net_device *dev = data;
        int i, n, max = R8125_ERI_REGS_SIZE;
        u32 dword_rd;
        struct rtl8125_private *tp = netdev_priv(dev);
        unsigned long flags;
        int len = 0;

        len += snprintf(page + len, count - len,
                        "\nDump Extended Registers\n"
                        "Offset\tValue\n------\t-----\n");

        spin_lock_irqsave(&tp->lock, flags);
        for (n = 0; n < max;) {
                len += snprintf(page + len, count - len,
                                "\n0x%02x:\t",
                                n);

                for (i = 0; i < 4 && n < max; i++, n+=4) {
                        dword_rd = rtl8125_eri_read(tp, n, 4, ERIAR_ExGMAC);
                        len += snprintf(page + len, count - len,
                                        "%08x ",
                                        dword_rd);
                }
        }
        spin_unlock_irqrestore(&tp->lock, flags);

        len += snprintf(page + len, count - len, "\n");
out:
        *eof = 1;
        return len;
}

static int proc_get_pci_registers(char *page, char **start,
                                  off_t offset, int count,
                                  int *eof, void *data)
{
        struct net_device *dev = data;
        int i, n, max = R8125_PCI_REGS_SIZE;
        u32 dword_rd;
        struct rtl8125_private *tp = netdev_priv(dev);
        unsigned long flags;
        int len = 0;

        len += snprintf(page + len, count - len,
                        "\nDump PCI Registers\n"
                        "Offset\tValue\n------\t-----\n");

        spin_lock_irqsave(&tp->lock, flags);
        for (n = 0; n < max;) {
                len += snprintf(page + len, count - len,
                                "\n0x%03x:\t",
                                n);

                for (i = 0; i < 4 && n < max; i++, n+=4) {
                        pci_read_config_dword(tp->pci_dev, n, &dword_rd);
                        len += snprintf(page + len, count - len,
                                        "%08x ",
                                        dword_rd);
                }
        }

        n = 0x110;
        pci_read_config_dword(tp->pci_dev, n, &dword_rd);
        len += snprintf(page + len, count - len,
                        "\n0x%03x:\t%08x ",
                        n,
                        dword_rd);
        n = 0x70c;
        pci_read_config_dword(tp->pci_dev, n, &dword_rd);
        len += snprintf(page + len, count - len,
                        "\n0x%03x:\t%08x ",
                        n,
                        dword_rd);
        spin_unlock_irqrestore(&tp->lock, flags);

        len += snprintf(page + len, count - len, "\n");

        *eof = 1;
        return len;
}

static int proc_get_temperature(char *page, char **start,
                                off_t offset, int count,
                                int *eof, void *data)
{
        struct net_device *dev = data;
        struct rtl8125_private *tp = netdev_priv(dev);
        u16 ts_digout, tj, fah;
        unsigned long flags;
        int len = 0;

        switch (tp->mcfg) {
        case CFG_METHOD_4:
        case CFG_METHOD_5:
                len += snprintf(page + len, count - len,
                                "\nChip Temperature\n");
                break;
        default:
                len += snprintf(page + len, count - len,
                                "\nThis Chip Does Not Support Dump Temperature\n");
                break;
        }

        spin_lock_irqsave(&tp->lock, flags);
        ts_digout = rtl8125_read_thermal_sensor(tp);
        spin_unlock_irqrestore(&tp->lock, flags);

        tj = ts_digout / 2;
        if (ts_digout <= 512) {
                tj = ts_digout / 2;
                len += snprintf(page + len, count - len,
                                "Cel:%d\n",
                                tj);
                fah = tj * (9/5) + 32;
                len += snprintf(page + len, count - len,
                                "Fah:%d\n",
                                fah);

        } else {
                tj = (512 - ((ts_digout / 2) - 512)) / 2;
                len += snprintf(page + len, count - len,
                                "Cel:-%d\n",
                                tj);
                fah = tj * (9/5) + 32;
                len += snprintf(page + len, count - len,
                                "Fah:-%d\n",
                                fah);
        }

        len += snprintf(page + len, count - len, "\n");

        *eof = 1;
        return len;
}
#endif
static void rtl8125_proc_module_init(void)
{
        //create /proc/net/r8125
#if LINUX_VERSION_CODE >= KERNEL_VERSION(2,6,32)
        rtl8125_proc = proc_mkdir(MODULENAME, init_net.proc_net);
#else
        rtl8125_proc = proc_mkdir(MODULENAME, proc_net);
#endif
        if (!rtl8125_proc)
                dprintk("cannot create %s proc entry \n", MODULENAME);
}

#if LINUX_VERSION_CODE >= KERNEL_VERSION(3,10,0)
/*
 * seq_file wrappers for procfile show routines.
 */
static int rtl8125_proc_open(struct inode *inode, struct file *file)
{
        struct net_device *dev = proc_get_parent_data(inode);
        int (*show)(struct seq_file *, void *) = PDE_DATA(inode);

        return single_open(file, show, dev);
}

#if LINUX_VERSION_CODE >= KERNEL_VERSION(5,6,0)
static const struct proc_ops rtl8125_proc_fops = {
        .proc_open           = rtl8125_proc_open,
        .proc_read           = seq_read,
        .proc_lseek          = seq_lseek,
        .proc_release        = single_release,
};
#else
static const struct file_operations rtl8125_proc_fops = {
        .open           = rtl8125_proc_open,
        .read           = seq_read,
        .llseek         = seq_lseek,
        .release        = single_release,
};
#endif

#endif

/*
 * Table of proc files we need to create.
 */
struct rtl8125_proc_file {
        char name[12];
#if LINUX_VERSION_CODE >= KERNEL_VERSION(3,10,0)
        int (*show)(struct seq_file *, void *);
#else
        int (*show)(char *, char **, off_t, int, int *, void *);
#endif
};

static const struct rtl8125_proc_file rtl8125_proc_files[] = {
        { "driver_var", &proc_get_driver_variable },
        { "tally", &proc_get_tally_counter },
        { "registers", &proc_get_registers },
        { "pcie_phy", &proc_get_pcie_phy },
        { "eth_phy", &proc_get_eth_phy },
        { "ext_regs", &proc_get_extended_registers },
        { "pci_regs", &proc_get_pci_registers },
        { "temp", &proc_get_temperature },
        { "", NULL }
};

static void rtl8125_proc_init(struct net_device *dev)
{
        struct rtl8125_private *tp = netdev_priv(dev);
        const struct rtl8125_proc_file *f;
        struct proc_dir_entry *dir;

        if (rtl8125_proc && !tp->proc_dir) {
#if LINUX_VERSION_CODE >= KERNEL_VERSION(3,10,0)
                dir = proc_mkdir_data(dev->name, 0, rtl8125_proc, dev);
                if (!dir) {
                        printk("Unable to initialize /proc/net/%s/%s\n",
                               MODULENAME, dev->name);
                        return;
                }

                tp->proc_dir = dir;
                proc_init_num++;

                for (f = rtl8125_proc_files; f->name[0]; f++) {
                        if (!proc_create_data(f->name, S_IFREG | S_IRUGO, dir,
                                              &rtl8125_proc_fops, f->show)) {
                                printk("Unable to initialize "
                                       "/proc/net/%s/%s/%s\n",
                                       MODULENAME, dev->name, f->name);
                                return;
                        }
                }
#else
                dir = proc_mkdir(dev->name, rtl8125_proc);
                if (!dir) {
                        printk("Unable to initialize /proc/net/%s/%s\n",
                               MODULENAME, dev->name);
                        return;
                }

                tp->proc_dir = dir;
                proc_init_num++;

                for (f = rtl8125_proc_files; f->name[0]; f++) {
                        if (!create_proc_read_entry(f->name, S_IFREG | S_IRUGO,
                                                    dir, f->show, dev)) {
                                printk("Unable to initialize "
                                       "/proc/net/%s/%s/%s\n",
                                       MODULENAME, dev->name, f->name);
                                return;
                        }
                }
#endif
        }
}

static void rtl8125_proc_remove(struct net_device *dev)
{
        struct rtl8125_private *tp = netdev_priv(dev);

        if (tp->proc_dir) {
#if LINUX_VERSION_CODE >= KERNEL_VERSION(3,10,0)
                remove_proc_subtree(dev->name, rtl8125_proc);
                proc_init_num--;

#else
                const struct rtl8125_proc_file *f;
                struct rtl8125_private *tp = netdev_priv(dev);

                for (f = rtl8125_proc_files; f->name[0]; f++)
                        remove_proc_entry(f->name, tp->proc_dir);

                remove_proc_entry(dev->name, rtl8125_proc);
                proc_init_num--;
#endif
                tp->proc_dir = NULL;
        }
}

#endif //ENABLE_R8125_PROCFS

static inline u16 map_phy_ocp_addr(u16 PageNum, u8 RegNum)
{
        u16 OcpPageNum = 0;
        u8 OcpRegNum = 0;
        u16 OcpPhyAddress = 0;

        if ( PageNum == 0 ) {
                OcpPageNum = OCP_STD_PHY_BASE_PAGE + ( RegNum / 8 );
                OcpRegNum = 0x10 + ( RegNum % 8 );
        } else {
                OcpPageNum = PageNum;
                OcpRegNum = RegNum;
        }

        OcpPageNum <<= 4;

        if ( OcpRegNum < 16 ) {
                OcpPhyAddress = 0;
        } else {
                OcpRegNum -= 16;
                OcpRegNum <<= 1;

                OcpPhyAddress = OcpPageNum + OcpRegNum;
        }


        return OcpPhyAddress;
}

static void mdio_real_direct_write_phy_ocp(struct rtl8125_private *tp,
                u16 RegAddr,
                u16 value)
{
        u32 data32;
        int i;

#if LINUX_VERSION_CODE >= KERNEL_VERSION(2,6,18)
        WARN_ON_ONCE(RegAddr % 2);
#endif
        data32 = RegAddr/2;
        data32 <<= OCPR_Addr_Reg_shift;
        data32 |= OCPR_Write | value;

        RTL_W32(tp, PHYOCP, data32);
        for (i = 0; i < 100; i++) {
                udelay(1);

                if (!(RTL_R32(tp, PHYOCP) & OCPR_Flag))
                        break;
        }
}

static void mdio_direct_write_phy_ocp(struct rtl8125_private *tp,
                                      u16 RegAddr,
                                      u16 value)
{
        if (tp->rtk_enable_diag) return;

        mdio_real_direct_write_phy_ocp(tp, RegAddr, value);
}

/*
static void rtl8125_mdio_write_phy_ocp(struct rtl8125_private *tp,
                                       u16 PageNum,
                                       u32 RegAddr,
                                       u32 value)
{
        u16 ocp_addr;

        ocp_addr = map_phy_ocp_addr(PageNum, RegAddr);

        mdio_direct_write_phy_ocp(tp, ocp_addr, value);
}
*/

static void rtl8125_mdio_real_write_phy_ocp(struct rtl8125_private *tp,
                u16 PageNum,
                u32 RegAddr,
                u32 value)
{
        u16 ocp_addr;

        ocp_addr = map_phy_ocp_addr(PageNum, RegAddr);

        mdio_real_direct_write_phy_ocp(tp, ocp_addr, value);
}

static void mdio_real_write(struct rtl8125_private *tp,
                            u16 RegAddr,
                            u16 value)
{
        if (RegAddr == 0x1F) {
                tp->cur_page = value;
                return;
        }
        rtl8125_mdio_real_write_phy_ocp(tp, tp->cur_page, RegAddr, value);
}

void rtl8125_mdio_write(struct rtl8125_private *tp,
                        u16 RegAddr,
                        u16 value)
{
        if (tp->rtk_enable_diag) return;

        mdio_real_write(tp, RegAddr, value);
}

void rtl8125_mdio_prot_write(struct rtl8125_private *tp,
                             u32 RegAddr,
                             u32 value)
{
        mdio_real_write(tp, RegAddr, value);
}

void rtl8125_mdio_prot_direct_write_phy_ocp(struct rtl8125_private *tp,
                u32 RegAddr,
                u32 value)
{
        mdio_real_direct_write_phy_ocp(tp, RegAddr, value);
}

static u32 mdio_real_direct_read_phy_ocp(struct rtl8125_private *tp,
                u16 RegAddr)
{
        u32 data32;
        int i, value = 0;

#if LINUX_VERSION_CODE >= KERNEL_VERSION(2,6,18)
        WARN_ON_ONCE(RegAddr % 2);
#endif
        data32 = RegAddr/2;
        data32 <<= OCPR_Addr_Reg_shift;

        RTL_W32(tp, PHYOCP, data32);
        for (i = 0; i < 100; i++) {
                udelay(1);

                if (RTL_R32(tp, PHYOCP) & OCPR_Flag)
                        break;
        }
        value = RTL_R32(tp, PHYOCP) & OCPDR_Data_Mask;

        return value;
}

static u32 mdio_direct_read_phy_ocp(struct rtl8125_private *tp,
                                    u16 RegAddr)
{
        if (tp->rtk_enable_diag) return 0xffffffff;

        return mdio_real_direct_read_phy_ocp(tp, RegAddr);
}

/*
static u32 rtl8125_mdio_read_phy_ocp(struct rtl8125_private *tp,
                                     u16 PageNum,
                                     u32 RegAddr)
{
        u16 ocp_addr;

        ocp_addr = map_phy_ocp_addr(PageNum, RegAddr);

        return mdio_direct_read_phy_ocp(tp, ocp_addr);
}
*/

static u32 rtl8125_mdio_real_read_phy_ocp(struct rtl8125_private *tp,
                u16 PageNum,
                u32 RegAddr)
{
        u16 ocp_addr;

        ocp_addr = map_phy_ocp_addr(PageNum, RegAddr);

        return mdio_real_direct_read_phy_ocp(tp, ocp_addr);
}

static u32 mdio_real_read(struct rtl8125_private *tp,
                          u16 RegAddr)
{
        return rtl8125_mdio_real_read_phy_ocp(tp, tp->cur_page, RegAddr);
}

u32 rtl8125_mdio_read(struct rtl8125_private *tp,
                      u16 RegAddr)
{
        if (tp->rtk_enable_diag) return 0xffffffff;

        return mdio_real_read(tp, RegAddr);
}

u32 rtl8125_mdio_prot_read(struct rtl8125_private *tp,
                           u32 RegAddr)
{
        return mdio_real_read(tp, RegAddr);
}

u32 rtl8125_mdio_prot_direct_read_phy_ocp(struct rtl8125_private *tp,
                u32 RegAddr)
{
        return mdio_real_direct_read_phy_ocp(tp, RegAddr);
}

static void ClearAndSetEthPhyBit(struct rtl8125_private *tp, u8  addr, u16 clearmask, u16 setmask)
{
        u16 PhyRegValue;

        PhyRegValue = rtl8125_mdio_read(tp, addr);
        PhyRegValue &= ~clearmask;
        PhyRegValue |= setmask;
        rtl8125_mdio_write(tp, addr, PhyRegValue);
}

void rtl8125_clear_eth_phy_bit(struct rtl8125_private *tp, u8 addr, u16 mask)
{
        ClearAndSetEthPhyBit(tp,
                             addr,
                             mask,
                             0
                            );
}

void rtl8125_set_eth_phy_bit(struct rtl8125_private *tp,  u8  addr, u16  mask)
{
        ClearAndSetEthPhyBit(tp,
                             addr,
                             0,
                             mask
                            );
}

static void ClearAndSetEthPhyOcpBit(struct rtl8125_private *tp, u16 addr, u16 clearmask, u16 setmask)
{
        u16 PhyRegValue;

        PhyRegValue = mdio_direct_read_phy_ocp(tp, addr);
        PhyRegValue &= ~clearmask;
        PhyRegValue |= setmask;
        mdio_direct_write_phy_ocp(tp, addr, PhyRegValue);
}

void ClearEthPhyOcpBit(struct rtl8125_private *tp, u16 addr, u16 mask)
{
        ClearAndSetEthPhyOcpBit(tp,
                                addr,
                                mask,
                                0
                               );
}

void SetEthPhyOcpBit(struct rtl8125_private *tp,  u16 addr, u16 mask)
{
        ClearAndSetEthPhyOcpBit(tp,
                                addr,
                                0,
                                mask
                               );
}

void rtl8125_mac_ocp_write(struct rtl8125_private *tp, u16 reg_addr, u16 value)
{
        u32 data32;

#if LINUX_VERSION_CODE >= KERNEL_VERSION(2,6,18)
        WARN_ON_ONCE(reg_addr % 2);
#endif

        data32 = reg_addr/2;
        data32 <<= OCPR_Addr_Reg_shift;
        data32 += value;
        data32 |= OCPR_Write;

        RTL_W32(tp, MACOCP, data32);
}

u32 rtl8125_mac_ocp_read(struct rtl8125_private *tp, u16 reg_addr)
{
        u32 data32;
        u16 data16 = 0;

#if LINUX_VERSION_CODE >= KERNEL_VERSION(2,6,18)
        WARN_ON_ONCE(reg_addr % 2);
#endif

        data32 = reg_addr/2;
        data32 <<= OCPR_Addr_Reg_shift;

        RTL_W32(tp, MACOCP, data32);
        data16 = (u16)RTL_R32(tp, MACOCP);

        return data16;
}

#ifdef ENABLE_USE_FIRMWARE_FILE
static void mac_mcu_write(struct rtl8125_private *tp, u16 reg, u16 value)
{
        if (reg == 0x1f) {
                tp->ocp_base = value << 4;
                return;
        }

        rtl8125_mac_ocp_write(tp, tp->ocp_base + reg, value);
}

static u32 mac_mcu_read(struct rtl8125_private *tp, u16 reg)
{
        return rtl8125_mac_ocp_read(tp, tp->ocp_base + reg);
}
#endif

static void
ClearAndSetMcuAccessRegBit(
        struct rtl8125_private *tp,
        u16   addr,
        u16   clearmask,
        u16   setmask
)
{
        u16 PhyRegValue;

        PhyRegValue = rtl8125_mac_ocp_read(tp, addr);
        PhyRegValue &= ~clearmask;
        PhyRegValue |= setmask;
        rtl8125_mac_ocp_write(tp, addr, PhyRegValue);
}

static void
ClearMcuAccessRegBit(
        struct rtl8125_private *tp,
        u16   addr,
        u16   mask
)
{
        ClearAndSetMcuAccessRegBit(tp,
                                   addr,
                                   mask,
                                   0
                                  );
}

static void
SetMcuAccessRegBit(
        struct rtl8125_private *tp,
        u16   addr,
        u16   mask
)
{
        ClearAndSetMcuAccessRegBit(tp,
                                   addr,
                                   0,
                                   mask
                                  );
}

u32 rtl8125_ocp_read_with_oob_base_address(struct rtl8125_private *tp, u16 addr, u8 len, const u32 base_address)
{
        return rtl8125_eri_read_with_oob_base_address(tp, addr, len, ERIAR_OOB, base_address);
}

u32 rtl8125_ocp_read(struct rtl8125_private *tp, u16 addr, u8 len)
{
        u32 value = 0;

        if (HW_DASH_SUPPORT_TYPE_2(tp))
                value = rtl8125_ocp_read_with_oob_base_address(tp, addr, len, NO_BASE_ADDRESS);
        else if (HW_DASH_SUPPORT_TYPE_3(tp))
                value = rtl8125_ocp_read_with_oob_base_address(tp, addr, len, RTL8168FP_OOBMAC_BASE);

        return value;
}

u32 rtl8125_ocp_write_with_oob_base_address(struct rtl8125_private *tp, u16 addr, u8 len, u32 value, const u32 base_address)
{
        return rtl8125_eri_write_with_oob_base_address(tp, addr, len, value, ERIAR_OOB, base_address);
}

void rtl8125_ocp_write(struct rtl8125_private *tp, u16 addr, u8 len, u32 value)
{
        if (HW_DASH_SUPPORT_TYPE_2(tp))
                rtl8125_ocp_write_with_oob_base_address(tp, addr, len, value, NO_BASE_ADDRESS);
        else if (HW_DASH_SUPPORT_TYPE_3(tp))
                rtl8125_ocp_write_with_oob_base_address(tp, addr, len, value, RTL8168FP_OOBMAC_BASE);
}

void rtl8125_oob_mutex_lock(struct rtl8125_private *tp)
{
        u8 reg_16, reg_a0;
        u32 wait_cnt_0, wait_Cnt_1;
        u16 ocp_reg_mutex_ib;
        u16 ocp_reg_mutex_oob;
        u16 ocp_reg_mutex_prio;

        if (!tp->DASH) return;

        switch (tp->mcfg) {
        case CFG_METHOD_2:
        case CFG_METHOD_3:
        case CFG_METHOD_4:
        case CFG_METHOD_5:
        default:
                ocp_reg_mutex_oob = 0x110;
                ocp_reg_mutex_ib = 0x114;
                ocp_reg_mutex_prio = 0x11C;
                break;
        }

        rtl8125_ocp_write(tp, ocp_reg_mutex_ib, 1, BIT_0);
        reg_16 = rtl8125_ocp_read(tp, ocp_reg_mutex_oob, 1);
        wait_cnt_0 = 0;
        while(reg_16) {
                reg_a0 = rtl8125_ocp_read(tp, ocp_reg_mutex_prio, 1);
                if (reg_a0) {
                        rtl8125_ocp_write(tp, ocp_reg_mutex_ib, 1, 0x00);
                        reg_a0 = rtl8125_ocp_read(tp, ocp_reg_mutex_prio, 1);
                        wait_Cnt_1 = 0;
                        while(reg_a0) {
                                reg_a0 = rtl8125_ocp_read(tp, ocp_reg_mutex_prio, 1);

                                wait_Cnt_1++;

                                if (wait_Cnt_1 > 2000)
                                        break;
                        };
                        rtl8125_ocp_write(tp, ocp_reg_mutex_ib, 1, BIT_0);

                }
                reg_16 = rtl8125_ocp_read(tp, ocp_reg_mutex_oob, 1);

                wait_cnt_0++;

                if (wait_cnt_0 > 2000)
                        break;
        };
}

void rtl8125_oob_mutex_unlock(struct rtl8125_private *tp)
{
        u16 ocp_reg_mutex_ib;
        u16 ocp_reg_mutex_oob;
        u16 ocp_reg_mutex_prio;

        if (!tp->DASH) return;

        switch (tp->mcfg) {
        case CFG_METHOD_2:
        case CFG_METHOD_3:
        case CFG_METHOD_4:
        case CFG_METHOD_5:
        default:
                ocp_reg_mutex_oob = 0x110;
                ocp_reg_mutex_ib = 0x114;
                ocp_reg_mutex_prio = 0x11C;
                break;
        }

        rtl8125_ocp_write(tp, ocp_reg_mutex_prio, 1, BIT_0);
        rtl8125_ocp_write(tp, ocp_reg_mutex_ib, 1, 0x00);
}

void rtl8125_oob_notify(struct rtl8125_private *tp, u8 cmd)
{
        rtl8125_eri_write(tp, 0xE8, 1, cmd, ERIAR_ExGMAC);

        rtl8125_ocp_write(tp, 0x30, 1, 0x01);
}

static int rtl8125_check_dash(struct rtl8125_private *tp)
{
        if (HW_DASH_SUPPORT_TYPE_2(tp) || HW_DASH_SUPPORT_TYPE_3(tp)) {
                if (rtl8125_ocp_read(tp, 0x128, 1) & BIT_0)
                        return 1;
        }

        return 0;
}

void rtl8125_dash2_disable_tx(struct rtl8125_private *tp)
{
        if (!tp->DASH) return;

        if (HW_DASH_SUPPORT_TYPE_2(tp) || HW_DASH_SUPPORT_TYPE_3(tp)) {
                u16 WaitCnt;
                u8 TmpUchar;

                //Disable oob Tx
                RTL_CMAC_W8(tp, CMAC_IBCR2, RTL_CMAC_R8(tp, CMAC_IBCR2) & ~( BIT_0 ));
                WaitCnt = 0;

                //wait oob tx disable
                do {
                        TmpUchar = RTL_CMAC_R8(tp, CMAC_IBISR0);

                        if ( TmpUchar & ISRIMR_DASH_TYPE2_TX_DISABLE_IDLE ) {
                                break;
                        }

                        udelay( 50 );
                        WaitCnt++;
                } while(WaitCnt < 2000);

                //Clear ISRIMR_DASH_TYPE2_TX_DISABLE_IDLE
                RTL_CMAC_W8(tp, CMAC_IBISR0, RTL_CMAC_R8(tp, CMAC_IBISR0) | ISRIMR_DASH_TYPE2_TX_DISABLE_IDLE);
        }
}

void rtl8125_dash2_enable_tx(struct rtl8125_private *tp)
{
        if (!tp->DASH) return;

        if (HW_DASH_SUPPORT_TYPE_2(tp) || HW_DASH_SUPPORT_TYPE_3(tp)) {
                RTL_CMAC_W8(tp, CMAC_IBCR2, RTL_CMAC_R8(tp, CMAC_IBCR2) | BIT_0);
        }
}

void rtl8125_dash2_disable_rx(struct rtl8125_private *tp)
{
        if (!tp->DASH) return;

        if (HW_DASH_SUPPORT_TYPE_2(tp) || HW_DASH_SUPPORT_TYPE_3(tp)) {
                RTL_CMAC_W8(tp, CMAC_IBCR0, RTL_CMAC_R8(tp, CMAC_IBCR0) & ~( BIT_0 ));
        }
}

void rtl8125_dash2_enable_rx(struct rtl8125_private *tp)
{
        if (!tp->DASH) return;

        if (HW_DASH_SUPPORT_TYPE_2(tp) || HW_DASH_SUPPORT_TYPE_3(tp)) {
                RTL_CMAC_W8(tp, CMAC_IBCR0, RTL_CMAC_R8(tp, CMAC_IBCR0) | BIT_0);
        }
}

static void rtl8125_dash2_disable_txrx(struct net_device *dev)
{
        struct rtl8125_private *tp = netdev_priv(dev);

        if (HW_DASH_SUPPORT_TYPE_2(tp) || HW_DASH_SUPPORT_TYPE_3(tp)) {
                rtl8125_dash2_disable_tx( tp );
                rtl8125_dash2_disable_rx( tp );
        }
}

static void rtl8125_driver_start(struct rtl8125_private *tp)
{
        if (!tp->DASH)
                return;

        if (HW_DASH_SUPPORT_TYPE_2(tp) || HW_DASH_SUPPORT_TYPE_3(tp)) {
                int timeout;
                u32 tmp_value;

                rtl8125_ocp_write(tp, 0x180, 1, OOB_CMD_DRIVER_START);
                tmp_value = rtl8125_ocp_read(tp, 0x30, 1);
                tmp_value |= BIT_0;
                rtl8125_ocp_write(tp, 0x30, 1, tmp_value);

                for (timeout = 0; timeout < 10; timeout++) {
                        mdelay(10);
                        if (rtl8125_ocp_read(tp, 0x124, 1) & BIT_0)
                                break;
                }
        }
}

static void rtl8125_driver_stop(struct rtl8125_private *tp)
{
        if (!tp->DASH)
                return;

        if (HW_DASH_SUPPORT_TYPE_2(tp) || HW_DASH_SUPPORT_TYPE_3(tp)) {
                struct net_device *dev = tp->dev;
                int timeout;
                u32 tmp_value;

                rtl8125_dash2_disable_txrx(dev);

                rtl8125_ocp_write(tp, 0x180, 1, OOB_CMD_DRIVER_STOP);
                tmp_value = rtl8125_ocp_read(tp, 0x30, 1);
                tmp_value |= BIT_0;
                rtl8125_ocp_write(tp, 0x30, 1, tmp_value);

                for (timeout = 0; timeout < 10; timeout++) {
                        mdelay(10);
                        if (!(rtl8125_ocp_read(tp, 0x124, 1) & BIT_0))
                                break;
                }
        }
}

void rtl8125_ephy_write(struct rtl8125_private *tp, int RegAddr, int value)
{
        int i;

        RTL_W32(tp, EPHYAR,
                EPHYAR_Write |
                (RegAddr & EPHYAR_Reg_Mask_v2) << EPHYAR_Reg_shift |
                (value & EPHYAR_Data_Mask));

        for (i = 0; i < 10; i++) {
                udelay(100);

                /* Check if the RTL8125 has completed EPHY write */
                if (!(RTL_R32(tp, EPHYAR) & EPHYAR_Flag))
                        break;
        }

        udelay(20);
}

u16 rtl8125_ephy_read(struct rtl8125_private *tp, int RegAddr)
{
        int i;
        u16 value = 0xffff;

        RTL_W32(tp, EPHYAR,
                EPHYAR_Read | (RegAddr & EPHYAR_Reg_Mask_v2) << EPHYAR_Reg_shift);

        for (i = 0; i < 10; i++) {
                udelay(100);

                /* Check if the RTL8125 has completed EPHY read */
                if (RTL_R32(tp, EPHYAR) & EPHYAR_Flag) {
                        value = (u16) (RTL_R32(tp, EPHYAR) & EPHYAR_Data_Mask);
                        break;
                }
        }

        udelay(20);

        return value;
}

static void ClearAndSetPCIePhyBit(struct rtl8125_private *tp, u8 addr, u16 clearmask, u16 setmask)
{
        u16 EphyValue;

        EphyValue = rtl8125_ephy_read(tp, addr);
        EphyValue &= ~clearmask;
        EphyValue |= setmask;
        rtl8125_ephy_write(tp, addr, EphyValue);
}

static void ClearPCIePhyBit(struct rtl8125_private *tp, u8 addr, u16 mask)
{
        ClearAndSetPCIePhyBit( tp,
                               addr,
                               mask,
                               0
                             );
}

static void SetPCIePhyBit( struct rtl8125_private *tp, u8 addr, u16 mask)
{
        ClearAndSetPCIePhyBit( tp,
                               addr,
                               0,
                               mask
                             );
}

static u32
rtl8125_csi_other_fun_read(struct rtl8125_private *tp,
                           u8 multi_fun_sel_bit,
                           u32 addr)
{
        u32 cmd;
        int i;
        u32 value = 0;

        cmd = CSIAR_Read | CSIAR_ByteEn << CSIAR_ByteEn_shift | (addr & CSIAR_Addr_Mask);

        if (tp->mcfg == CFG_METHOD_DEFAULT)
                multi_fun_sel_bit = 0;

        if (multi_fun_sel_bit > 7)
                return 0xffffffff;

        cmd |= multi_fun_sel_bit << 16;

        RTL_W32(tp, CSIAR, cmd);

        for (i = 0; i < 10; i++) {
                udelay(100);

                /* Check if the RTL8125 has completed CSI read */
                if (RTL_R32(tp, CSIAR) & CSIAR_Flag) {
                        value = (u32)RTL_R32(tp, CSIDR);
                        break;
                }
        }

        udelay(20);

        return value;
}

static void
rtl8125_csi_other_fun_write(struct rtl8125_private *tp,
                            u8 multi_fun_sel_bit,
                            u32 addr,
                            u32 value)
{
        u32 cmd;
        int i;

        RTL_W32(tp, CSIDR, value);
        cmd = CSIAR_Write | CSIAR_ByteEn << CSIAR_ByteEn_shift | (addr & CSIAR_Addr_Mask);
        if (tp->mcfg == CFG_METHOD_DEFAULT)
                multi_fun_sel_bit = 0;

        if ( multi_fun_sel_bit > 7 )
                return;

        cmd |= multi_fun_sel_bit << 16;

        RTL_W32(tp, CSIAR, cmd);

        for (i = 0; i < 10; i++) {
                udelay(100);

                /* Check if the RTL8125 has completed CSI write */
                if (!(RTL_R32(tp, CSIAR) & CSIAR_Flag))
                        break;
        }

        udelay(20);
}

static u32
rtl8125_csi_read(struct rtl8125_private *tp,
                 u32 addr)
{
        u8 multi_fun_sel_bit;

        multi_fun_sel_bit = 0;

        return rtl8125_csi_other_fun_read(tp, multi_fun_sel_bit, addr);
}

static void
rtl8125_csi_write(struct rtl8125_private *tp,
                  u32 addr,
                  u32 value)
{
        u8 multi_fun_sel_bit;

        multi_fun_sel_bit = 0;

        rtl8125_csi_other_fun_write(tp, multi_fun_sel_bit, addr, value);
}

static u8
rtl8125_csi_fun0_read_byte(struct rtl8125_private *tp,
                           u32 addr)
{
        u8 RetVal = 0;

        if (tp->mcfg == CFG_METHOD_DEFAULT) {
                struct pci_dev *pdev = tp->pci_dev;

                pci_read_config_byte(pdev, addr, &RetVal);
        } else {
                u32 TmpUlong;
                u16 RegAlignAddr;
                u8 ShiftByte;

                RegAlignAddr = addr & ~(0x3);
                ShiftByte = addr & (0x3);
                TmpUlong = rtl8125_csi_other_fun_read(tp, 0, addr);
                TmpUlong >>= (8*ShiftByte);
                RetVal = (u8)TmpUlong;
        }

        udelay(20);

        return RetVal;
}

static void
rtl8125_csi_fun0_write_byte(struct rtl8125_private *tp,
                            u32 addr,
                            u8 value)
{
        if (tp->mcfg == CFG_METHOD_DEFAULT) {
                struct pci_dev *pdev = tp->pci_dev;

                pci_write_config_byte(pdev, addr, value);
        } else {
                u32 TmpUlong;
                u16 RegAlignAddr;
                u8 ShiftByte;

                RegAlignAddr = addr & ~(0x3);
                ShiftByte = addr & (0x3);
                TmpUlong = rtl8125_csi_other_fun_read(tp, 0, RegAlignAddr);
                TmpUlong &= ~(0xFF << (8*ShiftByte));
                TmpUlong |= (value << (8*ShiftByte));
                rtl8125_csi_other_fun_write( tp, 0, RegAlignAddr, TmpUlong );
        }

        udelay(20);
}

u32 rtl8125_eri_read_with_oob_base_address(struct rtl8125_private *tp, int addr, int len, int type, const u32 base_address)
{
        int i, val_shift, shift = 0;
        u32 value1 = 0, value2 = 0, mask;
        u32 eri_cmd;
        const u32 transformed_base_address = ((base_address & 0x00FFF000) << 6) | (base_address & 0x000FFF);

        if (len > 4 || len <= 0)
                return -1;

        while (len > 0) {
                val_shift = addr % ERIAR_Addr_Align;
                addr = addr & ~0x3;

                eri_cmd = ERIAR_Read |
                          transformed_base_address |
                          type << ERIAR_Type_shift |
                          ERIAR_ByteEn << ERIAR_ByteEn_shift |
                          (addr & 0x0FFF);
                if (addr & 0xF000) {
                        u32 tmp;

                        tmp = addr & 0xF000;
                        tmp >>= 12;
                        eri_cmd |= (tmp << 20) & 0x00F00000;
                }

                RTL_W32(tp, ERIAR, eri_cmd);

                for (i = 0; i < 10; i++) {
                        udelay(100);

                        /* Check if the RTL8125 has completed ERI read */
                        if (RTL_R32(tp, ERIAR) & ERIAR_Flag)
                                break;
                }

                if (len == 1)       mask = (0xFF << (val_shift * 8)) & 0xFFFFFFFF;
                else if (len == 2)  mask = (0xFFFF << (val_shift * 8)) & 0xFFFFFFFF;
                else if (len == 3)  mask = (0xFFFFFF << (val_shift * 8)) & 0xFFFFFFFF;
                else            mask = (0xFFFFFFFF << (val_shift * 8)) & 0xFFFFFFFF;

                value1 = RTL_R32(tp, ERIDR) & mask;
                value2 |= (value1 >> val_shift * 8) << shift * 8;

                if (len <= 4 - val_shift) {
                        len = 0;
                } else {
                        len -= (4 - val_shift);
                        shift = 4 - val_shift;
                        addr += 4;
                }
        }

        udelay(20);

        return value2;
}

u32 rtl8125_eri_read(struct rtl8125_private *tp, int addr, int len, int type)
{
        return rtl8125_eri_read_with_oob_base_address(tp, addr, len, type, 0);
}

int rtl8125_eri_write_with_oob_base_address(struct rtl8125_private *tp, int addr, int len, u32 value, int type, const u32 base_address)
{
        int i, val_shift, shift = 0;
        u32 value1 = 0, mask;
        u32 eri_cmd;
        const u32 transformed_base_address = ((base_address & 0x00FFF000) << 6) | (base_address & 0x000FFF);

        if (len > 4 || len <= 0)
                return -1;

        while (len > 0) {
                val_shift = addr % ERIAR_Addr_Align;
                addr = addr & ~0x3;

                if (len == 1)       mask = (0xFF << (val_shift * 8)) & 0xFFFFFFFF;
                else if (len == 2)  mask = (0xFFFF << (val_shift * 8)) & 0xFFFFFFFF;
                else if (len == 3)  mask = (0xFFFFFF << (val_shift * 8)) & 0xFFFFFFFF;
                else            mask = (0xFFFFFFFF << (val_shift * 8)) & 0xFFFFFFFF;

                value1 = rtl8125_eri_read_with_oob_base_address(tp, addr, 4, type, base_address) & ~mask;
                value1 |= ((value << val_shift * 8) >> shift * 8);

                RTL_W32(tp, ERIDR, value1);

                eri_cmd = ERIAR_Write |
                          transformed_base_address |
                          type << ERIAR_Type_shift |
                          ERIAR_ByteEn << ERIAR_ByteEn_shift |
                          (addr & 0x0FFF);
                if (addr & 0xF000) {
                        u32 tmp;

                        tmp = addr & 0xF000;
                        tmp >>= 12;
                        eri_cmd |= (tmp << 20) & 0x00F00000;
                }

                RTL_W32(tp, ERIAR, eri_cmd);

                for (i = 0; i < 10; i++) {
                        udelay(100);

                        /* Check if the RTL8125 has completed ERI write */
                        if (!(RTL_R32(tp, ERIAR) & ERIAR_Flag))
                                break;
                }

                if (len <= 4 - val_shift) {
                        len = 0;
                } else {
                        len -= (4 - val_shift);
                        shift = 4 - val_shift;
                        addr += 4;
                }
        }

        udelay(20);

        return 0;
}

int rtl8125_eri_write(struct rtl8125_private *tp, int addr, int len, u32 value, int type)
{
        return rtl8125_eri_write_with_oob_base_address(tp, addr, len, value, type, NO_BASE_ADDRESS);
}

static void
rtl8125_enable_rxdvgate(struct net_device *dev)
{
        struct rtl8125_private *tp = netdev_priv(dev);

        switch (tp->mcfg) {
        case CFG_METHOD_2:
        case CFG_METHOD_3:
        case CFG_METHOD_4:
        case CFG_METHOD_5:
                RTL_W8(tp, 0xF2, RTL_R8(tp, 0xF2) | BIT_3);
                mdelay(2);
                break;
        }
}

static void
rtl8125_disable_rxdvgate(struct net_device *dev)
{
        struct rtl8125_private *tp = netdev_priv(dev);

        switch (tp->mcfg) {
        case CFG_METHOD_2:
        case CFG_METHOD_3:
        case CFG_METHOD_4:
        case CFG_METHOD_5:
                RTL_W8(tp, 0xF2, RTL_R8(tp, 0xF2) & ~BIT_3);
                mdelay(2);
                break;
        }
}

static u8
rtl8125_is_gpio_low(struct net_device *dev)
{
        struct rtl8125_private *tp = netdev_priv(dev);
        u8 gpio_low = FALSE;

        switch (tp->HwSuppCheckPhyDisableModeVer) {
        case 3:
                if (!(rtl8125_mac_ocp_read(tp, 0xDC04) & BIT_13))
                        gpio_low = TRUE;
                break;
        }

        if (gpio_low)
                dprintk("gpio is low.\n");

        return gpio_low;
}

static u8
rtl8125_is_phy_disable_mode_enabled(struct net_device *dev)
{
        struct rtl8125_private *tp = netdev_priv(dev);
        u8 phy_disable_mode_enabled = FALSE;

        switch (tp->HwSuppCheckPhyDisableModeVer) {
        case 3:
                if (RTL_R8(tp, 0xF2) & BIT_5)
                        phy_disable_mode_enabled = TRUE;
                break;
        }

        if (phy_disable_mode_enabled)
                dprintk("phy disable mode enabled.\n");

        return phy_disable_mode_enabled;
}

static u8
rtl8125_is_in_phy_disable_mode(struct net_device *dev)
{
        u8 in_phy_disable_mode = FALSE;

        if (rtl8125_is_phy_disable_mode_enabled(dev) && rtl8125_is_gpio_low(dev))
                in_phy_disable_mode = TRUE;

        if (in_phy_disable_mode)
                dprintk("Hardware is in phy disable mode.\n");

        return in_phy_disable_mode;
}

void
rtl8125_wait_txrx_fifo_empty(struct net_device *dev)
{
        struct rtl8125_private *tp = netdev_priv(dev);
        int i;

        switch (tp->mcfg) {
        case CFG_METHOD_2:
        case CFG_METHOD_3:
        case CFG_METHOD_4:
        case CFG_METHOD_5:
                for (i = 0; i < 3000; i++) {
                        udelay(50);
                        if ((RTL_R8(tp, MCUCmd_reg) & (Txfifo_empty | Rxfifo_empty)) == (Txfifo_empty | Rxfifo_empty))
                                break;

                }
                break;
        }

        switch (tp->mcfg) {
        case CFG_METHOD_4:
        case CFG_METHOD_5:
                for (i = 0; i < 3000; i++) {
                        udelay(50);
                        if ((RTL_R16(tp, IntrMitigate) & (BIT_0 | BIT_1 | BIT_8)) == (BIT_0 | BIT_1 | BIT_8))
                                break;

                }
                break;
        }
}

#ifdef ENABLE_DASH_SUPPORT

static inline void
rtl8125_enable_dash2_interrupt(struct rtl8125_private *tp)
{
        if (!tp->DASH) return;

        if (HW_DASH_SUPPORT_TYPE_2(tp) || HW_DASH_SUPPORT_TYPE_3(tp)) {
                RTL_CMAC_W8(tp, CMAC_IBIMR0, ( ISRIMR_DASH_TYPE2_ROK | ISRIMR_DASH_TYPE2_TOK | ISRIMR_DASH_TYPE2_TDU | ISRIMR_DASH_TYPE2_RDU | ISRIMR_DASH_TYPE2_RX_DISABLE_IDLE ));
        }
}

static inline void
rtl8125_disable_dash2_interrupt(struct rtl8125_private *tp)
{
        if (!tp->DASH) return;

        if (HW_DASH_SUPPORT_TYPE_2(tp) || HW_DASH_SUPPORT_TYPE_3(tp)) {
                RTL_CMAC_W8(tp, CMAC_IBIMR0, 0);
        }
}
#endif

void
rtl8125_enable_hw_linkchg_interrupt(struct rtl8125_private *tp)
{
        switch (tp->HwCurrIsrVer) {
        case 2:
                RTL_W32(tp, IMR_V2_SET_REG_8125, ISRIMR_V2_LINKCHG);
                break;
        case 1:
                RTL_W32(tp, tp->imr_reg[0], LinkChg);
                break;
        }

#ifdef ENABLE_DASH_SUPPORT
        if (tp->DASH)
                rtl8125_enable_dash2_interrupt(tp);
#endif
}

static inline void
rtl8125_enable_hw_interrupt(struct rtl8125_private *tp)
{
        switch (tp->HwCurrIsrVer) {
        case 2:
                RTL_W32(tp, IMR_V2_SET_REG_8125, tp->intr_mask);
                break;
        case 1:
                RTL_W32(tp, tp->imr_reg[0], tp->intr_mask);

                if (R8125_MULTI_RX_Q(tp)) {
                        int i;
                        for (i=1; i<tp->num_rx_rings; i++)
                                RTL_W16(tp, tp->imr_reg[i], other_q_intr_mask);
                }
                break;
        }

#ifdef ENABLE_DASH_SUPPORT
        if (tp->DASH)
                rtl8125_enable_dash2_interrupt(tp);
#endif
}

static inline void rtl8125_clear_hw_isr_v2(struct rtl8125_private *tp,
                u32 message_id)
{
        RTL_W32(tp, ISR_V2_8125, BIT(message_id));
}

static inline void
rtl8125_disable_hw_interrupt(struct rtl8125_private *tp)
{
        if (tp->HwCurrIsrVer == 2) {
                RTL_W32(tp, IMR_V2_CLEAR_REG_8125, 0xFFFFFFFF);
        } else {
                RTL_W32(tp, tp->imr_reg[0], 0x0000);

                if (R8125_MULTI_RX_Q(tp)) {
                        int i;
                        for (i=1; i<tp->num_rx_rings; i++)
                                RTL_W16(tp, tp->imr_reg[i], 0);
                }

#ifdef ENABLE_DASH_SUPPORT
                if (tp->DASH)
                        rtl8125_disable_dash2_interrupt(tp);
#endif
        }
}

static inline void
rtl8125_switch_to_hw_interrupt(struct rtl8125_private *tp)
{
        RTL_W32(tp, TIMER_INT0_8125, 0x0000);

        rtl8125_enable_hw_interrupt(tp);
}

static inline void
rtl8125_switch_to_timer_interrupt(struct rtl8125_private *tp)
{
        if (tp->use_timer_interrrupt) {
                RTL_W32(tp, TIMER_INT0_8125, timer_count);
                RTL_W32(tp, TCTR0_8125, timer_count);
                RTL_W32(tp, tp->imr_reg[0], tp->timer_intr_mask);

#ifdef ENABLE_DASH_SUPPORT
                if (tp->DASH)
                        rtl8125_enable_dash2_interrupt(tp);
#endif
        } else {
                rtl8125_switch_to_hw_interrupt(tp);
        }
}

static void
rtl8125_irq_mask_and_ack(struct rtl8125_private *tp)
{
        rtl8125_disable_hw_interrupt(tp);

        if (tp->HwCurrIsrVer == 2) {
                RTL_W32(tp, ISR_V2_8125, 0xFFFFFFFF);
        } else {
#ifdef ENABLE_DASH_SUPPORT
                if (tp->DASH) {
                        if (tp->dash_printer_enabled) {
                                RTL_W32(tp, tp->isr_reg[0], RTL_R32(tp, tp->isr_reg[0]) &
                                        ~(ISRIMR_DASH_INTR_EN | ISRIMR_DASH_INTR_CMAC_RESET));
                        } else {
                                if (HW_DASH_SUPPORT_TYPE_2(tp) || HW_DASH_SUPPORT_TYPE_3(tp)) {
                                        RTL_CMAC_W8(tp, CMAC_IBISR0, RTL_CMAC_R8(tp, CMAC_IBISR0));
                                }
                        }
                } else {
                        RTL_W32(tp, tp->isr_reg[0], RTL_R32(tp, tp->isr_reg[0]));
                }
#else
                RTL_W32(tp, tp->isr_reg[0], RTL_R32(tp, tp->isr_reg[0]));
#endif
                if (R8125_MULTI_RX_Q(tp)) {
                        int i;
                        for (i=1; i<tp->num_rx_rings; i++)
                                RTL_W16(tp, tp->isr_reg[i], RTL_R16(tp, tp->isr_reg[i]));
                }
        }
}

static void
rtl8125_nic_reset(struct net_device *dev)
{
        struct rtl8125_private *tp = netdev_priv(dev);
        int i;

        RTL_W32(tp, RxConfig, (RX_DMA_BURST << RxCfgDMAShift));

        rtl8125_enable_rxdvgate(dev);

        rtl8125_wait_txrx_fifo_empty(dev);

        switch (tp->mcfg) {
        case CFG_METHOD_2:
        case CFG_METHOD_3:
        case CFG_METHOD_4:
        case CFG_METHOD_5:
        default:
                mdelay(2);
                break;
        }

        /* Soft reset the chip. */
        RTL_W8(tp, ChipCmd, CmdReset);

        /* Check that the chip has finished the reset. */
        for (i = 100; i > 0; i--) {
                udelay(100);
                if ((RTL_R8(tp, ChipCmd) & CmdReset) == 0)
                        break;
        }
}

static void
rtl8125_hw_set_interrupt_type(struct rtl8125_private *tp, u8 isr_ver)
{
        u8 tmp;

        switch (tp->HwSuppIsrVer) {
        case 2:
                tmp = RTL_R8(tp, INT_CFG0_8125);
                tmp &= ~(INT_CFG0_ENABLE_8125);
                if (isr_ver == 2)
                        tmp |= INT_CFG0_ENABLE_8125;
                RTL_W8(tp, INT_CFG0_8125, tmp);
                break;
        }
}

static void
rtl8125_hw_clear_timer_int(struct net_device *dev)
{
        struct rtl8125_private *tp = netdev_priv(dev);

        switch (tp->mcfg) {
        case CFG_METHOD_2:
        case CFG_METHOD_3:
        case CFG_METHOD_4:
        case CFG_METHOD_5:
                RTL_W32(tp, TIMER_INT0_8125, 0x0000);
                RTL_W32(tp, TIMER_INT1_8125, 0x0000);
                RTL_W32(tp, TIMER_INT2_8125, 0x0000);
                RTL_W32(tp, TIMER_INT3_8125, 0x0000);
                break;
        }
}

static void
rtl8125_hw_clear_int_miti(struct net_device *dev)
{
        struct rtl8125_private *tp = netdev_priv(dev);
        int i;

        switch (tp->HwSuppIntMitiVer) {
        case 3:
                //IntMITI_0-IntMITI_31
                for (i=0xA00; i<0xB00; i+=4)
                        RTL_W32(tp, i, 0x0000);
                break;
        case 4:
                //IntMITI_0-IntMITI_15
                for (i = 0xA00; i < 0xA80; i += 4)
                        RTL_W32(tp, i, 0x0000);

                RTL_W8(tp, INT_CFG0_8125, RTL_R8(tp, INT_CFG0_8125) &
                       ~(INT_CFG0_TIMEOUT0_BYPASS_8125 | INT_CFG0_MITIGATION_BYPASS_8125));

                RTL_W16(tp, INT_CFG1_8125, 0x0000);
                break;
        }
}

void
rtl8125_hw_set_timer_int_8125(struct rtl8125_private *tp,
                              u32 message_id,
                              u8 timer_intmiti_val)
{
        switch (tp->HwSuppIntMitiVer) {
        case 4:
                if (message_id < R8125_MAX_RX_QUEUES_VEC_V3) //ROK
                        RTL_W8(tp,INT_MITI_V2_0_RX + 8 * message_id, timer_intmiti_val);
                else if (message_id == 16) //TOK
                        RTL_W8(tp,INT_MITI_V2_0_TX, timer_intmiti_val);
                else if (message_id == 18) //TOK
                        RTL_W8(tp,INT_MITI_V2_1_TX, timer_intmiti_val);
                break;
        }
}

void
rtl8125_hw_reset(struct net_device *dev)
{
        struct rtl8125_private *tp = netdev_priv(dev);

        rtl8125_lib_reset_prepare(tp);

        /* Disable interrupts */
        rtl8125_irq_mask_and_ack(tp);

        rtl8125_hw_clear_timer_int(dev);

        rtl8125_nic_reset(dev);
}

static unsigned int
rtl8125_xmii_reset_pending(struct net_device *dev)
{
        struct rtl8125_private *tp = netdev_priv(dev);
        unsigned int retval;

        rtl8125_mdio_write(tp, 0x1f, 0x0000);
        retval = rtl8125_mdio_read(tp, MII_BMCR) & BMCR_RESET;

        return retval;
}

static unsigned int
rtl8125_xmii_link_ok(struct net_device *dev)
{
        struct rtl8125_private *tp = netdev_priv(dev);
        unsigned int retval;

        retval = (RTL_R16(tp, PHYstatus) & LinkStatus) ? 1 : 0;

        return retval;
}

static int
rtl8125_wait_phy_reset_complete(struct rtl8125_private *tp)
{
        int i, val;

        for (i = 0; i < 2500; i++) {
                val = rtl8125_mdio_read(tp, MII_BMCR) & BMCR_RESET;
                if (!val)
                        return 0;

                mdelay(1);
        }

        return -1;
}

static void
rtl8125_xmii_reset_enable(struct net_device *dev)
{
        struct rtl8125_private *tp = netdev_priv(dev);

        if (rtl8125_is_in_phy_disable_mode(dev)) {
                return;
        }

        rtl8125_mdio_write(tp, 0x1f, 0x0000);
        rtl8125_mdio_write(tp, MII_ADVERTISE, rtl8125_mdio_read(tp, MII_ADVERTISE) &
                           ~(ADVERTISE_10HALF | ADVERTISE_10FULL |
                             ADVERTISE_100HALF | ADVERTISE_100FULL));
        rtl8125_mdio_write(tp, MII_CTRL1000, rtl8125_mdio_read(tp, MII_CTRL1000) &
                           ~(ADVERTISE_1000HALF | ADVERTISE_1000FULL));
        mdio_direct_write_phy_ocp(tp, 0xA5D4, mdio_direct_read_phy_ocp(tp, 0xA5D4) & ~(RTK_ADVERTISE_2500FULL));
        rtl8125_mdio_write(tp, MII_BMCR, BMCR_RESET | BMCR_ANENABLE);

        if (rtl8125_wait_phy_reset_complete(tp) == 0) return;

        if (netif_msg_link(tp))
                printk(KERN_ERR "%s: PHY reset failed.\n", dev->name);
}

void
rtl8125_init_ring_indexes(struct rtl8125_private *tp)
{
        int i;

        for (i = 0; i < tp->num_tx_rings; i++) {
                struct rtl8125_tx_ring *ring = &tp->tx_ring[i];
                ring->dirty_tx = ring->cur_tx = 0;
                ring->NextHwDesCloPtr = 0;
                ring->BeginHwDesCloPtr = 0;
                ring->index = i;
                ring->priv = tp;
        }

        for (i = 0; i < tp->num_rx_rings; i++) {
                struct rtl8125_rx_ring *ring = &tp->rx_ring[i];
                ring->dirty_rx = ring->cur_rx = 0;
                ring->index = i;
                ring->priv = tp;
        }

#ifdef ENABLE_LIB_SUPPORT
        for (i = 0; i < tp->HwSuppNumTxQueues; i++) {
                struct rtl8125_ring *ring = &tp->lib_tx_ring[i];
                ring->direction = RTL8125_CH_DIR_TX;
                ring->queue_num = i;
                ring->private = tp;
        }

        for (i = 0; i < tp->HwSuppNumRxQueues; i++) {
                struct rtl8125_ring *ring = &tp->lib_rx_ring[i];
                ring->direction = RTL8125_CH_DIR_RX;
                ring->queue_num = i;
                ring->private = tp;
        }
#endif
}

static void
rtl8125_issue_offset_99_event(struct rtl8125_private *tp)
{
        switch (tp->mcfg) {
        case CFG_METHOD_2:
        case CFG_METHOD_3:
        case CFG_METHOD_4:
        case CFG_METHOD_5:
                rtl8125_mac_ocp_write(tp, 0xE09A,  rtl8125_mac_ocp_read(tp, 0xE09A) | BIT_0);
                break;
        }
}

#ifdef ENABLE_DASH_SUPPORT
static void
NICChkTypeEnableDashInterrupt(struct rtl8125_private *tp)
{
        if (tp->DASH) {
                //
                // even disconnected, enable 3 dash interrupt mask bits for in-band/out-band communication
                //
                if (HW_DASH_SUPPORT_TYPE_2(tp) || HW_DASH_SUPPORT_TYPE_3(tp)) {
                        rtl8125_enable_dash2_interrupt(tp);
                        RTL_W16(tp, IntrMask, (ISRIMR_DASH_INTR_EN | ISRIMR_DASH_INTR_CMAC_RESET));
                }
        }
}
#endif

static int rtl8125_enable_eee_plus(struct rtl8125_private *tp)
{
        int ret;

        ret = 0;
        switch (tp->mcfg) {
        case CFG_METHOD_2:
        case CFG_METHOD_3:
        case CFG_METHOD_4:
        case CFG_METHOD_5:
                rtl8125_mac_ocp_write(tp, 0xE080, rtl8125_mac_ocp_read(tp, 0xE080)|BIT_1);
                break;

        default:
//      dev_printk(KERN_DEBUG, tp_to_dev(tp), "Not Support EEEPlus\n");
                ret = -EOPNOTSUPP;
                break;
        }

        return ret;
}

static int rtl8125_disable_eee_plus(struct rtl8125_private *tp)
{
        int ret;

        ret = 0;
        switch (tp->mcfg) {
        case CFG_METHOD_2:
        case CFG_METHOD_3:
        case CFG_METHOD_4:
        case CFG_METHOD_5:
                rtl8125_mac_ocp_write(tp, 0xE080, rtl8125_mac_ocp_read(tp, 0xE080)&~BIT_1);
                break;

        default:
//      dev_printk(KERN_DEBUG, tp_to_dev(tp), "Not Support EEEPlus\n");
                ret = -EOPNOTSUPP;
                break;
        }

        return ret;
}

static void
rtl8125_wakeup_all_tx_queue(struct net_device *dev)
{
        struct rtl8125_private *tp = netdev_priv(dev);
        int i;

        for (i=0; i<tp->num_tx_rings; i++)
                netif_start_subqueue(dev, i);
}

static void
rtl8125_stop_all_tx_queue(struct net_device *dev)
{
        struct rtl8125_private *tp = netdev_priv(dev);
        int i;

        for (i=0; i<tp->num_tx_rings; i++)
                netif_stop_subqueue(dev, i);
}

static void
rtl8125_link_on_patch(struct net_device *dev)
{
        struct rtl8125_private *tp = netdev_priv(dev);

        rtl8125_hw_config(dev);

        if ((tp->mcfg == CFG_METHOD_2) &&
            netif_running(dev)) {
                if (RTL_R16(tp, PHYstatus)&FullDup)
                        RTL_W32(tp, TxConfig, (RTL_R32(tp, TxConfig) | (BIT_24 | BIT_25)) & ~BIT_19);
                else
                        RTL_W32(tp, TxConfig, (RTL_R32(tp, TxConfig) | BIT_25) & ~(BIT_19 | BIT_24));
        }

        if ((tp->mcfg == CFG_METHOD_2 ||
             tp->mcfg == CFG_METHOD_3 ||
             tp->mcfg == CFG_METHOD_4 ||
             tp->mcfg == CFG_METHOD_5) &&
            (RTL_R8(tp, PHYstatus) & _10bps))
                rtl8125_enable_eee_plus(tp);

        rtl8125_hw_start(dev);

        netif_carrier_on(dev);

        rtl8125_wakeup_all_tx_queue(dev);
}

static void
rtl8125_link_down_patch(struct net_device *dev)
{
        struct rtl8125_private *tp = netdev_priv(dev);

        if (tp->mcfg == CFG_METHOD_2 ||
            tp->mcfg == CFG_METHOD_3 ||
            tp->mcfg == CFG_METHOD_4 ||
            tp->mcfg == CFG_METHOD_5)
                rtl8125_disable_eee_plus(tp);

        rtl8125_stop_all_tx_queue(dev);

        netif_carrier_off(dev);

        rtl8125_hw_reset(dev);

        rtl8125_tx_clear(tp);

        rtl8125_rx_clear(tp);

        rtl8125_init_ring(dev);

        rtl8125_enable_hw_linkchg_interrupt(tp);

        //rtl8125_set_speed(dev, tp->autoneg, tp->speed, tp->duplex, tp->advertising);

#ifdef ENABLE_DASH_SUPPORT
        if (tp->DASH) {
                NICChkTypeEnableDashInterrupt(tp);
        }
#endif
}

static void
_rtl8125_check_link_status(struct net_device *dev)
{
        struct rtl8125_private *tp = netdev_priv(dev);

        if (tp->link_ok(dev)) {
                rtl8125_link_on_patch(dev);

                if (netif_msg_ifup(tp))
                        printk(KERN_INFO PFX "%s: link up\n", dev->name);
        } else {
                if (netif_msg_ifdown(tp))
                        printk(KERN_INFO PFX "%s: link down\n", dev->name);

                rtl8125_link_down_patch(dev);
        }
}

static void
rtl8125_check_link_status(struct net_device *dev)
{
        struct rtl8125_private *tp = netdev_priv(dev);

        _rtl8125_check_link_status(dev);

        tp->resume_not_chg_speed = 0;
}

static void
rtl8125_link_option(u8 *aut,
                    u32 *spd,
                    u8 *dup,
                    u32 *adv)
{
        if ((*spd != SPEED_2500) && (*spd != SPEED_1000) &&
            (*spd != SPEED_100) && (*spd != SPEED_10))
                *spd = SPEED_2500;

        if ((*dup != DUPLEX_FULL) && (*dup != DUPLEX_HALF))
                *dup = DUPLEX_FULL;

        if ((*aut != AUTONEG_ENABLE) && (*aut != AUTONEG_DISABLE))
                *aut = AUTONEG_ENABLE;

        *adv &= (ADVERTISED_10baseT_Half |
                 ADVERTISED_10baseT_Full |
                 ADVERTISED_100baseT_Half |
                 ADVERTISED_100baseT_Full |
                 ADVERTISED_1000baseT_Half |
                 ADVERTISED_1000baseT_Full |
                 ADVERTISED_2500baseX_Full);
        if (*adv == 0)
                *adv = (ADVERTISED_10baseT_Half |
                        ADVERTISED_10baseT_Full |
                        ADVERTISED_100baseT_Half |
                        ADVERTISED_100baseT_Full |
                        ADVERTISED_1000baseT_Half |
                        ADVERTISED_1000baseT_Full |
                        ADVERTISED_2500baseX_Full);
}

/*
static void
rtl8125_enable_ocp_phy_power_saving(struct net_device *dev)
{
        struct rtl8125_private *tp = netdev_priv(dev);
        u16 val;

         if (tp->mcfg == CFG_METHOD_2 ||
             tp->mcfg == CFG_METHOD_3 ||
             tp->mcfg == CFG_METHOD_4 ||
			 tp->mcfg == CFG_METHOD_5) {
                val = mdio_direct_read_phy_ocp(tp, 0xC416);
                if (val != 0x0050) {
                        rtl8125_set_phy_mcu_patch_request(tp);
                        mdio_direct_write_phy_ocp(tp, 0xC416, 0x0000);
                        mdio_direct_write_phy_ocp(tp, 0xC416, 0x0050);
                        rtl8125_clear_phy_mcu_patch_request(tp);
                }
        }
}
*/

static void
rtl8125_disable_ocp_phy_power_saving(struct net_device *dev)
{
        struct rtl8125_private *tp = netdev_priv(dev);
        u16 val;

        if (tp->mcfg == CFG_METHOD_2 ||
            tp->mcfg == CFG_METHOD_3 ||
            tp->mcfg == CFG_METHOD_4 ||
            tp->mcfg == CFG_METHOD_5) {
                val = mdio_direct_read_phy_ocp(tp, 0xC416);
                if (val != 0x0500) {
                        rtl8125_set_phy_mcu_patch_request(tp);
                        mdio_direct_write_phy_ocp(tp, 0xC416, 0x0000);
                        mdio_direct_write_phy_ocp(tp, 0xC416, 0x0500);
                        rtl8125_clear_phy_mcu_patch_request(tp);
                }
        }
}

static void
rtl8125_wait_ll_share_fifo_ready(struct net_device *dev)
{
        struct rtl8125_private *tp = netdev_priv(dev);
        int i;

        for (i = 0; i < 10; i++) {
                udelay(100);
                if (RTL_R16(tp, 0xD2) & BIT_9)
                        break;
        }
}

static void
rtl8125_disable_pci_offset_99(struct rtl8125_private *tp)
{
        switch (tp->mcfg) {
        case CFG_METHOD_2:
        case CFG_METHOD_3:
        case CFG_METHOD_4:
        case CFG_METHOD_5:
                rtl8125_mac_ocp_write(tp, 0xE032,  rtl8125_mac_ocp_read(tp, 0xE032) & ~(BIT_0 | BIT_1));
                break;
        }

        switch (tp->mcfg) {
        case CFG_METHOD_2:
        case CFG_METHOD_3:
        case CFG_METHOD_4:
        case CFG_METHOD_5:
                rtl8125_csi_fun0_write_byte(tp, 0x99, 0x00);
                break;
        }
}

static void
rtl8125_enable_pci_offset_99(struct rtl8125_private *tp)
{
        u32 csi_tmp;

        switch (tp->mcfg) {
        case CFG_METHOD_2:
        case CFG_METHOD_3:
        case CFG_METHOD_4:
        case CFG_METHOD_5:
                rtl8125_csi_fun0_write_byte(tp, 0x99, tp->org_pci_offset_99);
                break;
        }

        switch (tp->mcfg) {
        case CFG_METHOD_2:
        case CFG_METHOD_3:
        case CFG_METHOD_4:
        case CFG_METHOD_5:
                csi_tmp = rtl8125_mac_ocp_read(tp, 0xE032);
                csi_tmp &= ~(BIT_0 | BIT_1);
                if (!(tp->org_pci_offset_99 & (BIT_5 | BIT_6)))
                        csi_tmp |= BIT_1;
                if (!(tp->org_pci_offset_99 & BIT_2))
                        csi_tmp |= BIT_0;
                rtl8125_mac_ocp_write(tp, 0xE032, csi_tmp);
                break;
        }
}

static void
rtl8125_init_pci_offset_99(struct rtl8125_private *tp)
{
        u32 csi_tmp;

        switch (tp->mcfg) {
        case CFG_METHOD_2:
        case CFG_METHOD_3:
        case CFG_METHOD_4:
        case CFG_METHOD_5:
                rtl8125_mac_ocp_write(tp, 0xCDD0, 0x9003);
                csi_tmp = rtl8125_mac_ocp_read(tp, 0xE034);
                csi_tmp |= (BIT_15 | BIT_14);
                rtl8125_mac_ocp_write(tp, 0xE034, csi_tmp);
                rtl8125_mac_ocp_write(tp, 0xCDD2, 0x889C);
                rtl8125_mac_ocp_write(tp, 0xCDD8, 0x9003);
                rtl8125_mac_ocp_write(tp, 0xCDD4, 0x8C30);
                rtl8125_mac_ocp_write(tp, 0xCDDA, 0x9003);
                rtl8125_mac_ocp_write(tp, 0xCDD6, 0x9003);
                rtl8125_mac_ocp_write(tp, 0xCDDC, 0x9003);
                rtl8125_mac_ocp_write(tp, 0xCDE8, 0x883E);
                rtl8125_mac_ocp_write(tp, 0xCDEA, 0x9003);
                rtl8125_mac_ocp_write(tp, 0xCDEC, 0x889C);
                rtl8125_mac_ocp_write(tp, 0xCDEE, 0x9003);
                rtl8125_mac_ocp_write(tp, 0xCDF0, 0x8C09);
                rtl8125_mac_ocp_write(tp, 0xCDF2, 0x9003);
                csi_tmp = rtl8125_mac_ocp_read(tp, 0xE032);
                csi_tmp |= (BIT_14);
                rtl8125_mac_ocp_write(tp, 0xE032, csi_tmp);
                csi_tmp = rtl8125_mac_ocp_read(tp, 0xE0A2);
                csi_tmp |= (BIT_0);
                rtl8125_mac_ocp_write(tp, 0xE0A2, csi_tmp);
                break;
        }

        rtl8125_enable_pci_offset_99(tp);
}

static void
rtl8125_disable_pci_offset_180(struct rtl8125_private *tp)
{
        u32 csi_tmp;

        switch (tp->mcfg) {
        case CFG_METHOD_2:
        case CFG_METHOD_3:
        case CFG_METHOD_4:
        case CFG_METHOD_5:
                csi_tmp = rtl8125_mac_ocp_read(tp, 0xE092);
                csi_tmp &= 0xFF00;
                rtl8125_mac_ocp_write(tp, 0xE092, csi_tmp);
                break;
        }
}

static void
rtl8125_enable_pci_offset_180(struct rtl8125_private *tp)
{
        u32 csi_tmp;

        switch (tp->mcfg) {
        case CFG_METHOD_2:
        case CFG_METHOD_3:
        case CFG_METHOD_4:
        case CFG_METHOD_5:
                csi_tmp = rtl8125_mac_ocp_read(tp, 0xE094);
                csi_tmp &= 0x00FF;
                rtl8125_mac_ocp_write(tp, 0xE094, csi_tmp);
                break;
        }

        switch (tp->mcfg) {
        case CFG_METHOD_2:
        case CFG_METHOD_3:
        case CFG_METHOD_4:
        case CFG_METHOD_5:
                csi_tmp = rtl8125_mac_ocp_read(tp, 0xE092);
                csi_tmp &= 0xFF00;
                csi_tmp |= BIT_2;
                rtl8125_mac_ocp_write(tp, 0xE092, csi_tmp);
                break;
        }
}

static void
rtl8125_init_pci_offset_180(struct rtl8125_private *tp)
{
        if (tp->org_pci_offset_180 & (BIT_0|BIT_1))
                rtl8125_enable_pci_offset_180(tp);
        else
                rtl8125_disable_pci_offset_180(tp);
}

static void
rtl8125_set_pci_99_180_exit_driver_para(struct net_device *dev)
{
        struct rtl8125_private *tp = netdev_priv(dev);

        switch (tp->mcfg) {
        case CFG_METHOD_2:
        case CFG_METHOD_3:
        case CFG_METHOD_4:
        case CFG_METHOD_5:
                rtl8125_issue_offset_99_event(tp);
                break;
        }

        switch (tp->mcfg) {
        case CFG_METHOD_2:
        case CFG_METHOD_3:
        case CFG_METHOD_4:
        case CFG_METHOD_5:
                rtl8125_disable_pci_offset_99(tp);
                break;
        }
        switch (tp->mcfg) {
        case CFG_METHOD_2:
        case CFG_METHOD_3:
        case CFG_METHOD_4:
        case CFG_METHOD_5:
                rtl8125_disable_pci_offset_180(tp);
                break;
        }
}

static void
rtl8125_enable_cfg9346_write(struct rtl8125_private *tp)
{
        RTL_W8(tp, Cfg9346, RTL_R8(tp, Cfg9346) | Cfg9346_Unlock);
}

static void
rtl8125_disable_cfg9346_write(struct rtl8125_private *tp)
{
        RTL_W8(tp, Cfg9346, RTL_R8(tp, Cfg9346) & ~Cfg9346_Unlock);
}

static void
rtl8125_enable_exit_l1_mask(struct rtl8125_private *tp)
{
        //(1)ERI(0xD4)(OCP 0xC0AC).bit[7:12]=6'b111111, L1 Mask
        SetMcuAccessRegBit(tp, 0xC0AC, (BIT_7 | BIT_8 | BIT_9 | BIT_10 | BIT_11 | BIT_12));
}

static void
rtl8125_disable_exit_l1_mask(struct rtl8125_private *tp)
{
        //(1)ERI(0xD4)(OCP 0xC0AC).bit[7:12]=6'b000000, L1 Mask
        ClearMcuAccessRegBit(tp, 0xC0AC, (BIT_7 | BIT_8 | BIT_9 | BIT_10 | BIT_11 | BIT_12));
}

static void
rtl8125_hw_d3_para(struct net_device *dev)
{
        struct rtl8125_private *tp = netdev_priv(dev);

        RTL_W16(tp, RxMaxSize, RX_BUF_SIZE);

        switch (tp->mcfg) {
        case CFG_METHOD_2:
        case CFG_METHOD_3:
        case CFG_METHOD_4:
        case CFG_METHOD_5:
                RTL_W8(tp, 0xF1, RTL_R8(tp, 0xF1) & ~BIT_7);
                rtl8125_enable_cfg9346_write(tp);
                RTL_W8(tp, Config2, RTL_R8(tp, Config2) & ~BIT_7);
                RTL_W8(tp, Config5, RTL_R8(tp, Config5) & ~BIT_0);
                rtl8125_disable_cfg9346_write(tp);
                break;
        }

        rtl8125_disable_exit_l1_mask(tp);

#ifdef ENABLE_REALWOW_SUPPORT
        rtl8125_set_realwow_d3_para(dev);
#endif

        switch (tp->mcfg) {
        case CFG_METHOD_2:
        case CFG_METHOD_3:
        case CFG_METHOD_4:
        case CFG_METHOD_5:
                rtl8125_mac_ocp_write(tp, 0xEA18, 0x0064);
                break;
        }

        rtl8125_set_pci_99_180_exit_driver_para(dev);

        /*disable ocp phy power saving*/
        if (tp->mcfg == CFG_METHOD_2 ||
            tp->mcfg == CFG_METHOD_3 ||
            tp->mcfg == CFG_METHOD_4 ||
            tp->mcfg == CFG_METHOD_5)
                rtl8125_disable_ocp_phy_power_saving(dev);

        rtl8125_disable_rxdvgate(dev);
}

static void
rtl8125_enable_magic_packet(struct net_device *dev)
{
        struct rtl8125_private *tp = netdev_priv(dev);

        switch (tp->HwSuppMagicPktVer) {
        case WAKEUP_MAGIC_PACKET_V3:
                rtl8125_mac_ocp_write(tp, 0xC0B6, rtl8125_mac_ocp_read(tp, 0xC0B6) | BIT_0);
                break;
        }
}
static void
rtl8125_disable_magic_packet(struct net_device *dev)
{
        struct rtl8125_private *tp = netdev_priv(dev);

        switch (tp->HwSuppMagicPktVer) {
        case WAKEUP_MAGIC_PACKET_V3:
                rtl8125_mac_ocp_write(tp, 0xC0B6, rtl8125_mac_ocp_read(tp, 0xC0B6) & ~BIT_0);
                break;
        }
}

static void
rtl8125_enable_linkchg_wakeup(struct net_device *dev)
{
        struct rtl8125_private *tp = netdev_priv(dev);

        switch (tp->HwSuppLinkChgWakeUpVer) {
        case 3:
                RTL_W8(tp, Config3, RTL_R8(tp, Config3) | LinkUp);
                ClearAndSetMcuAccessRegBit(tp, 0xE0C6,  (BIT_5 | BIT_3 | BIT_2),  (BIT_4 | BIT_1 | BIT_0));
                break;
        }
}

static void
rtl8125_disable_linkchg_wakeup(struct net_device *dev)
{
        struct rtl8125_private *tp = netdev_priv(dev);

        switch (tp->HwSuppLinkChgWakeUpVer) {
        case 3:
                RTL_W8(tp, Config3, RTL_R8(tp, Config3) & ~LinkUp);
                ClearMcuAccessRegBit(tp, 0xE0C6,  (BIT_5 | BIT_4 | BIT_3 | BIT_2 | BIT_1 | BIT_0));
                break;
        }
}

#define WAKE_ANY (WAKE_PHY | WAKE_MAGIC | WAKE_UCAST | WAKE_BCAST | WAKE_MCAST)

static u32
rtl8125_get_hw_wol(struct rtl8125_private *tp)
{
        u8 options;
        u32 csi_tmp;
        u32 wol_opts = 0;

        options = RTL_R8(tp, Config1);
        if (!(options & PMEnable))
                goto out;

        options = RTL_R8(tp, Config3);
        if (options & LinkUp)
                wol_opts |= WAKE_PHY;

        switch (tp->HwSuppMagicPktVer) {
        case WAKEUP_MAGIC_PACKET_V3:
                csi_tmp = rtl8125_mac_ocp_read(tp, 0xC0B6);
                if (csi_tmp & BIT_0)
                        wol_opts |= WAKE_MAGIC;
                break;
        }

        options = RTL_R8(tp, Config5);
        if (options & UWF)
                wol_opts |= WAKE_UCAST;
        if (options & BWF)
                wol_opts |= WAKE_BCAST;
        if (options & MWF)
                wol_opts |= WAKE_MCAST;

out:
        return wol_opts;
}

static void
rtl8125_enable_d0_speedup(struct rtl8125_private *tp)
{
        if (FALSE == HW_SUPPORT_D0_SPEED_UP(tp)) return;
        if (tp->D0SpeedUpSpeed == D0_SPEED_UP_SPEED_DISABLE) return;

        if (tp->HwSuppD0SpeedUpVer == 1) {
                u16 mac_ocp_data;

                RTL_W8(tp, 0xD0, RTL_R8(tp, 0xD0) | BIT_3);

                //speed up speed
                mac_ocp_data = rtl8125_mac_ocp_read(tp, 0xE10A);
                mac_ocp_data &= ~(BIT_10 | BIT_9 | BIT_8 | BIT_7);
                if (tp->D0SpeedUpSpeed == D0_SPEED_UP_SPEED_2500) {
                        mac_ocp_data |= BIT_7;
                }
                rtl8125_mac_ocp_write(tp, 0xE10A, mac_ocp_data);

                //speed up flowcontrol
                mac_ocp_data = rtl8125_mac_ocp_read(tp, 0xE860);
                mac_ocp_data |= (BIT_15 | BIT_14);
                rtl8125_mac_ocp_write(tp, 0xE860, mac_ocp_data);
        }
}

static void
rtl8125_disable_d0_speedup(struct rtl8125_private *tp)
{
        if (FALSE == HW_SUPPORT_D0_SPEED_UP(tp)) return;

        if (tp->HwSuppD0SpeedUpVer == 1)
                RTL_W8(tp, 0xD0, RTL_R8(tp, 0xD0) & ~BIT_7);
}

static void
rtl8125_set_hw_wol(struct net_device *dev, u32 wolopts)
{
        struct rtl8125_private *tp = netdev_priv(dev);
        int i,tmp;
        static struct {
                u32 opt;
                u16 reg;
                u8  mask;
        } cfg[] = {
                { WAKE_PHY,   Config3, LinkUp },
                { WAKE_UCAST, Config5, UWF },
                { WAKE_BCAST, Config5, BWF },
                { WAKE_MCAST, Config5, MWF },
                { WAKE_ANY,   Config5, LanWake },
                { WAKE_MAGIC, Config3, MagicPacket },
        };

        switch (tp->HwSuppMagicPktVer) {
        case WAKEUP_MAGIC_PACKET_V3:
        default:
                tmp = ARRAY_SIZE(cfg) - 1;

                if (wolopts & WAKE_MAGIC)
                        rtl8125_enable_magic_packet(dev);
                else
                        rtl8125_disable_magic_packet(dev);
                break;
        }

        rtl8125_enable_cfg9346_write(tp);

        for (i = 0; i < tmp; i++) {
                u8 options = RTL_R8(tp, cfg[i].reg) & ~cfg[i].mask;
                if (wolopts & cfg[i].opt)
                        options |= cfg[i].mask;
                RTL_W8(tp, cfg[i].reg, options);
        }

        switch (tp->HwSuppLinkChgWakeUpVer) {
        case 3:
                if (wolopts & WAKE_PHY)
                        rtl8125_enable_linkchg_wakeup(dev);
                else
                        rtl8125_disable_linkchg_wakeup(dev);
                break;
        }

        rtl8125_disable_cfg9346_write(tp);
}

static void
rtl8125_phy_restart_nway(struct net_device *dev)
{
        struct rtl8125_private *tp = netdev_priv(dev);

        if (rtl8125_is_in_phy_disable_mode(dev)) return;

        rtl8125_mdio_write(tp, 0x1F, 0x0000);
        rtl8125_mdio_write(tp, MII_BMCR, BMCR_ANENABLE | BMCR_ANRESTART);
}

static void
rtl8125_phy_setup_force_mode(struct net_device *dev, u32 speed, u8 duplex)
{
        struct rtl8125_private *tp = netdev_priv(dev);
        u16 bmcr_true_force = 0;

        if (rtl8125_is_in_phy_disable_mode(dev)) return;

        if ((speed == SPEED_10) && (duplex == DUPLEX_HALF)) {
                bmcr_true_force = BMCR_SPEED10;
        } else if ((speed == SPEED_10) && (duplex == DUPLEX_FULL)) {
                bmcr_true_force = BMCR_SPEED10 | BMCR_FULLDPLX;
        } else if ((speed == SPEED_100) && (duplex == DUPLEX_HALF)) {
                bmcr_true_force = BMCR_SPEED100;
        } else if ((speed == SPEED_100) && (duplex == DUPLEX_FULL)) {
                bmcr_true_force = BMCR_SPEED100 | BMCR_FULLDPLX;
        } else {
                netif_err(tp, drv, dev, "Failed to set phy force mode!\n");
                return;
        }

        rtl8125_mdio_write(tp, 0x1F, 0x0000);
        rtl8125_mdio_write(tp, MII_BMCR, bmcr_true_force);
}

static void
rtl8125_set_pci_pme(struct rtl8125_private *tp, int set)
{
        struct pci_dev *pdev = tp->pci_dev;
        u16 pmc;

        if (!pdev->pm_cap)
                return;

        pci_read_config_word(pdev, pdev->pm_cap + PCI_PM_CTRL, &pmc);
        pmc |= PCI_PM_CTRL_PME_STATUS;
        if (set)
                pmc |= PCI_PM_CTRL_PME_ENABLE;
        else
                pmc &= ~PCI_PM_CTRL_PME_ENABLE;
        pci_write_config_word(pdev, pdev->pm_cap + PCI_PM_CTRL, pmc);
}

static void
rtl8125_set_wol_link_speed(struct net_device *dev)
{
        struct rtl8125_private *tp = netdev_priv(dev);
        int auto_nego;
        int giga_ctrl;
        int ctrl_2500;
        u32 adv;
        u16 anlpar;
        u16 gbsr;
        u16 status_2500;
        u16 aner;

        if (!tp->link_ok(dev) || tp->autoneg != AUTONEG_ENABLE)
                goto exit;

        rtl8125_mdio_write(tp, 0x1F, 0x0000);
        aner = rtl8125_mdio_read(tp, MII_EXPANSION);
        if (!(aner & EXPANSION_NWAY)) goto exit;

        auto_nego = rtl8125_mdio_read(tp, MII_ADVERTISE);
        auto_nego &= ~(ADVERTISE_10HALF | ADVERTISE_10FULL
                       | ADVERTISE_100HALF | ADVERTISE_100FULL);

        giga_ctrl = rtl8125_mdio_read(tp, MII_CTRL1000);
        giga_ctrl &= ~(ADVERTISE_1000HALF | ADVERTISE_1000FULL);

        ctrl_2500 = mdio_direct_read_phy_ocp(tp, 0xA5D4);
        ctrl_2500 &= ~(RTK_ADVERTISE_2500FULL);

        anlpar = rtl8125_mdio_read(tp, MII_LPA);
        gbsr = rtl8125_mdio_read(tp, MII_STAT1000);
        status_2500 = mdio_direct_read_phy_ocp(tp, 0xA5D6);

        adv = tp->advertising;
        if ((adv & ADVERTISED_10baseT_Half) && (anlpar & LPA_10HALF))
                auto_nego |= ADVERTISE_10HALF;
        else if ((adv & ADVERTISED_10baseT_Full) && (anlpar & LPA_10FULL))
                auto_nego |= ADVERTISE_10FULL;
        else if ((adv & ADVERTISED_100baseT_Half) && (anlpar & LPA_100HALF))
                auto_nego |= ADVERTISE_100HALF;
        else if ((adv & ADVERTISED_100baseT_Full) && (anlpar & LPA_100FULL))
                auto_nego |= ADVERTISE_100FULL;
        else if (adv & ADVERTISED_1000baseT_Half && (gbsr & LPA_1000HALF))
                giga_ctrl |= ADVERTISE_1000HALF;
        else if (adv & ADVERTISED_1000baseT_Full && (gbsr & LPA_1000FULL))
                giga_ctrl |= ADVERTISE_1000FULL;
        else if (adv & ADVERTISED_2500baseX_Full && (status_2500 & RTK_LPA_ADVERTISE_2500FULL))
                ctrl_2500 |= RTK_ADVERTISE_2500FULL;
        else
                goto exit;

        if (tp->DASH)
                auto_nego |= (ADVERTISE_100FULL | ADVERTISE_100HALF | ADVERTISE_10HALF | ADVERTISE_10FULL);

#ifdef CONFIG_DOWN_SPEED_100
        auto_nego |= (ADVERTISE_100FULL | ADVERTISE_100HALF | ADVERTISE_10HALF | ADVERTISE_10FULL);
#endif

        rtl8125_mdio_write(tp, MII_ADVERTISE, auto_nego);
        rtl8125_mdio_write(tp, MII_CTRL1000, giga_ctrl);
        mdio_direct_write_phy_ocp(tp, 0xA5D4, ctrl_2500);

        rtl8125_phy_restart_nway(dev);

exit:
        return;
}

static bool
rtl8125_keep_wol_link_speed(struct net_device *dev, u8 from_suspend)
{
        struct rtl8125_private *tp = netdev_priv(dev);

        if ((from_suspend && !tp->link_ok(dev)) ||
            (!from_suspend && tp->resume_not_chg_speed))
                return 1;

        return 0;
}
static void
rtl8125_powerdown_pll(struct net_device *dev, u8 from_suspend)
{
        struct rtl8125_private *tp = netdev_priv(dev);

        tp->check_keep_link_speed = 0;
        if (tp->wol_enabled == WOL_ENABLED || tp->DASH || tp->EnableKCPOffload) {
                rtl8125_set_hw_wol(dev, tp->wol_opts);

                if (tp->mcfg == CFG_METHOD_2 ||
                    tp->mcfg == CFG_METHOD_3 ||
                    tp->mcfg == CFG_METHOD_4 ||
                    tp->mcfg == CFG_METHOD_5) {
                        rtl8125_enable_cfg9346_write(tp);
                        RTL_W8(tp, Config2, RTL_R8(tp, Config2) | PMSTS_En);
                        rtl8125_disable_cfg9346_write(tp);
                }

                /* Enable the PME and clear the status */
                rtl8125_set_pci_pme(tp, 1);

                if (rtl8125_keep_wol_link_speed(dev, from_suspend)) {
                        if (tp->wol_opts & WAKE_PHY)
                                tp->check_keep_link_speed = 1;
                } else {
                        if (HW_SUPPORT_D0_SPEED_UP(tp)) {
                                rtl8125_enable_d0_speedup(tp);
                                tp->check_keep_link_speed = 1;
                        }

                        rtl8125_set_wol_link_speed(dev);
                }

                RTL_W32(tp, RxConfig, RTL_R32(tp, RxConfig) | AcceptBroadcast | AcceptMulticast | AcceptMyPhys);

                return;
        }

        if (tp->DASH)
                return;

        rtl8125_phy_power_down(dev);

        if (!tp->HwIcVerUnknown) {
                switch (tp->mcfg) {
                case CFG_METHOD_2:
                case CFG_METHOD_3:
                case CFG_METHOD_4:
                case CFG_METHOD_5:
                        RTL_W8(tp, PMCH, RTL_R8(tp, PMCH) & ~BIT_7);
                        break;
                }
        }

        switch (tp->mcfg) {
        case CFG_METHOD_2:
        case CFG_METHOD_3:
        case CFG_METHOD_4:
        case CFG_METHOD_5:
                RTL_W8(tp, 0xF2, RTL_R8(tp, 0xF2) & ~BIT_6);
                break;
        }
}

static void rtl8125_powerup_pll(struct net_device *dev)
{
        struct rtl8125_private *tp = netdev_priv(dev);

        switch (tp->mcfg) {
        case CFG_METHOD_2:
        case CFG_METHOD_3:
        case CFG_METHOD_4:
        case CFG_METHOD_5:
                RTL_W8(tp, PMCH, RTL_R8(tp, PMCH) | BIT_7 | BIT_6);
                break;
        }

        if (tp->resume_not_chg_speed) return;

        rtl8125_phy_power_up(dev);
}

#if LINUX_VERSION_CODE > KERNEL_VERSION(2,4,22)
static void
rtl8125_get_wol(struct net_device *dev,
                struct ethtool_wolinfo *wol)
{
        struct rtl8125_private *tp = netdev_priv(dev);
        u8 options;
        unsigned long flags;

        wol->wolopts = 0;

        if (tp->mcfg == CFG_METHOD_DEFAULT) {
                wol->supported = 0;
                return;
        } else {
                wol->supported = WAKE_ANY;
        }

        spin_lock_irqsave(&tp->lock, flags);

        options = RTL_R8(tp, Config1);
        if (!(options & PMEnable))
                goto out_unlock;

        wol->wolopts = tp->wol_opts;

out_unlock:
        spin_unlock_irqrestore(&tp->lock, flags);
}

static int
rtl8125_set_wol(struct net_device *dev,
                struct ethtool_wolinfo *wol)
{
        struct rtl8125_private *tp = netdev_priv(dev);
        unsigned long flags;

        if (tp->mcfg == CFG_METHOD_DEFAULT)
                return -EOPNOTSUPP;

        spin_lock_irqsave(&tp->lock, flags);

        tp->wol_opts = wol->wolopts;

        tp->wol_enabled = (tp->wol_opts) ? WOL_ENABLED : WOL_DISABLED;

        spin_unlock_irqrestore(&tp->lock, flags);

        device_set_wakeup_enable(tp_to_dev(tp), wol->wolopts);

        return 0;
}

static void
rtl8125_get_drvinfo(struct net_device *dev,
                    struct ethtool_drvinfo *info)
{
        struct rtl8125_private *tp = netdev_priv(dev);
        struct rtl8125_fw *rtl_fw = tp->rtl_fw;

        strcpy(info->driver, MODULENAME);
        strcpy(info->version, RTL8125_VERSION);
        strcpy(info->bus_info, pci_name(tp->pci_dev));
        info->regdump_len = R8125_REGS_DUMP_SIZE;
        info->eedump_len = tp->eeprom_len;
        BUILD_BUG_ON(sizeof(info->fw_version) < sizeof(rtl_fw->version));
        if (rtl_fw)
                strlcpy(info->fw_version, rtl_fw->version,
                        sizeof(info->fw_version));
}

static int
rtl8125_get_regs_len(struct net_device *dev)
{
        return R8125_REGS_DUMP_SIZE;
}
#endif //LINUX_VERSION_CODE > KERNEL_VERSION(2,4,22)

static void
rtl8125_set_d0_speedup_speed(struct rtl8125_private *tp)
{
        if (FALSE == HW_SUPPORT_D0_SPEED_UP(tp)) return;

        tp->D0SpeedUpSpeed = D0_SPEED_UP_SPEED_DISABLE;
        if (tp->autoneg == AUTONEG_ENABLE) {
                if (tp->speed == SPEED_2500)
                        tp->D0SpeedUpSpeed = D0_SPEED_UP_SPEED_2500;
                else if(tp->speed == SPEED_1000)
                        tp->D0SpeedUpSpeed = D0_SPEED_UP_SPEED_1000;
        }
}

static int
rtl8125_set_speed_xmii(struct net_device *dev,
                       u8 autoneg,
                       u32 speed,
                       u8 duplex,
                       u32 adv)
{
        struct rtl8125_private *tp = netdev_priv(dev);
        int auto_nego = 0;
        int giga_ctrl = 0;
        int ctrl_2500 = 0;
        int rc = -EINVAL;

        //Disable Giga Lite
        ClearEthPhyOcpBit(tp, 0xA428, BIT_9);
        ClearEthPhyOcpBit(tp, 0xA5EA, BIT_0);

        if (speed != SPEED_2500 &&
            (speed != SPEED_1000) &&
            (speed != SPEED_100) &&
            (speed != SPEED_10)) {
                speed = SPEED_2500;
                duplex = DUPLEX_FULL;
        }

        giga_ctrl = rtl8125_mdio_read(tp, MII_CTRL1000);
        giga_ctrl &= ~(ADVERTISE_1000HALF | ADVERTISE_1000FULL);
        ctrl_2500 = mdio_direct_read_phy_ocp(tp, 0xA5D4);
        ctrl_2500 &= ~(RTK_ADVERTISE_2500FULL);

        if (autoneg == AUTONEG_ENABLE) {
                /*n-way force*/
                auto_nego = rtl8125_mdio_read(tp, MII_ADVERTISE);
                auto_nego &= ~(ADVERTISE_10HALF | ADVERTISE_10FULL |
                               ADVERTISE_100HALF | ADVERTISE_100FULL |
                               ADVERTISE_PAUSE_CAP | ADVERTISE_PAUSE_ASYM);

                if (adv & ADVERTISED_10baseT_Half)
                        auto_nego |= ADVERTISE_10HALF;
                if (adv & ADVERTISED_10baseT_Full)
                        auto_nego |= ADVERTISE_10FULL;
                if (adv & ADVERTISED_100baseT_Half)
                        auto_nego |= ADVERTISE_100HALF;
                if (adv & ADVERTISED_100baseT_Full)
                        auto_nego |= ADVERTISE_100FULL;
                if (adv & ADVERTISED_1000baseT_Half)
                        giga_ctrl |= ADVERTISE_1000HALF;
                if (adv & ADVERTISED_1000baseT_Full)
                        giga_ctrl |= ADVERTISE_1000FULL;
                if (adv & ADVERTISED_2500baseX_Full)
                        ctrl_2500 |= RTK_ADVERTISE_2500FULL;

                //flow control
                if (dev->mtu <= ETH_DATA_LEN && tp->fcpause == rtl8125_fc_full)
                        auto_nego |= ADVERTISE_PAUSE_CAP | ADVERTISE_PAUSE_ASYM;

                tp->phy_auto_nego_reg = auto_nego;
                tp->phy_1000_ctrl_reg = giga_ctrl;

                tp->phy_2500_ctrl_reg = ctrl_2500;

                rtl8125_mdio_write(tp, 0x1f, 0x0000);
                rtl8125_mdio_write(tp, MII_ADVERTISE, auto_nego);
                rtl8125_mdio_write(tp, MII_CTRL1000, giga_ctrl);
                mdio_direct_write_phy_ocp(tp, 0xA5D4, ctrl_2500);
                rtl8125_phy_restart_nway(dev);
                mdelay(20);
        } else {
                /*true force*/
                if (speed == SPEED_10 || speed == SPEED_100)
                        rtl8125_phy_setup_force_mode(dev, speed, duplex);
                else
                        goto out;
        }

        tp->autoneg = autoneg;
        tp->speed = speed;
        tp->duplex = duplex;
        tp->advertising = adv;

        rtl8125_set_d0_speedup_speed(tp);

        rc = 0;
out:
        return rc;
}

static int
rtl8125_set_speed(struct net_device *dev,
                  u8 autoneg,
                  u32 speed,
                  u8 duplex,
                  u32 adv)
{
        struct rtl8125_private *tp = netdev_priv(dev);
        int ret;

        if (tp->resume_not_chg_speed) return 0;

        ret = tp->set_speed(dev, autoneg, speed, duplex, adv);

        return ret;
}

#if LINUX_VERSION_CODE > KERNEL_VERSION(2,4,22)
static int
rtl8125_set_settings(struct net_device *dev,
#if LINUX_VERSION_CODE < KERNEL_VERSION(4,6,0)
                     struct ethtool_cmd *cmd
#else
                     const struct ethtool_link_ksettings *cmd
#endif
                    )
{
        struct rtl8125_private *tp = netdev_priv(dev);
        int ret;
        unsigned long flags;
        u8 autoneg;
        u32 speed;
        u8 duplex;
        u32 supported, advertising;

#if LINUX_VERSION_CODE < KERNEL_VERSION(4,6,0)
        autoneg = cmd->autoneg;
        speed = cmd->speed;
        duplex = cmd->duplex;
        supported = cmd->supported;
        advertising = cmd->advertising;
#else
        const struct ethtool_link_settings *base = &cmd->base;
        autoneg = base->autoneg;
        speed = base->speed;
        duplex = base->duplex;
        ethtool_convert_link_mode_to_legacy_u32(&supported,
                                                cmd->link_modes.supported);
        ethtool_convert_link_mode_to_legacy_u32(&advertising,
                                                cmd->link_modes.advertising);
#endif
        if (advertising & ~supported)
                return -EINVAL;

        spin_lock_irqsave(&tp->lock, flags);
        ret = rtl8125_set_speed(dev, autoneg, speed, duplex, advertising);
        spin_unlock_irqrestore(&tp->lock, flags);

        return ret;
}

#if LINUX_VERSION_CODE < KERNEL_VERSION(3,3,0)
static u32
rtl8125_get_tx_csum(struct net_device *dev)
{
        struct rtl8125_private *tp = netdev_priv(dev);
        u32 ret;
        unsigned long flags;

        spin_lock_irqsave(&tp->lock, flags);
#if LINUX_VERSION_CODE < KERNEL_VERSION(3,0,0)
        ret = ((dev->features & NETIF_F_IP_CSUM) != 0);
#else
        ret = ((dev->features & (NETIF_F_IP_CSUM | NETIF_F_IPV6_CSUM)) != 0);
#endif //LINUX_VERSION_CODE < KERNEL_VERSION(3,0,0)
        spin_unlock_irqrestore(&tp->lock, flags);

        return ret;
}

static u32
rtl8125_get_rx_csum(struct net_device *dev)
{
        struct rtl8125_private *tp = netdev_priv(dev);
        u32 ret;
        unsigned long flags;

        spin_lock_irqsave(&tp->lock, flags);
        ret = tp->cp_cmd & RxChkSum;
        spin_unlock_irqrestore(&tp->lock, flags);

        return ret;
}

static int
rtl8125_set_tx_csum(struct net_device *dev,
                    u32 data)
{
        struct rtl8125_private *tp = netdev_priv(dev);
        unsigned long flags;

        if (tp->mcfg == CFG_METHOD_DEFAULT)
                return -EOPNOTSUPP;

        spin_lock_irqsave(&tp->lock, flags);

#if LINUX_VERSION_CODE < KERNEL_VERSION(3,0,0)
        if (data)
                dev->features |= NETIF_F_IP_CSUM;
        else
                dev->features &= ~NETIF_F_IP_CSUM;
#else
        if (data)
                dev->features |= (NETIF_F_IP_CSUM | NETIF_F_IPV6_CSUM);
        else
                dev->features &= ~(NETIF_F_IP_CSUM | NETIF_F_IPV6_CSUM);
#endif //LINUX_VERSION_CODE < KERNEL_VERSION(3,0,0)

        spin_unlock_irqrestore(&tp->lock, flags);

        return 0;
}

static int
rtl8125_set_rx_csum(struct net_device *dev,
                    u32 data)
{
        struct rtl8125_private *tp = netdev_priv(dev);
        unsigned long flags;

        if (tp->mcfg == CFG_METHOD_DEFAULT)
                return -EOPNOTSUPP;

        spin_lock_irqsave(&tp->lock, flags);

        if (data)
                tp->cp_cmd |= RxChkSum;
        else
                tp->cp_cmd &= ~RxChkSum;

        RTL_W16(tp, CPlusCmd, tp->cp_cmd);

        spin_unlock_irqrestore(&tp->lock, flags);

        return 0;
}
#endif //LINUX_VERSION_CODE < KERNEL_VERSION(3,3,0)
#endif //LINUX_VERSION_CODE > KERNEL_VERSION(2,4,22)

static u32
rtl8125_rx_desc_opts1(struct rtl8125_private *tp,
                      struct RxDesc *desc)
{
        if (tp->InitRxDescType == RX_DESC_RING_TYPE_3)
                return ((struct RxDescV3 *)desc)->RxDescNormalDDWord4.opts1;
        else
                return desc->opts1;
}

static u32
rtl8125_rx_desc_opts2(struct rtl8125_private *tp,
                      struct RxDesc *desc)
{
        if (tp->InitRxDescType == RX_DESC_RING_TYPE_3)
                return ((struct RxDescV3 *)desc)->RxDescNormalDDWord4.opts2;
        else
                return desc->opts2;
}

static void
rtl8125_clear_rx_desc_opts2(struct rtl8125_private *tp,
                            struct RxDesc *desc)
{
        if (tp->InitRxDescType == RX_DESC_RING_TYPE_3)
                ((struct RxDescV3 *)desc)->RxDescNormalDDWord4.opts2 = 0;
        else
                desc->opts2 = 0;
}

#ifdef CONFIG_R8125_VLAN

static inline u32
rtl8125_tx_vlan_tag(struct rtl8125_private *tp,
                    struct sk_buff *skb)
{
#if LINUX_VERSION_CODE < KERNEL_VERSION(3,0,0)
        return (tp->vlgrp && vlan_tx_tag_present(skb)) ?
               TxVlanTag | swab16(vlan_tx_tag_get(skb)) : 0x00;
#elif LINUX_VERSION_CODE < KERNEL_VERSION(4,0,0)
        return (vlan_tx_tag_present(skb)) ?
               TxVlanTag | swab16(vlan_tx_tag_get(skb)) : 0x00;
#else
        return (skb_vlan_tag_present(skb)) ?
               TxVlanTag | swab16(skb_vlan_tag_get(skb)) : 0x00;
#endif

        return 0;
}

#if LINUX_VERSION_CODE < KERNEL_VERSION(3,0,0)

static void
rtl8125_vlan_rx_register(struct net_device *dev,
                         struct vlan_group *grp)
{
        struct rtl8125_private *tp = netdev_priv(dev);
        unsigned long flags;

        spin_lock_irqsave(&tp->lock, flags);
        tp->vlgrp = grp;
        if (tp->mcfg == CFG_METHOD_2 ||
            tp->mcfg == CFG_METHOD_3 ||
            tp->mcfg == CFG_METHOD_4 ||
            tp->mcfg == CFG_METHOD_5) {
                if (tp->vlgrp) {
                        tp->rtl8125_rx_config |= (EnableInnerVlan | EnableOuterVlan);
                        RTL_W32(tp, RxConfig, RTL_R32(tp, RxConfig) | (EnableInnerVlan | EnableOuterVlan))
                } else {
                        tp->rtl8125_rx_config &= ~(EnableInnerVlan | EnableOuterVlan);
                        RTL_W32(tp, RxConfig, RTL_R32(tp, RxConfig) & ~(EnableInnerVlan | EnableOuterVlan))
                }
        }
        spin_unlock_irqrestore(&tp->lock, flags);
}

#endif

#if LINUX_VERSION_CODE < KERNEL_VERSION(2,6,22)
static void
rtl8125_vlan_rx_kill_vid(struct net_device *dev,
                         unsigned short vid)
{
        struct rtl8125_private *tp = netdev_priv(dev);
        unsigned long flags;

        spin_lock_irqsave(&tp->lock, flags);
#if LINUX_VERSION_CODE < KERNEL_VERSION(2,6,21)
        if (tp->vlgrp)
                tp->vlgrp->vlan_devices[vid] = NULL;
#else
        vlan_group_set_device(tp->vlgrp, vid, NULL);
#endif //LINUX_VERSION_CODE < KERNEL_VERSION(2,6,21)
        spin_unlock_irqrestore(&tp->lock, flags);
}
#endif //LINUX_VERSION_CODE < KERNEL_VERSION(2,6,22)

static int
rtl8125_rx_vlan_skb(struct rtl8125_private *tp,
                    struct RxDesc *desc,
                    struct sk_buff *skb)
{
        u32 opts2 = le32_to_cpu(rtl8125_rx_desc_opts2(tp, desc));
        int ret = -1;

#if LINUX_VERSION_CODE < KERNEL_VERSION(3,0,0)
        if (tp->vlgrp && (opts2 & RxVlanTag)) {
                rtl8125_rx_hwaccel_skb(skb, tp->vlgrp,
                                       swab16(opts2 & 0xffff));
                ret = 0;
        }
#elif LINUX_VERSION_CODE < KERNEL_VERSION(3,10,0)
        if (opts2 & RxVlanTag)
                __vlan_hwaccel_put_tag(skb, swab16(opts2 & 0xffff));
#else
        if (opts2 & RxVlanTag)
                __vlan_hwaccel_put_tag(skb, htons(ETH_P_8021Q), swab16(opts2 & 0xffff));
#endif

        rtl8125_clear_rx_desc_opts2(tp, desc);
        return ret;
}

#else /* !CONFIG_R8125_VLAN */

static inline u32
rtl8125_tx_vlan_tag(struct rtl8125_private *tp,
                    struct sk_buff *skb)
{
        return 0;
}

static int
rtl8125_rx_vlan_skb(struct rtl8125_private *tp,
                    struct RxDesc *desc,
                    struct sk_buff *skb)
{
        return -1;
}

#endif

#if LINUX_VERSION_CODE >= KERNEL_VERSION(3,0,0)

static netdev_features_t rtl8125_fix_features(struct net_device *dev,
                netdev_features_t features)
{
        struct rtl8125_private *tp = netdev_priv(dev);
        unsigned long flags;

        spin_lock_irqsave(&tp->lock, flags);
        if (dev->mtu > MSS_MAX)
                features &= ~NETIF_F_ALL_TSO;
        if (dev->mtu > ETH_DATA_LEN) {
                features &= ~NETIF_F_ALL_TSO;
                features &= ~NETIF_F_ALL_CSUM;
        }
#ifndef CONFIG_R8125_VLAN
        features &= ~NETIF_F_ALL_CSUM;
#endif
        spin_unlock_irqrestore(&tp->lock, flags);

        return features;
}

static int rtl8125_hw_set_features(struct net_device *dev,
                                   netdev_features_t features)
{
        struct rtl8125_private *tp = netdev_priv(dev);
        u32 rx_config;

        rx_config = RTL_R32(tp, RxConfig);
        if (features & NETIF_F_RXALL)
                rx_config |= (AcceptErr | AcceptRunt);
        else
                rx_config &= ~(AcceptErr | AcceptRunt);

        if (features & NETIF_F_HW_VLAN_RX)
                rx_config |= (EnableInnerVlan | EnableOuterVlan);
        else
                rx_config &= ~(EnableInnerVlan | EnableOuterVlan);

        RTL_W32(tp, RxConfig, rx_config);

        if (features & NETIF_F_RXCSUM)
                tp->cp_cmd |= RxChkSum;
        else
                tp->cp_cmd &= ~RxChkSum;

        RTL_W16(tp, CPlusCmd, tp->cp_cmd);
        RTL_R16(tp, CPlusCmd);

        return 0;
}

static int rtl8125_set_features(struct net_device *dev,
                                netdev_features_t features)
{
        struct rtl8125_private *tp = netdev_priv(dev);
        unsigned long flags;

        features &= NETIF_F_RXALL | NETIF_F_RXCSUM | NETIF_F_HW_VLAN_RX;

        spin_lock_irqsave(&tp->lock, flags);
        if (features ^ dev->features)
                rtl8125_hw_set_features(dev, features);
        spin_unlock_irqrestore(&tp->lock, flags);

        return 0;
}

#endif

static void rtl8125_gset_xmii(struct net_device *dev,
#if LINUX_VERSION_CODE < KERNEL_VERSION(4,6,0)
                              struct ethtool_cmd *cmd
#else
                              struct ethtool_link_ksettings *cmd
#endif
                             )
{
        struct rtl8125_private *tp = netdev_priv(dev);
        u16 status;
        u8 autoneg, duplex;
        u32 speed = 0;
        u16 bmcr;
        u32 supported, advertising;
        unsigned long flags;

        supported = SUPPORTED_10baseT_Half |
                    SUPPORTED_10baseT_Full |
                    SUPPORTED_100baseT_Half |
                    SUPPORTED_100baseT_Full |
                    SUPPORTED_1000baseT_Full |
                    SUPPORTED_2500baseX_Full |
                    SUPPORTED_Autoneg |
                    SUPPORTED_TP |
                    SUPPORTED_Pause	|
                    SUPPORTED_Asym_Pause;

        advertising = ADVERTISED_TP;

        spin_lock_irqsave(&tp->lock, flags);
        rtl8125_mdio_write(tp, 0x1F, 0x0000);
        bmcr = rtl8125_mdio_read(tp, MII_BMCR);
        spin_unlock_irqrestore(&tp->lock, flags);

        if (bmcr & BMCR_ANENABLE) {
                advertising |= ADVERTISED_Autoneg;
                autoneg = AUTONEG_ENABLE;

                if (tp->phy_auto_nego_reg & ADVERTISE_10HALF)
                        advertising |= ADVERTISED_10baseT_Half;
                if (tp->phy_auto_nego_reg & ADVERTISE_10FULL)
                        advertising |= ADVERTISED_10baseT_Full;
                if (tp->phy_auto_nego_reg & ADVERTISE_100HALF)
                        advertising |= ADVERTISED_100baseT_Half;
                if (tp->phy_auto_nego_reg & ADVERTISE_100FULL)
                        advertising |= ADVERTISED_100baseT_Full;
                if (tp->phy_1000_ctrl_reg & ADVERTISE_1000FULL)
                        advertising |= ADVERTISED_1000baseT_Full;
                if (tp->phy_2500_ctrl_reg & RTK_ADVERTISE_2500FULL)
                        advertising |= ADVERTISED_2500baseX_Full;
        } else {
                autoneg = AUTONEG_DISABLE;
        }

        status = RTL_R16(tp, PHYstatus);

        if (status & LinkStatus) {
                /*link on*/
                if (status & _2500bpsF)
                        speed = SPEED_2500;
                else if (status & _1000bpsF)
                        speed = SPEED_1000;
                else if (status & _100bps)
                        speed = SPEED_100;
                else if (status & _10bps)
                        speed = SPEED_10;

                if (status & TxFlowCtrl)
                        advertising |= ADVERTISED_Asym_Pause;

                if (status & RxFlowCtrl)
                        advertising |= ADVERTISED_Pause;

                duplex = ((status & (_1000bpsF | _2500bpsF)) || (status & FullDup)) ?
                         DUPLEX_FULL : DUPLEX_HALF;
        } else {
                /*link down*/
                speed = SPEED_UNKNOWN;
                duplex = DUPLEX_UNKNOWN;
        }

#if LINUX_VERSION_CODE < KERNEL_VERSION(4,6,0)
        cmd->supported = supported;
        cmd->advertising = advertising;
        cmd->autoneg = autoneg;
        cmd->speed = speed;
        cmd->duplex = duplex;
        cmd->port = PORT_TP;
#else
        ethtool_convert_legacy_u32_to_link_mode(cmd->link_modes.supported,
                                                supported);
        ethtool_convert_legacy_u32_to_link_mode(cmd->link_modes.advertising,
                                                advertising);
        cmd->base.autoneg = autoneg;
        cmd->base.speed = speed;
        cmd->base.duplex = duplex;
        cmd->base.port = PORT_TP;
#endif
}

#if LINUX_VERSION_CODE > KERNEL_VERSION(2,4,22)
static int
rtl8125_get_settings(struct net_device *dev,
#if LINUX_VERSION_CODE < KERNEL_VERSION(4,6,0)
                     struct ethtool_cmd *cmd
#else
                     struct ethtool_link_ksettings *cmd
#endif
                    )
{
        struct rtl8125_private *tp = netdev_priv(dev);

        tp->get_settings(dev, cmd);

        return 0;
}

static void rtl8125_get_regs(struct net_device *dev, struct ethtool_regs *regs,
                             void *p)
{
        struct rtl8125_private *tp = netdev_priv(dev);
        void __iomem *ioaddr = tp->mmio_addr;
        unsigned int i;
        u8 *data = p;
        unsigned long flags;

        if (regs->len < R8125_REGS_DUMP_SIZE)
                return /* -EINVAL */;

        memset(p, 0, regs->len);

        spin_lock_irqsave(&tp->lock, flags);
        for (i = 0; i < R8125_MAC_REGS_SIZE; i++)
                *data++ = readb(ioaddr + i);
        data = (u8*)p + 256;

        rtl8125_mdio_write(tp, 0x1F, 0x0000);
        for (i = 0; i < R8125_PHY_REGS_SIZE/2; i++) {
                *(u16*)data = rtl8125_mdio_read(tp, i);
                data += 2;
        }
        data = (u8*)p + 256 * 2;

        for (i = 0; i < R8125_EPHY_REGS_SIZE/2; i++) {
                *(u16*)data = rtl8125_ephy_read(tp, i);
                data += 2;
        }
        data = (u8*)p + 256 * 3;

        switch (tp->mcfg) {
        case CFG_METHOD_2:
        case CFG_METHOD_3:
        case CFG_METHOD_4:
        case CFG_METHOD_5:
        default:
                for (i = 0; i < R8125_ERI_REGS_SIZE; i+=4) {
                        *(u32*)data = rtl8125_eri_read(tp, i , 4, ERIAR_ExGMAC);
                        data += 4;
                }
                break;
        }
        spin_unlock_irqrestore(&tp->lock, flags);
}

static void rtl8125_get_pauseparam(struct net_device *dev,
                                   struct ethtool_pauseparam *pause)
{
        struct rtl8125_private *tp = netdev_priv(dev);
        unsigned long flags;

        spin_lock_irqsave(&tp->lock, flags);

        pause->autoneg = (tp->autoneg ? AUTONEG_ENABLE : AUTONEG_DISABLE);
        if (tp->fcpause == rtl8125_fc_rx_pause)
                pause->rx_pause = 1;
        else if (tp->fcpause == rtl8125_fc_tx_pause)
                pause->tx_pause = 1;
        else if (tp->fcpause == rtl8125_fc_full) {
                pause->rx_pause = 1;
                pause->tx_pause = 1;
        }

        spin_unlock_irqrestore(&tp->lock, flags);
}

static int rtl8125_set_pauseparam(struct net_device *dev,
                                  struct ethtool_pauseparam *pause)
{
        struct rtl8125_private *tp = netdev_priv(dev);
        enum rtl8125_fc_mode newfc;
        unsigned long flags;

        if (pause->tx_pause || pause->rx_pause)
                newfc = rtl8125_fc_full;
        else
                newfc = rtl8125_fc_none;

        spin_lock_irqsave(&tp->lock, flags);

        if (tp->fcpause != newfc) {
                tp->fcpause = newfc;

                rtl8125_set_speed(dev, tp->autoneg, tp->speed, tp->duplex, tp->advertising);
        }

        spin_unlock_irqrestore(&tp->lock, flags);

        return 0;

}

static u32
rtl8125_get_msglevel(struct net_device *dev)
{
        struct rtl8125_private *tp = netdev_priv(dev);

        return tp->msg_enable;
}

static void
rtl8125_set_msglevel(struct net_device *dev,
                     u32 value)
{
        struct rtl8125_private *tp = netdev_priv(dev);

        tp->msg_enable = value;
}

static const char rtl8125_gstrings[][ETH_GSTRING_LEN] = {
        "tx_packets",
        "rx_packets",
        "tx_errors",
        "rx_errors",
        "rx_missed",
        "align_errors",
        "tx_single_collisions",
        "tx_multi_collisions",
        "unicast",
        "broadcast",
        "multicast",
        "tx_aborted",
        "tx_underrun",
};
#endif //#LINUX_VERSION_CODE > KERNEL_VERSION(2,4,22)

#if LINUX_VERSION_CODE < KERNEL_VERSION(2,6,33)
#if LINUX_VERSION_CODE > KERNEL_VERSION(2,4,22)
static int rtl8125_get_stats_count(struct net_device *dev)
{
        return ARRAY_SIZE(rtl8125_gstrings);
}
#endif //#LINUX_VERSION_CODE > KERNEL_VERSION(2,4,22)
#else
static int rtl8125_get_sset_count(struct net_device *dev, int sset)
{
        switch (sset) {
        case ETH_SS_STATS:
                return ARRAY_SIZE(rtl8125_gstrings);
        default:
                return -EOPNOTSUPP;
        }
}
#endif

#if LINUX_VERSION_CODE > KERNEL_VERSION(2,4,22)
static void
rtl8125_get_ethtool_stats(struct net_device *dev,
                          struct ethtool_stats *stats,
                          u64 *data)
{
        struct rtl8125_private *tp = netdev_priv(dev);
        struct rtl8125_counters *counters;
        dma_addr_t paddr;
        u32 cmd;
        u32 WaitCnt;
        unsigned long flags;

        ASSERT_RTNL();

        counters = tp->tally_vaddr;
        paddr = tp->tally_paddr;
        if (!counters)
                return;

        spin_lock_irqsave(&tp->lock, flags);
        RTL_W32(tp, CounterAddrHigh, (u64)paddr >> 32);
        cmd = (u64)paddr & DMA_BIT_MASK(32);
        RTL_W32(tp, CounterAddrLow, cmd);
        RTL_W32(tp, CounterAddrLow, cmd | CounterDump);

        WaitCnt = 0;
        while (RTL_R32(tp, CounterAddrLow) & CounterDump) {
                udelay(10);

                WaitCnt++;
                if (WaitCnt > 20)
                        break;
        }
        spin_unlock_irqrestore(&tp->lock, flags);

        data[0] = le64_to_cpu(counters->tx_packets);
        data[1] = le64_to_cpu(counters->rx_packets);
        data[2] = le64_to_cpu(counters->tx_errors);
        data[3] = le32_to_cpu(counters->rx_errors);
        data[4] = le16_to_cpu(counters->rx_missed);
        data[5] = le16_to_cpu(counters->align_errors);
        data[6] = le32_to_cpu(counters->tx_one_collision);
        data[7] = le32_to_cpu(counters->tx_multi_collision);
        data[8] = le64_to_cpu(counters->rx_unicast);
        data[9] = le64_to_cpu(counters->rx_broadcast);
        data[10] = le32_to_cpu(counters->rx_multicast);
        data[11] = le16_to_cpu(counters->tx_aborted);
        data[12] = le16_to_cpu(counters->tx_underun);
}

static void
rtl8125_get_strings(struct net_device *dev,
                    u32 stringset,
                    u8 *data)
{
        switch (stringset) {
        case ETH_SS_STATS:
                memcpy(data, *rtl8125_gstrings, sizeof(rtl8125_gstrings));
                break;
        }
}
#endif //#LINUX_VERSION_CODE > KERNEL_VERSION(2,4,22)

static int rtl_get_eeprom_len(struct net_device *dev)
{
        struct rtl8125_private *tp = netdev_priv(dev);

        return tp->eeprom_len;
}

static int rtl_get_eeprom(struct net_device *dev, struct ethtool_eeprom *eeprom, u8 *buf)
{
        struct rtl8125_private *tp = netdev_priv(dev);
        int i,j,ret;
        int start_w, end_w;
        int VPD_addr, VPD_data;
        u32 *eeprom_buff;
        u16 tmp;

        if (tp->eeprom_type == EEPROM_TYPE_NONE) {
                dev_printk(KERN_DEBUG, tp_to_dev(tp), "Detect none EEPROM\n");
                return -EOPNOTSUPP;
        } else if (eeprom->len == 0 || (eeprom->offset+eeprom->len) > tp->eeprom_len) {
                dev_printk(KERN_DEBUG, tp_to_dev(tp), "Invalid parameter\n");
                return -EINVAL;
        }

        switch (tp->mcfg) {
        case CFG_METHOD_2:
        case CFG_METHOD_3:
        case CFG_METHOD_4:
        case CFG_METHOD_5:
        default:
                VPD_addr = 0xD2;
                VPD_data = 0xD4;
                break;
        }

        start_w = eeprom->offset >> 2;
        end_w = (eeprom->offset + eeprom->len - 1) >> 2;

        eeprom_buff = kmalloc(sizeof(u32)*(end_w - start_w + 1), GFP_KERNEL);
        if (!eeprom_buff)
                return -ENOMEM;

        rtl8125_enable_cfg9346_write(tp);
        ret = -EFAULT;
        for (i=start_w; i<=end_w; i++) {
                pci_write_config_word(tp->pci_dev, VPD_addr, (u16)i*4);
                ret = -EFAULT;
                for (j = 0; j < 10; j++) {
                        udelay(400);
                        pci_read_config_word(tp->pci_dev, VPD_addr, &tmp);
                        if (tmp&0x8000) {
                                ret = 0;
                                break;
                        }
                }

                if (ret)
                        break;

                pci_read_config_dword(tp->pci_dev, VPD_data, &eeprom_buff[i-start_w]);
        }
        rtl8125_disable_cfg9346_write(tp);

        if (!ret)
                memcpy(buf, (u8 *)eeprom_buff + (eeprom->offset & 3), eeprom->len);

        kfree(eeprom_buff);

        return ret;
}

#undef ethtool_op_get_link
#define ethtool_op_get_link _kc_ethtool_op_get_link
static u32 _kc_ethtool_op_get_link(struct net_device *dev)
{
        return netif_carrier_ok(dev) ? 1 : 0;
}

#if LINUX_VERSION_CODE < KERNEL_VERSION(3,3,0)
#undef ethtool_op_get_sg
#define ethtool_op_get_sg _kc_ethtool_op_get_sg
static u32 _kc_ethtool_op_get_sg(struct net_device *dev)
{
#ifdef NETIF_F_SG
        return (dev->features & NETIF_F_SG) != 0;
#else
        return 0;
#endif
}

#undef ethtool_op_set_sg
#define ethtool_op_set_sg _kc_ethtool_op_set_sg
static int _kc_ethtool_op_set_sg(struct net_device *dev, u32 data)
{
        struct rtl8125_private *tp = netdev_priv(dev);

        if (tp->mcfg == CFG_METHOD_DEFAULT)
                return -EOPNOTSUPP;

#ifdef NETIF_F_SG
        if (data)
                dev->features |= NETIF_F_SG;
        else
                dev->features &= ~NETIF_F_SG;
#endif

        return 0;
}
#endif

static int rtl8125_enable_eee(struct rtl8125_private *tp)
{
        struct ethtool_eee *eee = &tp->eee;
        u16 eee_adv_t = ethtool_adv_to_mmd_eee_adv_t(eee->advertised);
        int ret;

        ret = 0;
        switch (tp->mcfg) {
        case CFG_METHOD_2:
        case CFG_METHOD_3:
                RTL_W16(tp, EEE_TXIDLE_TIMER_8125, eee->tx_lpi_timer);

                SetMcuAccessRegBit(tp, 0xE040, (BIT_1|BIT_0));
                SetMcuAccessRegBit(tp, 0xEB62, (BIT_2|BIT_1));

                SetEthPhyOcpBit(tp, 0xA432, BIT_4);
                SetEthPhyOcpBit(tp, 0xA5D0, eee_adv_t);
                ClearEthPhyOcpBit(tp, 0xA6D4, BIT_0);

                ClearEthPhyOcpBit(tp, 0xA6D8, BIT_4);
                ClearEthPhyOcpBit(tp, 0xA428, BIT_7);
                ClearEthPhyOcpBit(tp, 0xA4A2, BIT_9);
                break;
        case CFG_METHOD_4:
        case CFG_METHOD_5:
                RTL_W16(tp, EEE_TXIDLE_TIMER_8125, eee->tx_lpi_timer);

                SetMcuAccessRegBit(tp, 0xE040, (BIT_1|BIT_0));

                SetEthPhyOcpBit(tp, 0xA5D0, eee_adv_t);
                if (eee->advertised & SUPPORTED_2500baseX_Full)
                        SetEthPhyOcpBit(tp, 0xA6D4, BIT_0);
                else
                        ClearEthPhyOcpBit(tp, 0xA6D4, BIT_0);

                ClearEthPhyOcpBit(tp, 0xA6D8, BIT_4);
                ClearEthPhyOcpBit(tp, 0xA428, BIT_7);
                ClearEthPhyOcpBit(tp, 0xA4A2, BIT_9);
                break;
        default:
//      dev_printk(KERN_DEBUG, tp_to_dev(tp), "Not Support EEE\n");
                ret = -EOPNOTSUPP;
                break;
        }

        /*Advanced EEE*/
        switch (tp->mcfg) {
        case CFG_METHOD_2:
        case CFG_METHOD_3:
        case CFG_METHOD_4:
        case CFG_METHOD_5:
                rtl8125_set_phy_mcu_patch_request(tp);
                ClearMcuAccessRegBit(tp, 0xE052, BIT_0);
                ClearEthPhyOcpBit(tp, 0xA442, BIT_12 | BIT_13);
                ClearEthPhyOcpBit(tp, 0xA430, BIT_15);
                rtl8125_clear_phy_mcu_patch_request(tp);
                break;
        }

        return ret;
}

static int rtl8125_disable_eee(struct rtl8125_private *tp)
{
        int ret;

        ret = 0;
        switch (tp->mcfg) {
        case CFG_METHOD_2:
        case CFG_METHOD_3:
                ClearMcuAccessRegBit(tp, 0xE040, (BIT_1|BIT_0));
                ClearMcuAccessRegBit(tp, 0xEB62, (BIT_2|BIT_1));

                ClearEthPhyOcpBit(tp, 0xA432, BIT_4);
                ClearEthPhyOcpBit(tp, 0xA5D0, (BIT_2 | BIT_1));
                ClearEthPhyOcpBit(tp, 0xA6D4, BIT_0);

                ClearEthPhyOcpBit(tp, 0xA6D8, BIT_4);
                ClearEthPhyOcpBit(tp, 0xA428, BIT_7);
                ClearEthPhyOcpBit(tp, 0xA4A2, BIT_9);
                break;
        case CFG_METHOD_4:
        case CFG_METHOD_5:
                ClearMcuAccessRegBit(tp, 0xE040, (BIT_1|BIT_0));

                ClearEthPhyOcpBit(tp, 0xA5D0, (BIT_2 | BIT_1));
                ClearEthPhyOcpBit(tp, 0xA6D4, BIT_0);

                ClearEthPhyOcpBit(tp, 0xA6D8, BIT_4);
                ClearEthPhyOcpBit(tp, 0xA428, BIT_7);
                ClearEthPhyOcpBit(tp, 0xA4A2, BIT_9);
                break;
        default:
//      dev_printk(KERN_DEBUG, tp_to_dev(tp), "Not Support EEE\n");
                ret = -EOPNOTSUPP;
                break;
        }

        /*Advanced EEE*/
        switch (tp->mcfg) {
        case CFG_METHOD_2:
        case CFG_METHOD_3:
        case CFG_METHOD_4:
        case CFG_METHOD_5:
                rtl8125_set_phy_mcu_patch_request(tp);
                ClearMcuAccessRegBit(tp, 0xE052, BIT_0);
                ClearEthPhyOcpBit(tp, 0xA442, BIT_12 | BIT_13);
                ClearEthPhyOcpBit(tp, 0xA430, BIT_15);
                rtl8125_clear_phy_mcu_patch_request(tp);
                break;
        }

        return ret;
}

static int rtl_nway_reset(struct net_device *dev)
{
        struct rtl8125_private *tp = netdev_priv(dev);
        unsigned long flags;
        int ret, bmcr;

        spin_lock_irqsave(&tp->lock, flags);

        if (unlikely(tp->rtk_enable_diag)) {
                spin_unlock_irqrestore(&tp->lock, flags);
                return -EBUSY;
        }

        /* if autoneg is off, it's an error */
        rtl8125_mdio_write(tp, 0x1F, 0x0000);
        bmcr = rtl8125_mdio_read(tp, MII_BMCR);

        if (bmcr & BMCR_ANENABLE) {
                bmcr |= BMCR_ANRESTART;
                rtl8125_mdio_write(tp, MII_BMCR, bmcr);
                ret = 0;
        } else {
                ret = -EINVAL;
        }

        spin_unlock_irqrestore(&tp->lock, flags);

        return ret;
}

#if LINUX_VERSION_CODE >= KERNEL_VERSION(3,6,0)
static u32
rtl8125_tx_lpi_timer_to_us(struct rtl8125_private *tp , u32 tx_lpi_timer)
{
        u32 to_us;
        u16 status;

        //2.5G : tx_lpi_timer * 3.2ns
        //Giga: tx_lpi_timer * 8ns
        //100M : tx_lpi_timer * 80ns
        to_us = tx_lpi_timer * 80;
        status = RTL_R16(tp, PHYstatus);
        if (status & LinkStatus) {
                /*link on*/
                if (status & _2500bpsF)
                        to_us = (tx_lpi_timer * 32) / 10;
                else if (status & _1000bpsF)
                        to_us = tx_lpi_timer * 8;
        }

        //ns to us
        to_us /= 1000;

        return to_us;
}

static int
rtl_ethtool_get_eee(struct net_device *net, struct ethtool_eee *edata)
{
        struct rtl8125_private *tp = netdev_priv(net);
        struct ethtool_eee *eee = &tp->eee;
        u32 lp, adv, tx_lpi_timer, supported = 0;
        unsigned long flags;
        u16 val;

        spin_lock_irqsave(&tp->lock, flags);

        if (unlikely(tp->rtk_enable_diag)) {
                spin_unlock_irqrestore(&tp->lock, flags);
                return -EBUSY;
        }

        /* Get Supported EEE */
        //val = mdio_direct_read_phy_ocp(tp, 0xA5C4);
        //supported = mmd_eee_cap_to_ethtool_sup_t(val);
        supported = eee->supported;

        /* Get advertisement EEE */
        val = mdio_direct_read_phy_ocp(tp, 0xA5D0);
        adv = mmd_eee_adv_to_ethtool_adv_t(val);

        /* Get LP advertisement EEE */
        val = mdio_direct_read_phy_ocp(tp, 0xA5D2);
        lp = mmd_eee_adv_to_ethtool_adv_t(val);

        /* Get EEE Tx LPI timer*/
        tx_lpi_timer = RTL_R16(tp, EEE_TXIDLE_TIMER_8125);

        val = rtl8125_mac_ocp_read(tp, 0xE040);
        val &= BIT_1 | BIT_0;

        spin_unlock_irqrestore(&tp->lock, flags);

        edata->eee_enabled = !!val;
        edata->eee_active = !!(supported & adv & lp);
        edata->supported = supported;
        edata->advertised = adv;
        edata->lp_advertised = lp;
        edata->tx_lpi_enabled = edata->eee_enabled;
        edata->tx_lpi_timer = rtl8125_tx_lpi_timer_to_us(tp, tx_lpi_timer);

        return 0;
}

static int
rtl_ethtool_set_eee(struct net_device *net, struct ethtool_eee *edata)
{
        struct rtl8125_private *tp = netdev_priv(net);
        struct ethtool_eee *eee = &tp->eee;
        u32 advertising;
        unsigned long flags;
        int rc = 0;

        if (!HW_HAS_WRITE_PHY_MCU_RAM_CODE(tp) ||
            tp->DASH)
                return -EOPNOTSUPP;

        spin_lock_irqsave(&tp->lock, flags);

        if (unlikely(tp->rtk_enable_diag)) {
                dev_printk(KERN_WARNING, tp_to_dev(tp), "Diag Enabled\n");
                rc = -EBUSY;
                goto exit_unlock;
        }

        if (tp->autoneg != AUTONEG_ENABLE) {
                dev_printk(KERN_WARNING, tp_to_dev(tp), "EEE requires autoneg\n");
                rc = -EINVAL;
                goto exit_unlock;
        }

        if (edata->tx_lpi_enabled) {
                if (edata->tx_lpi_timer > tp->max_jumbo_frame_size ||
                    edata->tx_lpi_timer < ETH_MIN_MTU) {
                        dev_printk(KERN_WARNING, tp_to_dev(tp), "Valid LPI timer range is %d to %d. \n",
                                   ETH_MIN_MTU, tp->max_jumbo_frame_size);
                        rc = -EINVAL;
                        goto exit_unlock;
                }
        }

        advertising = tp->advertising;
        if (!edata->advertised) {
                edata->advertised = advertising & eee->supported;
        } else if (edata->advertised & ~advertising) {
                dev_printk(KERN_WARNING, tp_to_dev(tp), "EEE advertised %x must be a subset of autoneg advertised speeds %x\n",
                           edata->advertised, advertising);
                rc = -EINVAL;
                goto exit_unlock;
        }

        if (edata->advertised & ~eee->supported) {
                dev_printk(KERN_WARNING, tp_to_dev(tp), "EEE advertised %x must be a subset of support %x\n",
                           edata->advertised, eee->supported);
                rc = -EINVAL;
                goto exit_unlock;
        }

        //tp->eee.eee_enabled = edata->eee_enabled;
        //tp->eee_adv_t = ethtool_adv_to_mmd_eee_adv_t(edata->advertised);

        dev_printk(KERN_WARNING, tp_to_dev(tp), "EEE tx_lpi_timer %x must be a subset of support %x\n",
                   edata->tx_lpi_timer, eee->tx_lpi_timer);

        eee->advertised = edata->advertised;
        eee->tx_lpi_enabled = edata->tx_lpi_enabled;
        eee->tx_lpi_timer = edata->tx_lpi_timer;
        eee->eee_enabled = edata->eee_enabled;

        if (eee->eee_enabled)
                rtl8125_enable_eee(tp);
        else
                rtl8125_disable_eee(tp);

        spin_unlock_irqrestore(&tp->lock, flags);

        rtl_nway_reset(net);

        return rc;

exit_unlock:

        spin_unlock_irqrestore(&tp->lock, flags);

        return rc;
}
#endif /* LINUX_VERSION_CODE >= KERNEL_VERSION(3,6,0) */

#if LINUX_VERSION_CODE > KERNEL_VERSION(2,4,22)
static const struct ethtool_ops rtl8125_ethtool_ops = {
        .get_drvinfo        = rtl8125_get_drvinfo,
        .get_regs_len       = rtl8125_get_regs_len,
        .get_link       = ethtool_op_get_link,
#if LINUX_VERSION_CODE < KERNEL_VERSION(4,6,0)
        .get_settings       = rtl8125_get_settings,
        .set_settings       = rtl8125_set_settings,
#else
        .get_link_ksettings       = rtl8125_get_settings,
        .set_link_ksettings       = rtl8125_set_settings,
#endif
#if LINUX_VERSION_CODE >= KERNEL_VERSION(2,6,0)
        .get_pauseparam     = rtl8125_get_pauseparam,
        .set_pauseparam     = rtl8125_set_pauseparam,
#endif
        .get_msglevel       = rtl8125_get_msglevel,
        .set_msglevel       = rtl8125_set_msglevel,
#if LINUX_VERSION_CODE < KERNEL_VERSION(3,3,0)
        .get_rx_csum        = rtl8125_get_rx_csum,
        .set_rx_csum        = rtl8125_set_rx_csum,
        .get_tx_csum        = rtl8125_get_tx_csum,
        .set_tx_csum        = rtl8125_set_tx_csum,
        .get_sg         = ethtool_op_get_sg,
        .set_sg         = ethtool_op_set_sg,
#ifdef NETIF_F_TSO
        .get_tso        = ethtool_op_get_tso,
        .set_tso        = ethtool_op_set_tso,
#endif
#endif
        .get_regs       = rtl8125_get_regs,
        .get_wol        = rtl8125_get_wol,
        .set_wol        = rtl8125_set_wol,
        .get_strings        = rtl8125_get_strings,
#if LINUX_VERSION_CODE < KERNEL_VERSION(2,6,33)
        .get_stats_count    = rtl8125_get_stats_count,
#else
        .get_sset_count     = rtl8125_get_sset_count,
#endif
        .get_ethtool_stats  = rtl8125_get_ethtool_stats,
#if LINUX_VERSION_CODE < KERNEL_VERSION(2,6,23)
#ifdef ETHTOOL_GPERMADDR
        .get_perm_addr      = ethtool_op_get_perm_addr,
#endif
#endif //LINUX_VERSION_CODE < KERNEL_VERSION(2,6,23)
        .get_eeprom     = rtl_get_eeprom,
        .get_eeprom_len     = rtl_get_eeprom_len,
#ifdef ENABLE_RSS_SUPPORT
        .get_rxnfc		= rtl8125_get_rxnfc,
        .set_rxnfc		= rtl8125_set_rxnfc,
        .get_rxfh_indir_size	= rtl8125_rss_indir_size,
        .get_rxfh_key_size	= rtl8125_get_rxfh_key_size,
        .get_rxfh		= rtl8125_get_rxfh,
        .set_rxfh		= rtl8125_set_rxfh,
#endif
#if LINUX_VERSION_CODE >= KERNEL_VERSION(3,5,0)
#ifdef ENABLE_PTP_SUPPORT
        .get_ts_info        = rtl8125_get_ts_info,
#else
        .get_ts_info        = ethtool_op_get_ts_info,
#endif //ENABLE_PTP_SUPPORT
#endif //LINUX_VERSION_CODE >= KERNEL_VERSION(3,5,0)
#if LINUX_VERSION_CODE >= KERNEL_VERSION(3,6,0)
        .get_eee = rtl_ethtool_get_eee,
        .set_eee = rtl_ethtool_set_eee,
#endif /* LINUX_VERSION_CODE >= KERNEL_VERSION(3,6,0) */
        .nway_reset = rtl_nway_reset,

};
#endif //LINUX_VERSION_CODE > KERNEL_VERSION(2,4,22)

#if 0

static int rtl8125_enable_green_feature(struct rtl8125_private *tp)
{
        u16 gphy_val;
        unsigned long flags;

        switch (tp->mcfg) {
        case CFG_METHOD_2:
        case CFG_METHOD_3:
        case CFG_METHOD_4:
        case CFG_METHOD_5:
                mdio_direct_write_phy_ocp(tp, 0xA436, 0x8011);
                SetEthPhyOcpBit(tp, 0xA438, BIT_15);
                rtl8125_mdio_write(tp, 0x00, 0x9200);
                break;
        default:
                dev_printk(KERN_DEBUG, tp_to_dev(tp), "Not Support Green Feature\n");
                break;
        }

        return 0;
}

static int rtl8125_disable_green_feature(struct rtl8125_private *tp)
{
        u16 gphy_val;
        unsigned long flags;

        switch (tp->mcfg) {
        case CFG_METHOD_2:
        case CFG_METHOD_3:
        case CFG_METHOD_4:
        case CFG_METHOD_5:
                mdio_direct_write_phy_ocp(tp, 0xA436, 0x8011);
                ClearEthPhyOcpBit(tp, 0xA438, BIT_15);
                rtl8125_mdio_write(tp, 0x00, 0x9200);
                break;
        default:
                dev_printk(KERN_DEBUG, tp_to_dev(tp), "Not Support Green Feature\n");
                break;
        }

        return 0;
}

#endif

static void rtl8125_get_mac_version(struct rtl8125_private *tp)
{
        u32 reg,val32;
        u32 ICVerID;

        val32 = RTL_R32(tp, TxConfig);
        reg = val32 & 0x7c800000;
        ICVerID = val32 & 0x00700000;

        switch (reg) {
        case 0x60800000:
                if (ICVerID == 0x00000000) {
                        tp->mcfg = CFG_METHOD_2;
                } else if (ICVerID == 0x100000) {
                        tp->mcfg = CFG_METHOD_3;
                } else {
                        tp->mcfg = CFG_METHOD_3;
                        tp->HwIcVerUnknown = TRUE;
                }

                tp->efuse_ver = EFUSE_SUPPORT_V4;
                break;
        case 0x64000000:
                if (ICVerID == 0x00000000) {
                        tp->mcfg = CFG_METHOD_4;
                } else if (ICVerID == 0x100000) {
                        tp->mcfg = CFG_METHOD_5;
                } else {
                        tp->mcfg = CFG_METHOD_5;
                        tp->HwIcVerUnknown = TRUE;
                }

                tp->efuse_ver = EFUSE_SUPPORT_V4;
                break;
        default:
                printk("unknown chip version (%x)\n",reg);
                tp->mcfg = CFG_METHOD_DEFAULT;
                tp->HwIcVerUnknown = TRUE;
                tp->efuse_ver = EFUSE_NOT_SUPPORT;
                break;
        }
}

static void
rtl8125_print_mac_version(struct rtl8125_private *tp)
{
        int i;
        for (i = ARRAY_SIZE(rtl_chip_info) - 1; i >= 0; i--) {
                if (tp->mcfg == rtl_chip_info[i].mcfg) {
                        dprintk("Realtek PCIe 2.5GbE Family Controller mcfg = %04d\n",
                                rtl_chip_info[i].mcfg);
                        return;
                }
        }

        dprintk("mac_version == Unknown\n");
}

static void
rtl8125_tally_counter_addr_fill(struct rtl8125_private *tp)
{
        if (!tp->tally_paddr)
                return;

        RTL_W32(tp, CounterAddrHigh, (u64)tp->tally_paddr >> 32);
        RTL_W32(tp, CounterAddrLow, (u64)tp->tally_paddr & (DMA_BIT_MASK(32)));
}

static void
rtl8125_tally_counter_clear(struct rtl8125_private *tp)
{
        if (!tp->tally_paddr)
                return;

        RTL_W32(tp, CounterAddrHigh, (u64)tp->tally_paddr >> 32);
        RTL_W32(tp, CounterAddrLow, ((u64)tp->tally_paddr & (DMA_BIT_MASK(32))) | CounterReset);
}

static void
rtl8125_clear_phy_ups_reg(struct net_device *dev)
{
        struct rtl8125_private *tp = netdev_priv(dev);

        switch (tp->mcfg) {
        case CFG_METHOD_4:
        case CFG_METHOD_5:
                ClearEthPhyOcpBit(tp, 0xA466, BIT_0);
                break;
        };
        ClearEthPhyOcpBit(tp, 0xA468, BIT_3 | BIT_1);
}

static int
rtl8125_is_ups_resume(struct net_device *dev)
{
        struct rtl8125_private *tp = netdev_priv(dev);

        if (tp->mcfg == CFG_METHOD_2 ||
            tp->mcfg == CFG_METHOD_3 ||
            tp->mcfg == CFG_METHOD_4 ||
            tp->mcfg == CFG_METHOD_5)
                return (rtl8125_mac_ocp_read(tp, 0xD42C) & BIT_8);

        return 0;
}

static void
rtl8125_clear_ups_resume_bit(struct net_device *dev)
{
        struct rtl8125_private *tp = netdev_priv(dev);

        if (tp->mcfg == CFG_METHOD_2 ||
            tp->mcfg == CFG_METHOD_3 ||
            tp->mcfg == CFG_METHOD_4 ||
            tp->mcfg == CFG_METHOD_5)
                rtl8125_mac_ocp_write(tp, 0xD408, rtl8125_mac_ocp_read(tp, 0xD408) & ~(BIT_8));
}

static void
rtl8125_wait_phy_ups_resume(struct net_device *dev, u16 PhyState)
{
        struct rtl8125_private *tp = netdev_priv(dev);
        u16 TmpPhyState;
        int i=0;

        if (tp->mcfg == CFG_METHOD_2 ||
            tp->mcfg == CFG_METHOD_3 ||
            tp->mcfg == CFG_METHOD_4 ||
            tp->mcfg == CFG_METHOD_5) {
                do {
                        TmpPhyState = mdio_direct_read_phy_ocp(tp, 0xA420);
                        TmpPhyState &= 0x7;
                        mdelay(1);
                        i++;
                } while ((i < 100) && (TmpPhyState != PhyState));
        }

#if LINUX_VERSION_CODE >= KERNEL_VERSION(2,6,18)
        WARN_ON_ONCE(i == 100);
#endif
}

void
rtl8125_enable_now_is_oob(struct rtl8125_private *tp)
{
        if ( tp->HwSuppNowIsOobVer == 1 ) {
                RTL_W8(tp, MCUCmd_reg, RTL_R8(tp, MCUCmd_reg) | Now_is_oob);
        }
}

void
rtl8125_disable_now_is_oob(struct rtl8125_private *tp)
{
        if ( tp->HwSuppNowIsOobVer == 1 ) {
                RTL_W8(tp, MCUCmd_reg, RTL_R8(tp, MCUCmd_reg) & ~Now_is_oob);
        }
}

static void
rtl8125_exit_oob(struct net_device *dev)
{
        struct rtl8125_private *tp = netdev_priv(dev);
        u16 data16;

        RTL_W32(tp, RxConfig, RTL_R32(tp, RxConfig) & ~(AcceptErr | AcceptRunt | AcceptBroadcast | AcceptMulticast | AcceptMyPhys |  AcceptAllPhys));

        switch (tp->mcfg) {
        case CFG_METHOD_2:
        case CFG_METHOD_3:
        case CFG_METHOD_4:
        case CFG_METHOD_5:
                rtl8125_dash2_disable_txrx(dev);
                break;
        }

        if (tp->DASH) {
                rtl8125_driver_stop(tp);
                rtl8125_driver_start(tp);
#ifdef ENABLE_DASH_SUPPORT
                DashHwInit(dev);
#endif
        }

#ifdef ENABLE_REALWOW_SUPPORT
        rtl8125_realwow_hw_init(dev);
#else
        //Disable realwow  function
        switch (tp->mcfg) {
        case CFG_METHOD_2:
        case CFG_METHOD_3:
        case CFG_METHOD_4:
        case CFG_METHOD_5:
                rtl8125_mac_ocp_write(tp, 0xC0BC, 0x00FF);
                break;
        }
#endif //ENABLE_REALWOW_SUPPORT

        rtl8125_nic_reset(dev);

        switch (tp->mcfg) {
        case CFG_METHOD_2:
        case CFG_METHOD_3:
        case CFG_METHOD_4:
        case CFG_METHOD_5:
                rtl8125_disable_now_is_oob(tp);

                data16 = rtl8125_mac_ocp_read(tp, 0xE8DE) & ~BIT_14;
                rtl8125_mac_ocp_write(tp, 0xE8DE, data16);
                rtl8125_wait_ll_share_fifo_ready(dev);

                rtl8125_mac_ocp_write(tp, 0xC0AA, 0x07D0);
                rtl8125_mac_ocp_write(tp, 0xC0A6, 0x01B5);
                rtl8125_mac_ocp_write(tp, 0xC01E, 0x5555);

                rtl8125_wait_ll_share_fifo_ready(dev);
                break;
        }

        //wait ups resume (phy state 2)
        switch (tp->mcfg) {
        case CFG_METHOD_2:
        case CFG_METHOD_3:
        case CFG_METHOD_4:
        case CFG_METHOD_5:
                if (rtl8125_is_ups_resume(dev)) {
                        rtl8125_wait_phy_ups_resume(dev, 2);
                        rtl8125_clear_ups_resume_bit(dev);
                        rtl8125_clear_phy_ups_reg(dev);
                }
                break;
        };
}

void
rtl8125_hw_disable_mac_mcu_bps(struct net_device *dev)
{
        struct rtl8125_private *tp = netdev_priv(dev);

        switch (tp->mcfg) {
        case CFG_METHOD_2:
        case CFG_METHOD_3:
        case CFG_METHOD_4:
        case CFG_METHOD_5:
                rtl8125_enable_cfg9346_write(tp);
                RTL_W8(tp, Config5, RTL_R8(tp, Config5) & ~BIT_0);
                RTL_W8(tp, Config2, RTL_R8(tp, Config2) & ~BIT_7);
                rtl8125_disable_cfg9346_write(tp);
                break;
        }

        switch (tp->mcfg) {
        case CFG_METHOD_2:
        case CFG_METHOD_3:
        case CFG_METHOD_4:
        case CFG_METHOD_5:
                rtl8125_mac_ocp_write(tp, 0xFC38, 0x0000);
                break;
        }

        switch (tp->mcfg) {
        case CFG_METHOD_2:
        case CFG_METHOD_3:
        case CFG_METHOD_4:
        case CFG_METHOD_5:
                rtl8125_mac_ocp_write(tp, 0xFC28, 0x0000);
                rtl8125_mac_ocp_write(tp, 0xFC2A, 0x0000);
                rtl8125_mac_ocp_write(tp, 0xFC2C, 0x0000);
                rtl8125_mac_ocp_write(tp, 0xFC2E, 0x0000);
                rtl8125_mac_ocp_write(tp, 0xFC30, 0x0000);
                rtl8125_mac_ocp_write(tp, 0xFC32, 0x0000);
                rtl8125_mac_ocp_write(tp, 0xFC34, 0x0000);
                rtl8125_mac_ocp_write(tp, 0xFC36, 0x0000);
                mdelay(3);
                rtl8125_mac_ocp_write(tp, 0xFC26, 0x0000);
                break;
        }
}

#ifdef ENABLE_USE_FIRMWARE_FILE
static void rtl8125_release_firmware(struct rtl8125_private *tp)
{
        if (tp->rtl_fw) {
                rtl8125_fw_release_firmware(tp->rtl_fw);
                kfree(tp->rtl_fw);
                tp->rtl_fw = NULL;
        }
}

void rtl8125_apply_firmware(struct rtl8125_private *tp)
{
        /* TODO: release firmware if rtl_fw_write_firmware signals failure. */
        if (tp->rtl_fw) {
                rtl8125_fw_write_firmware(tp, tp->rtl_fw);
                /* At least one firmware doesn't reset tp->ocp_base. */
                tp->ocp_base = OCP_STD_PHY_BASE;

                /* PHY soft reset may still be in progress */
                //phy_read_poll_timeout(tp->phydev, MII_BMCR, val,
                //		      !(val & BMCR_RESET),
                //		      50000, 600000, true);
                rtl8125_wait_phy_reset_complete(tp);

                tp->hw_ram_code_ver = rtl8125_get_hw_phy_mcu_code_ver(tp);
                tp->sw_ram_code_ver = tp->hw_ram_code_ver;
                tp->HwHasWrRamCodeToMicroP = TRUE;
        }
}
#endif

static void
rtl8125_hw_init(struct net_device *dev)
{
        struct rtl8125_private *tp = netdev_priv(dev);
        u32 csi_tmp;

        switch (tp->mcfg) {
        case CFG_METHOD_2:
        case CFG_METHOD_3:
        case CFG_METHOD_4:
        case CFG_METHOD_5:
                rtl8125_enable_cfg9346_write(tp);
                RTL_W8(tp, Config5, RTL_R8(tp, Config5) & ~BIT_0);
                RTL_W8(tp, Config2, RTL_R8(tp, Config2) & ~BIT_7);
                rtl8125_disable_cfg9346_write(tp);
                RTL_W8(tp, 0xF1, RTL_R8(tp, 0xF1) & ~BIT_7);
                break;
        }

        //Disable UPS
        switch (tp->mcfg) {
        case CFG_METHOD_2:
        case CFG_METHOD_3:
        case CFG_METHOD_4:
        case CFG_METHOD_5:
                rtl8125_mac_ocp_write(tp, 0xD40A, rtl8125_mac_ocp_read( tp, 0xD40A) & ~(BIT_4));
                break;
        }

        /*disable ocp phy power saving*/
        if (tp->mcfg == CFG_METHOD_2 ||
            tp->mcfg == CFG_METHOD_3 ||
            tp->mcfg == CFG_METHOD_4 ||
            tp->mcfg == CFG_METHOD_5)
                rtl8125_disable_ocp_phy_power_saving(dev);

        //Set PCIE uncorrectable error status mask pcie 0x108
        csi_tmp = rtl8125_csi_read(tp, 0x108);
        csi_tmp |= BIT_20;
        rtl8125_csi_write(tp, 0x108, csi_tmp);

        rtl8125_enable_cfg9346_write(tp);
        rtl8125_disable_linkchg_wakeup(dev);
        rtl8125_disable_cfg9346_write(tp);
        rtl8125_disable_magic_packet(dev);
        rtl8125_disable_d0_speedup(tp);
        rtl8125_set_pci_pme(tp, 0);
        if (s0_magic_packet == 1)
                rtl8125_enable_magic_packet(dev);

#ifdef ENABLE_USE_FIRMWARE_FILE
        if (tp->rtl_fw &&
            !tp->resume_not_chg_speed &&
            !(HW_DASH_SUPPORT_TYPE_3(tp) &&
              tp->HwPkgDet == 0x06))
                rtl8125_apply_firmware(tp);
#endif
}

static void
rtl8125_hw_ephy_config(struct net_device *dev)
{
        struct rtl8125_private *tp = netdev_priv(dev);

        switch (tp->mcfg) {
        case CFG_METHOD_2:
                rtl8125_ephy_write(tp, 0x01, 0xA812);
                rtl8125_ephy_write(tp, 0x09, 0x520C);
                rtl8125_ephy_write(tp, 0x04, 0xD000);
                rtl8125_ephy_write(tp, 0x0D, 0xF702);
                rtl8125_ephy_write(tp, 0x0A, 0x8653);
                rtl8125_ephy_write(tp, 0x06, 0x001E);
                rtl8125_ephy_write(tp, 0x08, 0x3595);
                rtl8125_ephy_write(tp, 0x20, 0x9455);
                rtl8125_ephy_write(tp, 0x21, 0x99FF);
                rtl8125_ephy_write(tp, 0x02, 0x6046);
                rtl8125_ephy_write(tp, 0x29, 0xFE00);
                rtl8125_ephy_write(tp, 0x23, 0xAB62);

                rtl8125_ephy_write(tp, 0x41, 0xA80C);
                rtl8125_ephy_write(tp, 0x49, 0x520C);
                rtl8125_ephy_write(tp, 0x44, 0xD000);
                rtl8125_ephy_write(tp, 0x4D, 0xF702);
                rtl8125_ephy_write(tp, 0x4A, 0x8653);
                rtl8125_ephy_write(tp, 0x46, 0x001E);
                rtl8125_ephy_write(tp, 0x48, 0x3595);
                rtl8125_ephy_write(tp, 0x60, 0x9455);
                rtl8125_ephy_write(tp, 0x61, 0x99FF);
                rtl8125_ephy_write(tp, 0x42, 0x6046);
                rtl8125_ephy_write(tp, 0x69, 0xFE00);
                rtl8125_ephy_write(tp, 0x63, 0xAB62);
                break;
        case CFG_METHOD_3:
                rtl8125_ephy_write(tp, 0x04, 0xD000);
                rtl8125_ephy_write(tp, 0x0A, 0x8653);
                rtl8125_ephy_write(tp, 0x23, 0xAB66);
                rtl8125_ephy_write(tp, 0x20, 0x9455);
                rtl8125_ephy_write(tp, 0x21, 0x99FF);
                rtl8125_ephy_write(tp, 0x29, 0xFE04);

                rtl8125_ephy_write(tp, 0x44, 0xD000);
                rtl8125_ephy_write(tp, 0x4A, 0x8653);
                rtl8125_ephy_write(tp, 0x63, 0xAB66);
                rtl8125_ephy_write(tp, 0x60, 0x9455);
                rtl8125_ephy_write(tp, 0x61, 0x99FF);
                rtl8125_ephy_write(tp, 0x69, 0xFE04);

                ClearAndSetPCIePhyBit(tp,
                                      0x2A,
                                      (BIT_14 | BIT_13 | BIT_12),
                                      (BIT_13 | BIT_12)
                                     );
                ClearPCIePhyBit(tp, 0x19, BIT_6);
                SetPCIePhyBit(tp, 0x1B, (BIT_11 | BIT_10 | BIT_9));
                ClearPCIePhyBit(tp, 0x1B, (BIT_14 | BIT_13 | BIT_12));
                rtl8125_ephy_write(tp, 0x02, 0x6042);
                rtl8125_ephy_write(tp, 0x06, 0x0014);

                ClearAndSetPCIePhyBit(tp,
                                      0x6A,
                                      (BIT_14 | BIT_13 | BIT_12),
                                      (BIT_13 | BIT_12)
                                     );
                ClearPCIePhyBit(tp, 0x59, BIT_6);
                SetPCIePhyBit(tp, 0x5B, (BIT_11 | BIT_10 | BIT_9));
                ClearPCIePhyBit(tp, 0x5B, (BIT_14 | BIT_13 | BIT_12));
                rtl8125_ephy_write(tp, 0x42, 0x6042);
                rtl8125_ephy_write(tp, 0x46, 0x0014);
                break;
        case CFG_METHOD_4:
                rtl8125_ephy_write(tp, 0x06, 0x001F);
                rtl8125_ephy_write(tp, 0x0A, 0xB66B);
                rtl8125_ephy_write(tp, 0x01, 0xA852);
                rtl8125_ephy_write(tp, 0x24, 0x0008);
                rtl8125_ephy_write(tp, 0x2F, 0x6052);
                rtl8125_ephy_write(tp, 0x0D, 0xF716);
                rtl8125_ephy_write(tp, 0x20, 0xD477);
                rtl8125_ephy_write(tp, 0x21, 0x4477);
                rtl8125_ephy_write(tp, 0x22, 0x0013);
                rtl8125_ephy_write(tp, 0x23, 0xBB66);
                rtl8125_ephy_write(tp, 0x0B, 0xA909);
                rtl8125_ephy_write(tp, 0x29, 0xFF04);
                rtl8125_ephy_write(tp, 0x1B, 0x1EA0);

                rtl8125_ephy_write(tp, 0x46, 0x001F);
                rtl8125_ephy_write(tp, 0x4A, 0xB66B);
                rtl8125_ephy_write(tp, 0x41, 0xA84A);
                rtl8125_ephy_write(tp, 0x64, 0x000C);
                rtl8125_ephy_write(tp, 0x6F, 0x604A);
                rtl8125_ephy_write(tp, 0x4D, 0xF716);
                rtl8125_ephy_write(tp, 0x60, 0xD477);
                rtl8125_ephy_write(tp, 0x61, 0x4477);
                rtl8125_ephy_write(tp, 0x62, 0x0013);
                rtl8125_ephy_write(tp, 0x63, 0xBB66);
                rtl8125_ephy_write(tp, 0x4B, 0xA909);
                rtl8125_ephy_write(tp, 0x69, 0xFF04);
                rtl8125_ephy_write(tp, 0x5B, 0x1EA0);
                break;
        case CFG_METHOD_5:
                rtl8125_ephy_write(tp, 0x0B, 0xA908);
                rtl8125_ephy_write(tp, 0x22, 0x0023);
                rtl8125_ephy_write(tp, 0x1E, 0x28EB);

                rtl8125_ephy_write(tp, 0x4B, 0xA908);
                rtl8125_ephy_write(tp, 0x62, 0x0023);
                rtl8125_ephy_write(tp, 0x5E, 0x28EB);
                break;
        }
}

static u16
rtl8125_get_hw_phy_mcu_code_ver(struct rtl8125_private *tp)
{
        u16 hw_ram_code_ver = ~0;

        switch (tp->mcfg) {
        case CFG_METHOD_2:
        case CFG_METHOD_3:
        case CFG_METHOD_4:
        case CFG_METHOD_5:
                mdio_direct_write_phy_ocp(tp, 0xA436, 0x801E);
                hw_ram_code_ver = mdio_direct_read_phy_ocp(tp, 0xA438);
                break;
        }

        return hw_ram_code_ver;
}

static int
rtl8125_check_hw_phy_mcu_code_ver(struct net_device *dev)
{
        struct rtl8125_private *tp = netdev_priv(dev);
        int ram_code_ver_match = 0;

        tp->hw_ram_code_ver = rtl8125_get_hw_phy_mcu_code_ver(tp);

        if (tp->hw_ram_code_ver == tp->sw_ram_code_ver) {
                ram_code_ver_match = 1;
                tp->HwHasWrRamCodeToMicroP = TRUE;
        }

        return ram_code_ver_match;
}

static bool
rtl8125_wait_phy_mcu_patch_request_ready(struct rtl8125_private *tp)
{
        u16 gphy_val;
        u16 WaitCount;
        bool bSuccess = TRUE;

        WaitCount = 0;
        do {
                gphy_val = mdio_direct_read_phy_ocp(tp, 0xB800);
                gphy_val &= BIT_6;
                udelay(100);
                WaitCount++;
        } while(gphy_val != BIT_6 && WaitCount < 1000);

        if (gphy_val != BIT_6 && WaitCount == 1000) bSuccess = FALSE;

        if (!bSuccess)
                dprintk("rtl8125_wait_phy_mcu_patch_request_ready fail.\n");

        return bSuccess;
}

bool
rtl8125_set_phy_mcu_patch_request(struct rtl8125_private *tp)
{
        SetEthPhyOcpBit(tp, 0xB820, BIT_4);

        return rtl8125_wait_phy_mcu_patch_request_ready(tp);
}

bool
rtl8125_clear_phy_mcu_patch_request(struct rtl8125_private *tp)
{
        ClearEthPhyOcpBit(tp, 0xB820, BIT_4);

        return rtl8125_wait_phy_mcu_patch_request_ready(tp);
}

static void
rtl8125_enable_phy_aldps(struct rtl8125_private *tp)
{
        //enable aldps
        //GPHY OCP 0xA430 bit[2] = 0x1 (en_aldps)
        SetEthPhyOcpBit(tp, 0xA430, BIT_2);
}

static void
rtl8125_hw_phy_config_8125a_1(struct net_device *dev)
{
        struct rtl8125_private *tp = netdev_priv(dev);

        ClearAndSetEthPhyOcpBit(tp,
                                0xAD40,
                                0x03FF,
                                0x84
                               );

        SetEthPhyOcpBit(tp, 0xAD4E, BIT_4);
        ClearAndSetEthPhyOcpBit(tp,
                                0xAD16,
                                0x03FF,
                                0x0006
                               );
        ClearAndSetEthPhyOcpBit(tp,
                                0xAD32,
                                0x003F,
                                0x0006
                               );
        ClearEthPhyOcpBit(tp, 0xAC08, BIT_12);
        ClearEthPhyOcpBit(tp, 0xAC08, BIT_8);
        ClearAndSetEthPhyOcpBit(tp,
                                0xAC8A,
                                BIT_15|BIT_14|BIT_13|BIT_12,
                                BIT_14|BIT_13|BIT_12
                               );
        SetEthPhyOcpBit(tp, 0xAD18, BIT_10);
        SetEthPhyOcpBit(tp, 0xAD1A, 0x3FF);
        SetEthPhyOcpBit(tp, 0xAD1C, 0x3FF);

        mdio_direct_write_phy_ocp(tp, 0xA436, 0x80EA);
        ClearAndSetEthPhyOcpBit(tp,
                                0xA438,
                                0xFF00,
                                0xC400
                               );
        mdio_direct_write_phy_ocp(tp, 0xA436, 0x80EB);
        ClearAndSetEthPhyOcpBit(tp,
                                0xA438,
                                0x0700,
                                0x0300
                               );
        mdio_direct_write_phy_ocp(tp, 0xA436, 0x80F8);
        ClearAndSetEthPhyOcpBit(tp,
                                0xA438,
                                0xFF00,
                                0x1C00
                               );
        mdio_direct_write_phy_ocp(tp, 0xA436, 0x80F1);
        ClearAndSetEthPhyOcpBit(tp,
                                0xA438,
                                0xFF00,
                                0x3000
                               );

        mdio_direct_write_phy_ocp(tp, 0xA436, 0x80FE);
        ClearAndSetEthPhyOcpBit(tp,
                                0xA438,
                                0xFF00,
                                0xA500
                               );
        mdio_direct_write_phy_ocp(tp, 0xA436, 0x8102);
        ClearAndSetEthPhyOcpBit(tp,
                                0xA438,
                                0xFF00,
                                0x5000
                               );
        mdio_direct_write_phy_ocp(tp, 0xA436, 0x8105);
        ClearAndSetEthPhyOcpBit(tp,
                                0xA438,
                                0xFF00,
                                0x3300
                               );
        mdio_direct_write_phy_ocp(tp, 0xA436, 0x8100);
        ClearAndSetEthPhyOcpBit(tp,
                                0xA438,
                                0xFF00,
                                0x7000
                               );
        mdio_direct_write_phy_ocp(tp, 0xA436, 0x8104);
        ClearAndSetEthPhyOcpBit(tp,
                                0xA438,
                                0xFF00,
                                0xF000
                               );
        mdio_direct_write_phy_ocp(tp, 0xA436, 0x8106);
        ClearAndSetEthPhyOcpBit(tp,
                                0xA438,
                                0xFF00,
                                0x6500
                               );
        mdio_direct_write_phy_ocp(tp, 0xA436, 0x80DC);
        ClearAndSetEthPhyOcpBit(tp,
                                0xA438,
                                0xFF00,
                                0xED00
                               );
        mdio_direct_write_phy_ocp(tp, 0xA436, 0x80DF);
        SetEthPhyOcpBit(tp, 0xA438, BIT_8);
        mdio_direct_write_phy_ocp(tp, 0xA436, 0x80E1);
        ClearEthPhyOcpBit(tp, 0xA438, BIT_8);

        ClearAndSetEthPhyOcpBit(tp,
                                0xBF06,
                                0x003F,
                                0x38
                               );

        mdio_direct_write_phy_ocp(tp, 0xA436, 0x819F);
        mdio_direct_write_phy_ocp(tp, 0xA438, 0xD0B6);

        mdio_direct_write_phy_ocp(tp, 0xBC34, 0x5555);
        ClearAndSetEthPhyOcpBit(tp,
                                0xBF0A,
                                BIT_11|BIT_10|BIT_9,
                                BIT_11|BIT_9
                               );

        ClearEthPhyOcpBit(tp, 0xA5C0, BIT_10);

        SetEthPhyOcpBit(tp, 0xA442, BIT_11);

        //enable aldps
        //GPHY OCP 0xA430 bit[2] = 0x1 (en_aldps)
        if (aspm) {
                if (HW_HAS_WRITE_PHY_MCU_RAM_CODE(tp)) {
                        rtl8125_enable_phy_aldps(tp);
                }
        }
}

static void
rtl8125_hw_phy_config_8125a_2(struct net_device *dev)
{
        struct rtl8125_private *tp = netdev_priv(dev);

        SetEthPhyOcpBit(tp, 0xAD4E, BIT_4);
        ClearAndSetEthPhyOcpBit(tp,
                                0xAD16,
                                0x03FF,
                                0x03FF
                               );
        ClearAndSetEthPhyOcpBit(tp,
                                0xAD32,
                                0x003F,
                                0x0006
                               );
        ClearEthPhyOcpBit(tp, 0xAC08, BIT_12);
        ClearEthPhyOcpBit(tp, 0xAC08, BIT_8);
        ClearAndSetEthPhyOcpBit(tp,
                                0xACC0,
                                BIT_1|BIT_0,
                                BIT_1
                               );
        ClearAndSetEthPhyOcpBit(tp,
                                0xAD40,
                                BIT_7|BIT_6|BIT_5,
                                BIT_6
                               );
        ClearAndSetEthPhyOcpBit(tp,
                                0xAD40,
                                BIT_2|BIT_1|BIT_0,
                                BIT_2
                               );
        ClearEthPhyOcpBit(tp, 0xAC14, BIT_7);
        ClearEthPhyOcpBit(tp, 0xAC80, BIT_9|BIT_8);
        ClearAndSetEthPhyOcpBit(tp,
                                0xAC5E,
                                BIT_2|BIT_1|BIT_0,
                                BIT_1
                               );
        mdio_direct_write_phy_ocp(tp, 0xAD4C, 0x00A8);
        mdio_direct_write_phy_ocp(tp, 0xAC5C, 0x01FF);
        ClearAndSetEthPhyOcpBit(tp,
                                0xAC8A,
                                BIT_7|BIT_6|BIT_5|BIT_4,
                                BIT_5|BIT_4
                               );
        mdio_direct_write_phy_ocp(tp, 0xB87C, 0x8157);
        ClearAndSetEthPhyOcpBit(tp,
                                0xB87E,
                                0xFF00,
                                0x0500
                               );
        mdio_direct_write_phy_ocp(tp, 0xB87C, 0x8159);
        ClearAndSetEthPhyOcpBit(tp,
                                0xB87E,
                                0xFF00,
                                0x0700
                               );


        mdio_direct_write_phy_ocp(tp, 0xB87C, 0x80A2);
        mdio_direct_write_phy_ocp(tp, 0xB87E, 0x0153);
        mdio_direct_write_phy_ocp(tp, 0xB87C, 0x809C);
        mdio_direct_write_phy_ocp(tp, 0xB87E, 0x0153);


        mdio_direct_write_phy_ocp(tp, 0xA436, 0x81B3);
        mdio_direct_write_phy_ocp(tp, 0xA438, 0x0043);
        mdio_direct_write_phy_ocp(tp, 0xA438, 0x00A7);
        mdio_direct_write_phy_ocp(tp, 0xA438, 0x00D6);
        mdio_direct_write_phy_ocp(tp, 0xA438, 0x00EC);
        mdio_direct_write_phy_ocp(tp, 0xA438, 0x00F6);
        mdio_direct_write_phy_ocp(tp, 0xA438, 0x00FB);
        mdio_direct_write_phy_ocp(tp, 0xA438, 0x00FD);
        mdio_direct_write_phy_ocp(tp, 0xA438, 0x00FF);
        mdio_direct_write_phy_ocp(tp, 0xA438, 0x00BB);
        mdio_direct_write_phy_ocp(tp, 0xA438, 0x0058);
        mdio_direct_write_phy_ocp(tp, 0xA438, 0x0029);
        mdio_direct_write_phy_ocp(tp, 0xA438, 0x0013);
        mdio_direct_write_phy_ocp(tp, 0xA438, 0x0009);
        mdio_direct_write_phy_ocp(tp, 0xA438, 0x0004);
        mdio_direct_write_phy_ocp(tp, 0xA438, 0x0002);
        mdio_direct_write_phy_ocp(tp, 0xA438, 0x0000);
        mdio_direct_write_phy_ocp(tp, 0xA438, 0x0000);
        mdio_direct_write_phy_ocp(tp, 0xA438, 0x0000);
        mdio_direct_write_phy_ocp(tp, 0xA438, 0x0000);
        mdio_direct_write_phy_ocp(tp, 0xA438, 0x0000);
        mdio_direct_write_phy_ocp(tp, 0xA438, 0x0000);
        mdio_direct_write_phy_ocp(tp, 0xA438, 0x0000);
        mdio_direct_write_phy_ocp(tp, 0xA438, 0x0000);
        mdio_direct_write_phy_ocp(tp, 0xA438, 0x0000);
        mdio_direct_write_phy_ocp(tp, 0xA438, 0x0000);
        mdio_direct_write_phy_ocp(tp, 0xA438, 0x0000);
        mdio_direct_write_phy_ocp(tp, 0xA438, 0x0000);
        mdio_direct_write_phy_ocp(tp, 0xA438, 0x0000);
        mdio_direct_write_phy_ocp(tp, 0xA438, 0x0000);
        mdio_direct_write_phy_ocp(tp, 0xA438, 0x0000);
        mdio_direct_write_phy_ocp(tp, 0xA438, 0x0000);
        mdio_direct_write_phy_ocp(tp, 0xA438, 0x0000);
        mdio_direct_write_phy_ocp(tp, 0xA438, 0x0000);
        mdio_direct_write_phy_ocp(tp, 0xA438, 0x0000);
        mdio_direct_write_phy_ocp(tp, 0xA438, 0x0000);
        mdio_direct_write_phy_ocp(tp, 0xA438, 0x0000);
        mdio_direct_write_phy_ocp(tp, 0xA438, 0x0000);
        mdio_direct_write_phy_ocp(tp, 0xA438, 0x0000);
        mdio_direct_write_phy_ocp(tp, 0xA438, 0x0000);
        mdio_direct_write_phy_ocp(tp, 0xA438, 0x0000);


        mdio_direct_write_phy_ocp(tp, 0xA436, 0x8257);
        mdio_direct_write_phy_ocp(tp, 0xA438, 0x020F);


        mdio_direct_write_phy_ocp(tp, 0xA436, 0x80EA);
        mdio_direct_write_phy_ocp(tp, 0xA438, 0x7843);


        rtl8125_set_phy_mcu_patch_request(tp);

        ClearEthPhyOcpBit(tp, 0xB896, BIT_0);
        ClearEthPhyOcpBit(tp, 0xB892, 0xFF00);

        mdio_direct_write_phy_ocp(tp, 0xB88E, 0xC091);
        mdio_direct_write_phy_ocp(tp, 0xB890, 0x6E12);
        mdio_direct_write_phy_ocp(tp, 0xB88E, 0xC092);
        mdio_direct_write_phy_ocp(tp, 0xB890, 0x1214);
        mdio_direct_write_phy_ocp(tp, 0xB88E, 0xC094);
        mdio_direct_write_phy_ocp(tp, 0xB890, 0x1516);
        mdio_direct_write_phy_ocp(tp, 0xB88E, 0xC096);
        mdio_direct_write_phy_ocp(tp, 0xB890, 0x171B);
        mdio_direct_write_phy_ocp(tp, 0xB88E, 0xC098);
        mdio_direct_write_phy_ocp(tp, 0xB890, 0x1B1C);
        mdio_direct_write_phy_ocp(tp, 0xB88E, 0xC09A);
        mdio_direct_write_phy_ocp(tp, 0xB890, 0x1F1F);
        mdio_direct_write_phy_ocp(tp, 0xB88E, 0xC09C);
        mdio_direct_write_phy_ocp(tp, 0xB890, 0x2021);
        mdio_direct_write_phy_ocp(tp, 0xB88E, 0xC09E);
        mdio_direct_write_phy_ocp(tp, 0xB890, 0x2224);
        mdio_direct_write_phy_ocp(tp, 0xB88E, 0xC0A0);
        mdio_direct_write_phy_ocp(tp, 0xB890, 0x2424);
        mdio_direct_write_phy_ocp(tp, 0xB88E, 0xC0A2);
        mdio_direct_write_phy_ocp(tp, 0xB890, 0x2424);
        mdio_direct_write_phy_ocp(tp, 0xB88E, 0xC0A4);
        mdio_direct_write_phy_ocp(tp, 0xB890, 0x2424);
        mdio_direct_write_phy_ocp(tp, 0xB88E, 0xC018);
        mdio_direct_write_phy_ocp(tp, 0xB890, 0x0AF2);
        mdio_direct_write_phy_ocp(tp, 0xB88E, 0xC01A);
        mdio_direct_write_phy_ocp(tp, 0xB890, 0x0D4A);
        mdio_direct_write_phy_ocp(tp, 0xB88E, 0xC01C);
        mdio_direct_write_phy_ocp(tp, 0xB890, 0x0F26);
        mdio_direct_write_phy_ocp(tp, 0xB88E, 0xC01E);
        mdio_direct_write_phy_ocp(tp, 0xB890, 0x118D);
        mdio_direct_write_phy_ocp(tp, 0xB88E, 0xC020);
        mdio_direct_write_phy_ocp(tp, 0xB890, 0x14F3);
        mdio_direct_write_phy_ocp(tp, 0xB88E, 0xC022);
        mdio_direct_write_phy_ocp(tp, 0xB890, 0x175A);
        mdio_direct_write_phy_ocp(tp, 0xB88E, 0xC024);
        mdio_direct_write_phy_ocp(tp, 0xB890, 0x19C0);
        mdio_direct_write_phy_ocp(tp, 0xB88E, 0xC026);
        mdio_direct_write_phy_ocp(tp, 0xB890, 0x1C26);
        mdio_direct_write_phy_ocp(tp, 0xB88E, 0xC089);
        mdio_direct_write_phy_ocp(tp, 0xB890, 0x6050);
        mdio_direct_write_phy_ocp(tp, 0xB88E, 0xC08A);
        mdio_direct_write_phy_ocp(tp, 0xB890, 0x5F6E);
        mdio_direct_write_phy_ocp(tp, 0xB88E, 0xC08C);
        mdio_direct_write_phy_ocp(tp, 0xB890, 0x6E6E);
        mdio_direct_write_phy_ocp(tp, 0xB88E, 0xC08E);
        mdio_direct_write_phy_ocp(tp, 0xB890, 0x6E6E);
        mdio_direct_write_phy_ocp(tp, 0xB88E, 0xC090);
        mdio_direct_write_phy_ocp(tp, 0xB890, 0x6E12);

        SetEthPhyOcpBit(tp, 0xB896, BIT_0);

        rtl8125_clear_phy_mcu_patch_request(tp);


        SetEthPhyOcpBit(tp, 0xD068, BIT_13);


        mdio_direct_write_phy_ocp(tp, 0xA436, 0x81A2);
        SetEthPhyOcpBit(tp, 0xA438, BIT_8);
        ClearAndSetEthPhyOcpBit(tp,
                                0xB54C,
                                0xFF00,
                                0xDB00);


        ClearEthPhyOcpBit(tp, 0xA454, BIT_0);


        SetEthPhyOcpBit(tp, 0xA5D4, BIT_5);
        ClearEthPhyOcpBit(tp, 0xAD4E, BIT_4);
        ClearEthPhyOcpBit(tp, 0xA86A, BIT_0);


        SetEthPhyOcpBit(tp, 0xA442, BIT_11);


        if (tp->RequirePhyMdiSwapPatch) {
                u16 adccal_offset_p0;
                u16 adccal_offset_p1;
                u16 adccal_offset_p2;
                u16 adccal_offset_p3;
                u16 rg_lpf_cap_xg_p0;
                u16 rg_lpf_cap_xg_p1;
                u16 rg_lpf_cap_xg_p2;
                u16 rg_lpf_cap_xg_p3;
                u16 rg_lpf_cap_p0;
                u16 rg_lpf_cap_p1;
                u16 rg_lpf_cap_p2;
                u16 rg_lpf_cap_p3;

                ClearAndSetEthPhyOcpBit(tp,
                                        0xD068,
                                        0x0007,
                                        0x0001
                                       );
                ClearAndSetEthPhyOcpBit(tp,
                                        0xD068,
                                        0x0018,
                                        0x0000
                                       );
                adccal_offset_p0 = mdio_direct_read_phy_ocp(tp, 0xD06A);
                adccal_offset_p0 &= 0x07FF;
                ClearAndSetEthPhyOcpBit(tp,
                                        0xD068,
                                        0x0018,
                                        0x0008
                                       );
                adccal_offset_p1 = mdio_direct_read_phy_ocp(tp, 0xD06A);
                adccal_offset_p1 &= 0x07FF;
                ClearAndSetEthPhyOcpBit(tp,
                                        0xD068,
                                        0x0018,
                                        0x0010
                                       );
                adccal_offset_p2 = mdio_direct_read_phy_ocp(tp, 0xD06A);
                adccal_offset_p2 &= 0x07FF;
                ClearAndSetEthPhyOcpBit(tp,
                                        0xD068,
                                        0x0018,
                                        0x0018
                                       );
                adccal_offset_p3 = mdio_direct_read_phy_ocp(tp, 0xD06A);
                adccal_offset_p3 &= 0x07FF;


                ClearAndSetEthPhyOcpBit(tp,
                                        0xD068,
                                        0x0018,
                                        0x0000
                                       );
                ClearAndSetEthPhyOcpBit(tp,
                                        0xD06A,
                                        0x07FF,
                                        adccal_offset_p3
                                       );
                ClearAndSetEthPhyOcpBit(tp,
                                        0xD068,
                                        0x0018,
                                        0x0008
                                       );
                ClearAndSetEthPhyOcpBit(tp,
                                        0xD06A,
                                        0x07FF,
                                        adccal_offset_p2
                                       );
                ClearAndSetEthPhyOcpBit(tp,
                                        0xD068,
                                        0x0018,
                                        0x0010
                                       );
                ClearAndSetEthPhyOcpBit(tp,
                                        0xD06A,
                                        0x07FF,
                                        adccal_offset_p1
                                       );
                ClearAndSetEthPhyOcpBit(tp,
                                        0xD068,
                                        0x0018,
                                        0x0018
                                       );
                ClearAndSetEthPhyOcpBit(tp,
                                        0xD06A,
                                        0x07FF,
                                        adccal_offset_p0
                                       );


                rg_lpf_cap_xg_p0 = mdio_direct_read_phy_ocp(tp, 0xBD5A);
                rg_lpf_cap_xg_p0 &= 0x001F;
                rg_lpf_cap_xg_p1 = mdio_direct_read_phy_ocp(tp, 0xBD5A);
                rg_lpf_cap_xg_p1 &= 0x1F00;
                rg_lpf_cap_xg_p2 = mdio_direct_read_phy_ocp(tp, 0xBD5C);
                rg_lpf_cap_xg_p2 &= 0x001F;
                rg_lpf_cap_xg_p3 = mdio_direct_read_phy_ocp(tp, 0xBD5C);
                rg_lpf_cap_xg_p3 &= 0x1F00;
                rg_lpf_cap_p0 = mdio_direct_read_phy_ocp(tp, 0xBC18);
                rg_lpf_cap_p0 &= 0x001F;
                rg_lpf_cap_p1 = mdio_direct_read_phy_ocp(tp, 0xBC18);
                rg_lpf_cap_p1 &= 0x1F00;
                rg_lpf_cap_p2 = mdio_direct_read_phy_ocp(tp, 0xBC1A);
                rg_lpf_cap_p2 &= 0x001F;
                rg_lpf_cap_p3 = mdio_direct_read_phy_ocp(tp, 0xBC1A);
                rg_lpf_cap_p3 &= 0x1F00;


                ClearAndSetEthPhyOcpBit(tp,
                                        0xBD5A,
                                        0x001F,
                                        rg_lpf_cap_xg_p3 >> 8
                                       );
                ClearAndSetEthPhyOcpBit(tp,
                                        0xBD5A,
                                        0x1F00,
                                        rg_lpf_cap_xg_p2 << 8
                                       );
                ClearAndSetEthPhyOcpBit(tp,
                                        0xBD5C,
                                        0x001F,
                                        rg_lpf_cap_xg_p1 >> 8
                                       );
                ClearAndSetEthPhyOcpBit(tp,
                                        0xBD5C,
                                        0x1F00,
                                        rg_lpf_cap_xg_p0 << 8
                                       );
                ClearAndSetEthPhyOcpBit(tp,
                                        0xBC18,
                                        0x001F,
                                        rg_lpf_cap_p3 >> 8
                                       );
                ClearAndSetEthPhyOcpBit(tp,
                                        0xBC18,
                                        0x1F00,
                                        rg_lpf_cap_p2 << 8
                                       );
                ClearAndSetEthPhyOcpBit(tp,
                                        0xBC1A,
                                        0x001F,
                                        rg_lpf_cap_p1 >> 8
                                       );
                ClearAndSetEthPhyOcpBit(tp,
                                        0xBC1A,
                                        0x1F00,
                                        rg_lpf_cap_p0 << 8
                                       );
        }


        if (aspm) {
                if (HW_HAS_WRITE_PHY_MCU_RAM_CODE(tp)) {
                        rtl8125_enable_phy_aldps(tp);
                }
        }
}

static void
rtl8125_hw_phy_config_8125b_1(struct net_device *dev)
{
        struct rtl8125_private *tp = netdev_priv(dev);

        SetEthPhyOcpBit(tp, 0xA442, BIT_11);


        SetEthPhyOcpBit(tp, 0xBC08, (BIT_3 | BIT_2));


        if (HW_HAS_WRITE_PHY_MCU_RAM_CODE(tp)) {
                mdio_direct_write_phy_ocp(tp, 0xA436, 0x8FFF);
                ClearAndSetEthPhyOcpBit(tp,
                                        0xA438,
                                        0xFF00,
                                        0x0400
                                       );
        }
        mdio_direct_write_phy_ocp(tp, 0xB87C, 0x8560);
        mdio_direct_write_phy_ocp(tp, 0xB87E, 0x19CC);
        mdio_direct_write_phy_ocp(tp, 0xB87C, 0x8562);
        mdio_direct_write_phy_ocp(tp, 0xB87E, 0x19CC);
        mdio_direct_write_phy_ocp(tp, 0xB87C, 0x8564);
        mdio_direct_write_phy_ocp(tp, 0xB87E, 0x19CC);
        mdio_direct_write_phy_ocp(tp, 0xB87C, 0x8566);
        mdio_direct_write_phy_ocp(tp, 0xB87E, 0x147D);
        mdio_direct_write_phy_ocp(tp, 0xB87C, 0x8568);
        mdio_direct_write_phy_ocp(tp, 0xB87E, 0x147D);
        mdio_direct_write_phy_ocp(tp, 0xB87C, 0x856A);
        mdio_direct_write_phy_ocp(tp, 0xB87E, 0x147D);
        if (HW_HAS_WRITE_PHY_MCU_RAM_CODE(tp)) {
                mdio_direct_write_phy_ocp(tp, 0xB87C, 0x8FFE);
                mdio_direct_write_phy_ocp(tp, 0xB87E, 0x0907);
        }
        ClearAndSetEthPhyOcpBit(tp,
                                0xACDA,
                                0xFF00,
                                0xFF00
                               );
        ClearAndSetEthPhyOcpBit(tp,
                                0xACDE,
                                0xF000,
                                0xF000
                               );
        mdio_direct_write_phy_ocp(tp, 0xB87C, 0x80D6);
        mdio_direct_write_phy_ocp(tp, 0xB87E, 0x2801);
        mdio_direct_write_phy_ocp(tp, 0xB87C, 0x80F2);
        mdio_direct_write_phy_ocp(tp, 0xB87E, 0x2801);
        mdio_direct_write_phy_ocp(tp, 0xB87C, 0x80F4);
        mdio_direct_write_phy_ocp(tp, 0xB87E, 0x6077);
        mdio_direct_write_phy_ocp(tp, 0xB506, 0x01E7);
        mdio_direct_write_phy_ocp(tp, 0xAC8C, 0x0FFC);
        mdio_direct_write_phy_ocp(tp, 0xAC46, 0xB7B4);
        mdio_direct_write_phy_ocp(tp, 0xAC50, 0x0FBC);
        mdio_direct_write_phy_ocp(tp, 0xAC3C, 0x9240);
        mdio_direct_write_phy_ocp(tp, 0xAC4E, 0x0DB4);
        mdio_direct_write_phy_ocp(tp, 0xACC6, 0x0707);
        mdio_direct_write_phy_ocp(tp, 0xACC8, 0xA0D3);
        mdio_direct_write_phy_ocp(tp, 0xAD08, 0x0007);

        mdio_direct_write_phy_ocp(tp, 0xB87C, 0x8013);
        mdio_direct_write_phy_ocp(tp, 0xB87E, 0x0700);
        mdio_direct_write_phy_ocp(tp, 0xB87C, 0x8FB9);
        mdio_direct_write_phy_ocp(tp, 0xB87E, 0x2801);
        mdio_direct_write_phy_ocp(tp, 0xB87C, 0x8FBA);
        mdio_direct_write_phy_ocp(tp, 0xB87E, 0x0100);
        mdio_direct_write_phy_ocp(tp, 0xB87C, 0x8FBC);
        mdio_direct_write_phy_ocp(tp, 0xB87E, 0x1900);
        mdio_direct_write_phy_ocp(tp, 0xB87C, 0x8FBE);
        mdio_direct_write_phy_ocp(tp, 0xB87E, 0xE100);
        mdio_direct_write_phy_ocp(tp, 0xB87C, 0x8FC0);
        mdio_direct_write_phy_ocp(tp, 0xB87E, 0x0800);
        mdio_direct_write_phy_ocp(tp, 0xB87C, 0x8FC2);
        mdio_direct_write_phy_ocp(tp, 0xB87E, 0xE500);
        mdio_direct_write_phy_ocp(tp, 0xB87C, 0x8FC4);
        mdio_direct_write_phy_ocp(tp, 0xB87E, 0x0F00);
        mdio_direct_write_phy_ocp(tp, 0xB87C, 0x8FC6);
        mdio_direct_write_phy_ocp(tp, 0xB87E, 0xF100);
        mdio_direct_write_phy_ocp(tp, 0xB87C, 0x8FC8);
        mdio_direct_write_phy_ocp(tp, 0xB87E, 0x0400);
        mdio_direct_write_phy_ocp(tp, 0xB87C, 0x8FCa);
        mdio_direct_write_phy_ocp(tp, 0xB87E, 0xF300);
        mdio_direct_write_phy_ocp(tp, 0xB87C, 0x8FCc);
        mdio_direct_write_phy_ocp(tp, 0xB87E, 0xFD00);
        mdio_direct_write_phy_ocp(tp, 0xB87C, 0x8FCe);
        mdio_direct_write_phy_ocp(tp, 0xB87E, 0xFF00);
        mdio_direct_write_phy_ocp(tp, 0xB87C, 0x8FD0);
        mdio_direct_write_phy_ocp(tp, 0xB87E, 0xFB00);
        mdio_direct_write_phy_ocp(tp, 0xB87C, 0x8FD2);
        mdio_direct_write_phy_ocp(tp, 0xB87E, 0x0100);
        mdio_direct_write_phy_ocp(tp, 0xB87C, 0x8FD4);
        mdio_direct_write_phy_ocp(tp, 0xB87E, 0xF400);
        mdio_direct_write_phy_ocp(tp, 0xB87C, 0x8FD6);
        mdio_direct_write_phy_ocp(tp, 0xB87E, 0xFF00);
        mdio_direct_write_phy_ocp(tp, 0xB87C, 0x8FD8);
        mdio_direct_write_phy_ocp(tp, 0xB87E, 0xF600);


        mdio_direct_write_phy_ocp(tp, 0xB87C, 0x813D);
        mdio_direct_write_phy_ocp(tp, 0xB87E, 0x390E);
        mdio_direct_write_phy_ocp(tp, 0xB87C, 0x814F);
        mdio_direct_write_phy_ocp(tp, 0xB87E, 0x790E);
        mdio_direct_write_phy_ocp(tp, 0xB87C, 0x80B0);
        mdio_direct_write_phy_ocp(tp, 0xB87E, 0x0F31);
        SetEthPhyOcpBit(tp, 0xBF4C, BIT_1);
        SetEthPhyOcpBit(tp, 0xBCCA, (BIT_9 | BIT_8));
        mdio_direct_write_phy_ocp(tp, 0xB87C, 0x8141);
        mdio_direct_write_phy_ocp(tp, 0xB87E, 0x320E);
        mdio_direct_write_phy_ocp(tp, 0xB87C, 0x8153);
        mdio_direct_write_phy_ocp(tp, 0xB87E, 0x720E);
        ClearEthPhyOcpBit(tp, 0xA432, BIT_6);
        mdio_direct_write_phy_ocp(tp, 0xB87C, 0x8529);
        mdio_direct_write_phy_ocp(tp, 0xB87E, 0x050E);


        mdio_direct_write_phy_ocp(tp, 0xA436, 0x816C);
        mdio_direct_write_phy_ocp(tp, 0xA438, 0xC4A0);
        mdio_direct_write_phy_ocp(tp, 0xA436, 0x8170);
        mdio_direct_write_phy_ocp(tp, 0xA438, 0xC4A0);
        mdio_direct_write_phy_ocp(tp, 0xA436, 0x8174);
        mdio_direct_write_phy_ocp(tp, 0xA438, 0x04A0);
        mdio_direct_write_phy_ocp(tp, 0xA436, 0x8178);
        mdio_direct_write_phy_ocp(tp, 0xA438, 0x04A0);
        mdio_direct_write_phy_ocp(tp, 0xA436, 0x817C);
        mdio_direct_write_phy_ocp(tp, 0xA438, 0x0719);
        if (HW_HAS_WRITE_PHY_MCU_RAM_CODE(tp)) {
                mdio_direct_write_phy_ocp(tp, 0xA436, 0x8FF4);
                mdio_direct_write_phy_ocp(tp, 0xA438, 0x0400);
                mdio_direct_write_phy_ocp(tp, 0xA436, 0x8FF1);
                mdio_direct_write_phy_ocp(tp, 0xA438, 0x0404);
        }
        mdio_direct_write_phy_ocp(tp, 0xBF4A, 0x001B);
        mdio_direct_write_phy_ocp(tp, 0xB87C, 0x8033);
        mdio_direct_write_phy_ocp(tp, 0xB87E, 0x7C13);
        mdio_direct_write_phy_ocp(tp, 0xB87C, 0x8037);
        mdio_direct_write_phy_ocp(tp, 0xB87E, 0x7C13);
        mdio_direct_write_phy_ocp(tp, 0xB87C, 0x803B);
        mdio_direct_write_phy_ocp(tp, 0xB87E, 0xFC32);
        mdio_direct_write_phy_ocp(tp, 0xB87C, 0x803F);
        mdio_direct_write_phy_ocp(tp, 0xB87E, 0x7C13);
        mdio_direct_write_phy_ocp(tp, 0xB87C, 0x8043);
        mdio_direct_write_phy_ocp(tp, 0xB87E, 0x7C13);
        mdio_direct_write_phy_ocp(tp, 0xB87C, 0x8047);
        mdio_direct_write_phy_ocp(tp, 0xB87E, 0x7C13);


        mdio_direct_write_phy_ocp(tp, 0xB87C, 0x8145);
        mdio_direct_write_phy_ocp(tp, 0xB87E, 0x370E);
        mdio_direct_write_phy_ocp(tp, 0xB87C, 0x8157);
        mdio_direct_write_phy_ocp(tp, 0xB87E, 0x770E);
        mdio_direct_write_phy_ocp(tp, 0xB87C, 0x8169);
        mdio_direct_write_phy_ocp(tp, 0xB87E, 0x0D0A);
        mdio_direct_write_phy_ocp(tp, 0xB87C, 0x817B);
        mdio_direct_write_phy_ocp(tp, 0xB87E, 0x1D0A);


        mdio_direct_write_phy_ocp(tp, 0xA436, 0x8217);
        ClearAndSetEthPhyOcpBit(tp,
                                0xA438,
                                0xFF00,
                                0x5000
                               );
        mdio_direct_write_phy_ocp(tp, 0xA436, 0x821A);
        ClearAndSetEthPhyOcpBit(tp,
                                0xA438,
                                0xFF00,
                                0x5000
                               );

        mdio_direct_write_phy_ocp(tp, 0xA436, 0x80DA);
        mdio_direct_write_phy_ocp(tp, 0xA438, 0x0403);
        mdio_direct_write_phy_ocp(tp, 0xA436, 0x80DC);
        ClearAndSetEthPhyOcpBit(tp,
                                0xA438,
                                0xFF00,
                                0x1000
                               );
        mdio_direct_write_phy_ocp(tp, 0xA436, 0x80B3);
        mdio_direct_write_phy_ocp(tp, 0xA438, 0x0384);
        mdio_direct_write_phy_ocp(tp, 0xA436, 0x80B7);
        mdio_direct_write_phy_ocp(tp, 0xA438, 0x2007);
        mdio_direct_write_phy_ocp(tp, 0xA436, 0x80BA);
        ClearAndSetEthPhyOcpBit(tp,
                                0xA438,
                                0xFF00,
                                0x6C00
                               );
        mdio_direct_write_phy_ocp(tp, 0xA436, 0x80B5);
        mdio_direct_write_phy_ocp(tp, 0xA438, 0xF009);
        mdio_direct_write_phy_ocp(tp, 0xA436, 0x80BD);
        ClearAndSetEthPhyOcpBit(tp,
                                0xA438,
                                0xFF00,
                                0x9F00
                               );

        mdio_direct_write_phy_ocp(tp, 0xA436, 0x80C7);
        mdio_direct_write_phy_ocp(tp, 0xA438, 0xf083);
        mdio_direct_write_phy_ocp(tp, 0xA436, 0x80DD);
        mdio_direct_write_phy_ocp(tp, 0xA438, 0x03f0);
        mdio_direct_write_phy_ocp(tp, 0xA436, 0x80DF);
        ClearAndSetEthPhyOcpBit(tp,
                                0xA438,
                                0xFF00,
                                0x1000
                               );
        mdio_direct_write_phy_ocp(tp, 0xA436, 0x80CB);
        mdio_direct_write_phy_ocp(tp, 0xA438, 0x2007);
        mdio_direct_write_phy_ocp(tp, 0xA436, 0x80CE);
        ClearAndSetEthPhyOcpBit(tp,
                                0xA438,
                                0xFF00,
                                0x6C00
                               );
        mdio_direct_write_phy_ocp(tp, 0xA436, 0x80C9);
        mdio_direct_write_phy_ocp(tp, 0xA438, 0x8009);
        mdio_direct_write_phy_ocp(tp, 0xA436, 0x80D1);
        ClearAndSetEthPhyOcpBit(tp,
                                0xA438,
                                0xFF00,
                                0x8000
                               );

        mdio_direct_write_phy_ocp(tp, 0xA436, 0x80A3);
        mdio_direct_write_phy_ocp(tp, 0xA438, 0x200A);
        mdio_direct_write_phy_ocp(tp, 0xA436, 0x80A5);
        mdio_direct_write_phy_ocp(tp, 0xA438, 0xF0AD);
        mdio_direct_write_phy_ocp(tp, 0xA436, 0x809F);
        mdio_direct_write_phy_ocp(tp, 0xA438, 0x6073);
        mdio_direct_write_phy_ocp(tp, 0xA436, 0x80A1);
        mdio_direct_write_phy_ocp(tp, 0xA438, 0x000B);
        mdio_direct_write_phy_ocp(tp, 0xA436, 0x80A9);
        ClearAndSetEthPhyOcpBit(tp,
                                0xA438,
                                0xFF00,
                                0xC000
                               );

        rtl8125_set_phy_mcu_patch_request(tp);

        ClearEthPhyOcpBit(tp, 0xB896, BIT_0);
        ClearEthPhyOcpBit(tp, 0xB892, 0xFF00);

        mdio_direct_write_phy_ocp(tp, 0xB88E, 0xC23E);
        mdio_direct_write_phy_ocp(tp, 0xB890, 0x0000);
        mdio_direct_write_phy_ocp(tp, 0xB88E, 0xC240);
        mdio_direct_write_phy_ocp(tp, 0xB890, 0x0103);
        mdio_direct_write_phy_ocp(tp, 0xB88E, 0xC242);
        mdio_direct_write_phy_ocp(tp, 0xB890, 0x0507);
        mdio_direct_write_phy_ocp(tp, 0xB88E, 0xC244);
        mdio_direct_write_phy_ocp(tp, 0xB890, 0x090B);
        mdio_direct_write_phy_ocp(tp, 0xB88E, 0xC246);
        mdio_direct_write_phy_ocp(tp, 0xB890, 0x0C0E);
        mdio_direct_write_phy_ocp(tp, 0xB88E, 0xC248);
        mdio_direct_write_phy_ocp(tp, 0xB890, 0x1012);
        mdio_direct_write_phy_ocp(tp, 0xB88E, 0xC24A);
        mdio_direct_write_phy_ocp(tp, 0xB890, 0x1416);

        SetEthPhyOcpBit(tp, 0xB896, BIT_0);

        rtl8125_clear_phy_mcu_patch_request(tp);


        SetEthPhyOcpBit(tp, 0xA86A, BIT_0);
        SetEthPhyOcpBit(tp, 0xA6F0, BIT_0);


        mdio_direct_write_phy_ocp(tp, 0xBFA0, 0xD70D);
        mdio_direct_write_phy_ocp(tp, 0xBFA2, 0x4100);
        mdio_direct_write_phy_ocp(tp, 0xBFA4, 0xE868);
        mdio_direct_write_phy_ocp(tp, 0xBFA6, 0xDC59);
        mdio_direct_write_phy_ocp(tp, 0xB54C, 0x3C18);
        ClearEthPhyOcpBit(tp, 0xBFA4, BIT_5);
        mdio_direct_write_phy_ocp(tp, 0xA436, 0x817D);
        SetEthPhyOcpBit(tp, 0xA438, BIT_12);


        if (aspm) {
                if (HW_HAS_WRITE_PHY_MCU_RAM_CODE(tp)) {
                        rtl8125_enable_phy_aldps(tp);
                }
        }
}

static void
rtl8125_hw_phy_config_8125b_2(struct net_device *dev)
{
        struct rtl8125_private *tp = netdev_priv(dev);

        SetEthPhyOcpBit(tp, 0xA442, BIT_11);


        ClearAndSetEthPhyOcpBit(tp,
                                0xAC46,
                                0x00F0,
                                0x0090
                               );
        ClearAndSetEthPhyOcpBit(tp,
                                0xAD30,
                                0x0003,
                                0x0001
                               );


        RTL_W16(tp, EEE_TXIDLE_TIMER_8125, tp->eee.tx_lpi_timer);

        mdio_direct_write_phy_ocp(tp, 0xB87C, 0x80F5);
        mdio_direct_write_phy_ocp(tp, 0xB87E, 0x760E);
        mdio_direct_write_phy_ocp(tp, 0xB87C, 0x8107);
        mdio_direct_write_phy_ocp(tp, 0xB87E, 0x360E);
        mdio_direct_write_phy_ocp(tp, 0xB87C, 0x8551);
        ClearAndSetEthPhyOcpBit(tp,
                                0xB87E,
                                BIT_15 | BIT_14 | BIT_13 | BIT_12 | BIT_11 | BIT_10 | BIT_9 | BIT_8,
                                BIT_11
                               );

        ClearAndSetEthPhyOcpBit(tp,
                                0xbf00,
                                0xE000,
                                0xA000
                               );
        ClearAndSetEthPhyOcpBit(tp,
                                0xbf46,
                                0x0F00,
                                0x0300
                               );
        mdio_direct_write_phy_ocp(tp, 0xa436, 0x8044);
        mdio_direct_write_phy_ocp(tp, 0xa438, 0x2417);
        mdio_direct_write_phy_ocp(tp, 0xa436, 0x804A);
        mdio_direct_write_phy_ocp(tp, 0xa438, 0x2417);
        mdio_direct_write_phy_ocp(tp, 0xa436, 0x8050);
        mdio_direct_write_phy_ocp(tp, 0xa438, 0x2417);
        mdio_direct_write_phy_ocp(tp, 0xa436, 0x8056);
        mdio_direct_write_phy_ocp(tp, 0xa438, 0x2417);
        mdio_direct_write_phy_ocp(tp, 0xa436, 0x805C);
        mdio_direct_write_phy_ocp(tp, 0xa438, 0x2417);
        mdio_direct_write_phy_ocp(tp, 0xa436, 0x8062);
        mdio_direct_write_phy_ocp(tp, 0xa438, 0x2417);
        mdio_direct_write_phy_ocp(tp, 0xa436, 0x8068);
        mdio_direct_write_phy_ocp(tp, 0xa438, 0x2417);
        mdio_direct_write_phy_ocp(tp, 0xa436, 0x806E);
        mdio_direct_write_phy_ocp(tp, 0xa438, 0x2417);
        mdio_direct_write_phy_ocp(tp, 0xa436, 0x8074);
        mdio_direct_write_phy_ocp(tp, 0xa438, 0x2417);
        mdio_direct_write_phy_ocp(tp, 0xa436, 0x807A);
        mdio_direct_write_phy_ocp(tp, 0xa438, 0x2417);


        SetEthPhyOcpBit(tp, 0xA4CA, BIT_6);


        ClearAndSetEthPhyOcpBit(tp,
                                0xBF84,
                                BIT_15 | BIT_14 | BIT_13,
                                BIT_15 | BIT_13
                               );


        mdio_direct_write_phy_ocp(tp, 0xA436, 0x8170);
        ClearAndSetEthPhyOcpBit(tp,
                                0xA438,
                                BIT_13 | BIT_10 | BIT_9 | BIT_8,
                                BIT_15 | BIT_14 | BIT_12 | BIT_11
                               );

        /*
        mdio_direct_write_phy_ocp(tp, 0xBFA0, 0xD70D);
        mdio_direct_write_phy_ocp(tp, 0xBFA2, 0x4100);
        mdio_direct_write_phy_ocp(tp, 0xBFA4, 0xE868);
        mdio_direct_write_phy_ocp(tp, 0xBFA6, 0xDC59);
        mdio_direct_write_phy_ocp(tp, 0xB54C, 0x3C18);
        ClearEthPhyOcpBit(tp, 0xBFA4, BIT_5);
        mdio_direct_write_phy_ocp(tp, 0xA436, 0x817D);
        SetEthPhyOcpBit(tp, 0xA438, BIT_12);
        */


        if (aspm) {
                if (HW_HAS_WRITE_PHY_MCU_RAM_CODE(tp)) {
                        rtl8125_enable_phy_aldps(tp);
                }
        }
}

static void
rtl8125_hw_phy_config(struct net_device *dev)
{
        struct rtl8125_private *tp = netdev_priv(dev);

        if (tp->resume_not_chg_speed) return;

        tp->phy_reset_enable(dev);

        if (HW_DASH_SUPPORT_TYPE_3(tp) && tp->HwPkgDet == 0x06) return;

        switch (tp->mcfg) {
        case CFG_METHOD_2:
                rtl8125_hw_phy_config_8125a_1(dev);
                break;
        case CFG_METHOD_3:
                rtl8125_hw_phy_config_8125a_2(dev);
                break;
        case CFG_METHOD_4:
                rtl8125_hw_phy_config_8125b_1(dev);
                break;
        case CFG_METHOD_5:
                rtl8125_hw_phy_config_8125b_2(dev);
                break;
        }

        //legacy force mode(Chap 22)
        switch (tp->mcfg) {
        case CFG_METHOD_2:
        case CFG_METHOD_3:
        case CFG_METHOD_4:
        case CFG_METHOD_5:
        default:
                rtl8125_mdio_write(tp, 0x1F, 0x0A5B);
                rtl8125_clear_eth_phy_bit(tp, 0x12, BIT_15);
                rtl8125_mdio_write(tp, 0x1F, 0x0000);
                break;
        }

        /*ocp phy power saving*/
        /*
        if (aspm) {
        if (tp->mcfg == CFG_METHOD_2 || tp->mcfg == CFG_METHOD_3)
                rtl8125_enable_ocp_phy_power_saving(dev);
        }
        */

        rtl8125_mdio_write(tp, 0x1F, 0x0000);

        if (HW_HAS_WRITE_PHY_MCU_RAM_CODE(tp)) {
                if (tp->eee.eee_enabled)
                        rtl8125_enable_eee(tp);
                else
                        rtl8125_disable_eee(tp);
        }
}

static void
rtl8125_up(struct net_device *dev)
{
        rtl8125_hw_init(dev);
        rtl8125_hw_reset(dev);
        rtl8125_powerup_pll(dev);
        rtl8125_hw_ephy_config(dev);
        rtl8125_hw_phy_config(dev);
        rtl8125_hw_config(dev);
}

static inline void rtl8125_delete_esd_timer(struct net_device *dev, struct timer_list *timer)
{
        del_timer_sync(timer);
}

static inline void rtl8125_request_esd_timer(struct net_device *dev)
{
        struct rtl8125_private *tp = netdev_priv(dev);
        struct timer_list *timer = &tp->esd_timer;
#if LINUX_VERSION_CODE < KERNEL_VERSION(4,14,0)
        setup_timer(timer, rtl8125_esd_timer, (unsigned long)dev);
#else
        timer_setup(timer, rtl8125_esd_timer, 0);
#endif
        mod_timer(timer, jiffies + RTL8125_ESD_TIMEOUT);
}

/*
static inline void rtl8125_delete_link_timer(struct net_device *dev, struct timer_list *timer)
{
        del_timer_sync(timer);
}

static inline void rtl8125_request_link_timer(struct net_device *dev)
{
        struct rtl8125_private *tp = netdev_priv(dev);
        struct timer_list *timer = &tp->link_timer;

#if LINUX_VERSION_CODE < KERNEL_VERSION(4,14,0)
        setup_timer(timer, rtl8125_link_timer, (unsigned long)dev);
#else
        timer_setup(timer, rtl8125_link_timer, 0);
#endif
        mod_timer(timer, jiffies + RTL8125_LINK_TIMEOUT);
}
*/

#ifdef CONFIG_NET_POLL_CONTROLLER
/*
 * Polling 'interrupt' - used by things like netconsole to send skbs
 * without having to re-enable interrupts. It's not called while
 * the interrupt routine is executing.
 */
static void
rtl8125_netpoll(struct net_device *dev)
{
        struct rtl8125_private *tp = netdev_priv(dev);
        int i;
        for (i = 0; i < tp->irq_nvecs; i++) {
                struct r8125_irq *irq = &tp->irq_tbl[i];
                struct r8125_napi *r8125napi = &tp->r8125napi[i];

                disable_irq(irq->vector);

#if LINUX_VERSION_CODE >= KERNEL_VERSION(4,12,0)
                irq->handler(irq->vector, r8125napi);
#elif LINUX_VERSION_CODE < KERNEL_VERSION(2,6,19)
                irq->handler(irq->vector, r8125napi, NULL);
#else
                irq->handler(irq->vector, r8125napi);
#endif

                enable_irq(irq->vector);
        }
}
#endif //CONFIG_NET_POLL_CONTROLLER

static void
rtl8125_get_bios_setting(struct net_device *dev)
{
        struct rtl8125_private *tp = netdev_priv(dev);

        switch (tp->mcfg) {
        case CFG_METHOD_2:
        case CFG_METHOD_3:
        case CFG_METHOD_4:
        case CFG_METHOD_5:
                tp->bios_setting = RTL_R32(tp, TimeInt2);
                break;
        }
}

static void
rtl8125_set_bios_setting(struct net_device *dev)
{
        struct rtl8125_private *tp = netdev_priv(dev);

        switch (tp->mcfg) {
        case CFG_METHOD_2:
        case CFG_METHOD_3:
        case CFG_METHOD_4:
        case CFG_METHOD_5:
                RTL_W32(tp, TimeInt2, tp->bios_setting);
                break;
        }
}

static void
rtl8125_setup_mqs_reg(struct rtl8125_private *tp)
{
        int i;

        //tx
        tp->tx_ring[0].tdsar_reg = TxDescStartAddrLow;
        for (i = 1; i < R8125_MAX_TX_QUEUES; i++) {
                tp->tx_ring[i].tdsar_reg =  (u16)(TNPDS_Q1_LOW_8125 + (i - 1) * 8);
        }

        for (i = 0; i < R8125_MAX_TX_QUEUES; i++) {
                tp->tx_ring[i].hw_clo_ptr_reg =  (u16)(HW_CLO_PTR0_8125 + i * 4);
                tp->tx_ring[i].sw_tail_ptr_reg =  (u16)(SW_TAIL_PTR0_8125 + i * 4);
        }

        //rx
        tp->rx_ring[0].rdsar_reg = RxDescAddrLow;
        for (i = 1; i < R8125_MAX_RX_QUEUES; i++) {
                tp->rx_ring[i].rdsar_reg =  (u16)(RDSAR_Q1_LOW_8125 + (i - 1) * 8);
        }

        tp->isr_reg[0] = ISR0_8125;
        for (i = 1; i < R8125_MAX_QUEUES; i++) {
                tp->isr_reg[i] =  (u16)(ISR1_8125 + (i - 1) * 4);
        }

        tp->imr_reg[0] = IMR0_8125;
        for (i = 1; i < R8125_MAX_QUEUES; i++) {
                tp->imr_reg[i] =  (u16)(IMR1_8125 + (i - 1) * 4);
        }
}

static void
rtl8125_init_software_variable(struct net_device *dev)
{
        struct rtl8125_private *tp = netdev_priv(dev);
        struct pci_dev *pdev = tp->pci_dev;

        rtl8125_get_bios_setting(dev);

#ifdef ENABLE_LIB_SUPPORT
        tp->ring_lib_enabled = 1;
#endif

        switch (tp->mcfg) {
        case CFG_METHOD_2:
        case CFG_METHOD_3:
        case CFG_METHOD_4:
        case CFG_METHOD_5:
                //tp->HwSuppDashVer = 3;
                break;
        default:
                tp->HwSuppDashVer = 0;
                break;
        }

        switch (tp->mcfg) {
        case CFG_METHOD_2:
        case CFG_METHOD_3:
        case CFG_METHOD_4:
        case CFG_METHOD_5:
                tp->HwPkgDet = rtl8125_mac_ocp_read(tp, 0xDC00);
                tp->HwPkgDet = (tp->HwPkgDet >> 3) & 0x07;
                break;
        }

        if (HW_DASH_SUPPORT_TYPE_3(tp) && tp->HwPkgDet == 0x06)
                eee_enable = 0;

        switch (tp->mcfg) {
        case CFG_METHOD_2:
        case CFG_METHOD_3:
        case CFG_METHOD_4:
        case CFG_METHOD_5:
                tp->HwSuppNowIsOobVer = 1;
                break;
        }

        switch (tp->mcfg) {
        case CFG_METHOD_2:
        case CFG_METHOD_3:
        case CFG_METHOD_4:
        case CFG_METHOD_5:
                tp->HwPcieSNOffset = 0x16C;
                break;
        }

#ifdef ENABLE_REALWOW_SUPPORT
        rtl8125_get_realwow_hw_version(dev);
#endif //ENABLE_REALWOW_SUPPORT

        if (HW_DASH_SUPPORT_DASH(tp) && rtl8125_check_dash(tp))
                tp->DASH = 1;
        else
                tp->DASH = 0;

        if (tp->DASH) {
                if (HW_DASH_SUPPORT_TYPE_3(tp)) {
                        u64 CmacMemPhysAddress;
                        void __iomem *cmac_ioaddr = NULL;

                        //map CMAC IO space
                        CmacMemPhysAddress = rtl8125_csi_other_fun_read(tp, 0, 0x18);
                        if (!(CmacMemPhysAddress & BIT_0)) {
                                if (CmacMemPhysAddress & BIT_2)
                                        CmacMemPhysAddress |=  (u64)rtl8125_csi_other_fun_read(tp, 0, 0x1C) << 32;

                                CmacMemPhysAddress &=  0xFFFFFFF0;
                                /* ioremap MMIO region */
                                cmac_ioaddr = ioremap(CmacMemPhysAddress, R8125_REGS_SIZE);
                        }

                        if (cmac_ioaddr == NULL) {
#if LINUX_VERSION_CODE > KERNEL_VERSION(2,6,0)
                                if (netif_msg_probe(tp))
                                        dev_err(&pdev->dev, "cannot remap CMAC MMIO, aborting\n");
#endif //LINUX_VERSION_CODE > KERNEL_VERSION(2,6,0)
                        }

                        if (cmac_ioaddr == NULL) {
                                tp->DASH = 0;
                        } else {
                                tp->mapped_cmac_ioaddr = cmac_ioaddr;
                        }
                }

                eee_enable = 0;
        }

        if	(HW_DASH_SUPPORT_TYPE_3(tp))
                tp->cmac_ioaddr = tp->mapped_cmac_ioaddr;

        if (aspm) {
                switch (tp->mcfg) {
                case CFG_METHOD_2:
                case CFG_METHOD_3:
                case CFG_METHOD_4:
                case CFG_METHOD_5:
                        tp->org_pci_offset_99 = rtl8125_csi_fun0_read_byte(tp, 0x99);
                        tp->org_pci_offset_99 &= ~(BIT_5|BIT_6);
                        break;
                }

                switch (tp->mcfg) {
                case CFG_METHOD_2:
                case CFG_METHOD_3:
                        tp->org_pci_offset_180 = rtl8125_csi_fun0_read_byte(tp, 0x264);
                        break;
                case CFG_METHOD_4:
                case CFG_METHOD_5:
                        tp->org_pci_offset_180 = rtl8125_csi_fun0_read_byte(tp, 0x214);
                        break;
                }
        }

        pci_read_config_byte(pdev, 0x80, &tp->org_pci_offset_80);
        pci_read_config_byte(pdev, 0x81, &tp->org_pci_offset_81);

        switch (tp->mcfg) {
        case CFG_METHOD_2:
        case CFG_METHOD_3:
        case CFG_METHOD_4:
        case CFG_METHOD_5:
        default:
                tp->use_timer_interrrupt = TRUE;
                break;
        }

        if (timer_count == 0 || tp->mcfg == CFG_METHOD_DEFAULT)
                tp->use_timer_interrrupt = FALSE;

        switch (tp->mcfg) {
        case CFG_METHOD_2:
        case CFG_METHOD_3:
        case CFG_METHOD_4:
        case CFG_METHOD_5:
                tp->HwSuppMagicPktVer = WAKEUP_MAGIC_PACKET_V3;
                break;
        default:
                tp->HwSuppMagicPktVer = WAKEUP_MAGIC_PACKET_NOT_SUPPORT;
                break;
        }

        switch (tp->mcfg) {
        case CFG_METHOD_2:
        case CFG_METHOD_3:
        case CFG_METHOD_4:
        case CFG_METHOD_5:
                tp->HwSuppLinkChgWakeUpVer = 3;
                break;
        }

        switch (tp->mcfg) {
        case CFG_METHOD_3:
        case CFG_METHOD_4:
        case CFG_METHOD_5:
                tp->HwSuppD0SpeedUpVer = 1;
                break;
        }

        switch (tp->mcfg) {
        case CFG_METHOD_2:
        case CFG_METHOD_3:
        case CFG_METHOD_4:
        case CFG_METHOD_5:
                tp->HwSuppCheckPhyDisableModeVer = 3;
                break;
        }

        switch (tp->mcfg) {
        case CFG_METHOD_2:
        case CFG_METHOD_3:
        case CFG_METHOD_4:
        case CFG_METHOD_5:
                tp->HwSuppTxNoCloseVer = 3;
                break;
        }

        if (tp->HwSuppTxNoCloseVer > 0 && tx_no_close_enable == 1)
                tp->EnableTxNoClose = TRUE;

        switch (tp->mcfg) {
        case CFG_METHOD_2:
        case CFG_METHOD_3:
                tp->RequireLSOPatch = TRUE;
                break;
        }

        switch (tp->mcfg) {
        case CFG_METHOD_2:
                tp->sw_ram_code_ver = NIC_RAMCODE_VERSION_CFG_METHOD_2;
                break;
        case CFG_METHOD_3:
                tp->sw_ram_code_ver = NIC_RAMCODE_VERSION_CFG_METHOD_3;
                break;
        case CFG_METHOD_4:
                tp->sw_ram_code_ver = NIC_RAMCODE_VERSION_CFG_METHOD_4;
                break;
        case CFG_METHOD_5:
                tp->sw_ram_code_ver = NIC_RAMCODE_VERSION_CFG_METHOD_5;
                break;
        }

        if (tp->HwIcVerUnknown) {
                tp->NotWrRamCodeToMicroP = TRUE;
                tp->NotWrMcuPatchCode = TRUE;
        }

        switch (tp->mcfg) {
        case CFG_METHOD_3:
                if ((rtl8125_mac_ocp_read(tp, 0xD442) & BIT_5) &&
                    (mdio_direct_read_phy_ocp(tp, 0xD068) & BIT_1)
                   ) {
                        tp->RequirePhyMdiSwapPatch = TRUE;
                }
                break;
        }

        switch (tp->mcfg) {
        case CFG_METHOD_4:
        case CFG_METHOD_5:
                tp->HwSuppNumTxQueues = 2;
                tp->HwSuppNumRxQueues = 4;
                break;
        default:
                tp->HwSuppNumTxQueues = 1;
                tp->HwSuppNumRxQueues = 1;
                break;
        }

        tp->num_tx_rings = 1;
#ifdef ENABLE_MULTIPLE_TX_QUEUE
#ifndef ENABLE_LIB_SUPPORT
        tp->num_tx_rings = tp->HwSuppNumTxQueues;
#endif
#endif

        switch (tp->mcfg) {
        case CFG_METHOD_4:
        case CFG_METHOD_5:
                tp->HwSuppRssVer = 5;
                tp->HwSuppIndirTblEntries = 128;
                break;
        }

        tp->num_rx_rings = 1;
#ifdef ENABLE_RSS_SUPPORT
#ifdef ENABLE_LIB_SUPPORT
        if (tp->HwSuppRssVer > 0)
                tp->EnableRss = 1;
#else
        if (tp->HwSuppRssVer > 0) {
                u8 rss_queue_num = netif_get_num_default_rss_queues();
                tp->num_rx_rings = (tp->HwSuppNumRxQueues > rss_queue_num)?
                                   rss_queue_num : tp->HwSuppNumRxQueues;

                if (!(tp->num_rx_rings >= 2 && tp->irq_nvecs >= tp->num_rx_rings))
                        tp->num_rx_rings = 1;

                if (tp->num_rx_rings >= 2)
                        tp->EnableRss = 1;
        }
#endif
        if (tp->EnableRss)
                rtl8125_init_rss(tp);
#endif

        rtl8125_setup_mqs_reg(tp);

        switch (tp->mcfg) {
        case CFG_METHOD_4:
        case CFG_METHOD_5:
                tp->HwSuppPtpVer = 1;
                break;
        }
#ifdef ENABLE_PTP_SUPPORT
        if (tp->HwSuppPtpVer > 0)
                tp->EnablePtp = 1;
#endif

        tp->InitRxDescType = RX_DESC_RING_TYPE_1;
        if (tp->EnableRss || tp->EnablePtp)
                tp->InitRxDescType = RX_DESC_RING_TYPE_3;

        tp->RxDescLength = RX_DESC_LEN_TYPE_1;
        if (tp->InitRxDescType == RX_DESC_RING_TYPE_3)
                tp->RxDescLength = RX_DESC_LEN_TYPE_3;
        tp->RxDescRingLength = NUM_RX_DESC * tp->RxDescLength;

        tp->rtl8125_rx_config = rtl_chip_info[tp->chipset].RCR_Cfg;
        if (tp->InitRxDescType == RX_DESC_RING_TYPE_3)
                tp->rtl8125_rx_config |= EnableRxDescV3;

        //init interrupt
        switch (tp->mcfg) {
        case CFG_METHOD_4:
        case CFG_METHOD_5:
                tp->HwSuppIsrVer = 2;
                break;
        default:
                tp->HwSuppIsrVer = 1;
                break;
        }

        tp->HwCurrIsrVer = tp->HwSuppIsrVer;
        if (tp->HwSuppIsrVer == 2 && !(tp->features & RTL_FEATURE_MSIX))
                tp->HwCurrIsrVer = 1;

        if (tp->HwCurrIsrVer < 2 || tp->irq_nvecs < 19)
                tp->num_tx_rings = 1;

        if (tp->HwCurrIsrVer == 2) {
                int i;

                tp->intr_mask = ISRIMR_V2_LINKCHG | ISRIMR_TOK_Q0;
                if (tp->num_tx_rings > 1)
                        tp->intr_mask |= ISRIMR_TOK_Q1;

                for (i = 0; i < tp->num_rx_rings; i++)
                        tp->intr_mask |= ISRIMR_V2_ROK_Q0 << i;
        } else {
                tp->intr_mask = LinkChg | RxDescUnavail | TxOK | RxOK | SWInt;
                tp->timer_intr_mask = LinkChg | PCSTimeout;

#ifdef ENABLE_DASH_SUPPORT
                if (tp->DASH) {
                        if (HW_DASH_SUPPORT_TYPE_3(tp)) {
                                tp->timer_intr_mask |= ( ISRIMR_DASH_INTR_EN | ISRIMR_DASH_INTR_CMAC_RESET);
                                tp->intr_mask |= ( ISRIMR_DASH_INTR_EN | ISRIMR_DASH_INTR_CMAC_RESET);
                        }
                }
#endif
        }

        switch (tp->mcfg) {
        case CFG_METHOD_2:
        case CFG_METHOD_3:
                tp->HwSuppIntMitiVer = 3;
                break;
        case CFG_METHOD_4:
        case CFG_METHOD_5:
                tp->HwSuppIntMitiVer = 4;
                break;
        }

        timer_count_v2 = (timer_count / 0x100);

        tp->NicCustLedValue = RTL_R16(tp, CustomLED);

        tp->wol_opts = rtl8125_get_hw_wol(tp);
        tp->wol_enabled = (tp->wol_opts) ? WOL_ENABLED : WOL_DISABLED;

        rtl8125_link_option((u8*)&autoneg_mode, (u32*)&speed_mode, (u8*)&duplex_mode, (u32*)&advertising_mode);

        tp->autoneg = autoneg_mode;
        tp->speed = speed_mode;
        tp->duplex = duplex_mode;
        tp->advertising = advertising_mode;
        tp->fcpause = rtl8125_fc_full;

        tp->max_jumbo_frame_size = rtl_chip_info[tp->chipset].jumbo_frame_sz;
#if LINUX_VERSION_CODE >= KERNEL_VERSION(4,10,0)
        /* MTU range: 60 - hw-specific max */
        dev->min_mtu = ETH_MIN_MTU;
        dev->max_mtu = tp->max_jumbo_frame_size;
#endif //LINUX_VERSION_CODE >= KERNEL_VERSION(4,10,0)

        if (tp->mcfg != CFG_METHOD_DEFAULT) {
                struct ethtool_eee *eee = &tp->eee;

                eee->eee_enabled = eee_enable;
                eee->supported  = SUPPORTED_100baseT_Full |
                                  SUPPORTED_1000baseT_Full;
                switch (tp->mcfg) {
                case CFG_METHOD_4:
                case CFG_METHOD_5:
                        eee->supported |= SUPPORTED_2500baseX_Full;
                        break;
                }
                eee->advertised = mmd_eee_adv_to_ethtool_adv_t(MDIO_EEE_1000T | MDIO_EEE_100TX);
                eee->tx_lpi_timer = dev->mtu + ETH_HLEN + 0x20;
        }

        tp->ptp_master_mode = enable_ptp_master_mode;
}

static void
rtl8125_release_board(struct pci_dev *pdev,
                      struct net_device *dev)
{
        struct rtl8125_private *tp = netdev_priv(dev);
        void __iomem *ioaddr = tp->mmio_addr;

        rtl8125_set_bios_setting(dev);
        rtl8125_rar_set(tp, tp->org_mac_addr);
        tp->wol_enabled = WOL_DISABLED;

        if (!tp->DASH)
                rtl8125_phy_power_down(dev);

#ifdef ENABLE_DASH_SUPPORT
        if (tp->DASH)
                FreeAllocatedDashShareMemory(dev);
#endif

        if (tp->mapped_cmac_ioaddr != NULL)
                iounmap(tp->mapped_cmac_ioaddr);

        iounmap(ioaddr);
        pci_release_regions(pdev);
        pci_clear_mwi(pdev);
        pci_disable_device(pdev);
        free_netdev(dev);
}

static int
rtl8125_get_mac_address(struct net_device *dev)
{
        struct rtl8125_private *tp = netdev_priv(dev);
        int i;
        u8 mac_addr[MAC_ADDR_LEN];

        for (i = 0; i < MAC_ADDR_LEN; i++)
                mac_addr[i] = RTL_R8(tp, MAC0 + i);

        if(tp->mcfg == CFG_METHOD_2 ||
            tp->mcfg == CFG_METHOD_3 ||
            tp->mcfg == CFG_METHOD_4 ||
            tp->mcfg == CFG_METHOD_5) {
                *(u32*)&mac_addr[0] = RTL_R32(tp, BACKUP_ADDR0_8125);
                *(u16*)&mac_addr[4] = RTL_R16(tp, BACKUP_ADDR1_8125);
        }

        if (!is_valid_ether_addr(mac_addr)) {
                netif_err(tp, probe, dev, "Invalid ether addr %pM\n",
                          mac_addr);
                eth_hw_addr_random(dev);
                ether_addr_copy(mac_addr, dev->dev_addr);
                netif_info(tp, probe, dev, "Random ether addr %pM\n",
                           mac_addr);
                tp->random_mac = 1;
        }

        rtl8125_rar_set(tp, mac_addr);

        for (i = 0; i < MAC_ADDR_LEN; i++) {
                dev->dev_addr[i] = RTL_R8(tp, MAC0 + i);
                tp->org_mac_addr[i] = dev->dev_addr[i]; /* keep the original MAC address */
        }
#if LINUX_VERSION_CODE > KERNEL_VERSION(2,6,13)
        memcpy(dev->perm_addr, dev->dev_addr, dev->addr_len);
#endif
//  memcpy(dev->dev_addr, dev->dev_addr, dev->addr_len);

        return 0;
}

/**
 * rtl8125_set_mac_address - Change the Ethernet Address of the NIC
 * @dev: network interface device structure
 * @p:   pointer to an address structure
 *
 * Return 0 on success, negative on failure
 **/
static int
rtl8125_set_mac_address(struct net_device *dev,
                        void *p)
{
        struct rtl8125_private *tp = netdev_priv(dev);
        struct sockaddr *addr = p;
        unsigned long flags;

        if (!is_valid_ether_addr(addr->sa_data))
                return -EADDRNOTAVAIL;

        spin_lock_irqsave(&tp->lock, flags);

        memcpy(dev->dev_addr, addr->sa_data, dev->addr_len);

        rtl8125_rar_set(tp, dev->dev_addr);

        spin_unlock_irqrestore(&tp->lock, flags);

        return 0;
}

/******************************************************************************
 * rtl8125_rar_set - Puts an ethernet address into a receive address register.
 *
 * tp - The private data structure for driver
 * addr - Address to put into receive address register
 *****************************************************************************/
void
rtl8125_rar_set(struct rtl8125_private *tp,
                uint8_t *addr)
{
        uint32_t rar_low = 0;
        uint32_t rar_high = 0;

        rar_low = ((uint32_t) addr[0] |
                   ((uint32_t) addr[1] << 8) |
                   ((uint32_t) addr[2] << 16) |
                   ((uint32_t) addr[3] << 24));

        rar_high = ((uint32_t) addr[4] |
                    ((uint32_t) addr[5] << 8));

        rtl8125_enable_cfg9346_write(tp);
        RTL_W32(tp, MAC0, rar_low);
        RTL_W32(tp, MAC4, rar_high);

        rtl8125_disable_cfg9346_write(tp);
}

#ifdef ETHTOOL_OPS_COMPAT
static int ethtool_get_settings(struct net_device *dev, void *useraddr)
{
        struct ethtool_cmd cmd = { ETHTOOL_GSET };
        int err;

        if (!ethtool_ops->get_settings)
                return -EOPNOTSUPP;

        err = ethtool_ops->get_settings(dev, &cmd);
        if (err < 0)
                return err;

        if (copy_to_user(useraddr, &cmd, sizeof(cmd)))
                return -EFAULT;
        return 0;
}

static int ethtool_set_settings(struct net_device *dev, void *useraddr)
{
        struct ethtool_cmd cmd;

        if (!ethtool_ops->set_settings)
                return -EOPNOTSUPP;

        if (copy_from_user(&cmd, useraddr, sizeof(cmd)))
                return -EFAULT;

        return ethtool_ops->set_settings(dev, &cmd);
}

static int ethtool_get_drvinfo(struct net_device *dev, void *useraddr)
{
        struct ethtool_drvinfo info;
        struct ethtool_ops *ops = ethtool_ops;

        if (!ops->get_drvinfo)
                return -EOPNOTSUPP;

        memset(&info, 0, sizeof(info));
        info.cmd = ETHTOOL_GDRVINFO;
        ops->get_drvinfo(dev, &info);

        if (ops->self_test_count)
                info.testinfo_len = ops->self_test_count(dev);
        if (ops->get_stats_count)
                info.n_stats = ops->get_stats_count(dev);
        if (ops->get_regs_len)
                info.regdump_len = ops->get_regs_len(dev);
        if (ops->get_eeprom_len)
                info.eedump_len = ops->get_eeprom_len(dev);

        if (copy_to_user(useraddr, &info, sizeof(info)))
                return -EFAULT;
        return 0;
}

static int ethtool_get_regs(struct net_device *dev, char *useraddr)
{
        struct ethtool_regs regs;
        struct ethtool_ops *ops = ethtool_ops;
        void *regbuf;
        int reglen, ret;

        if (!ops->get_regs || !ops->get_regs_len)
                return -EOPNOTSUPP;

        if (copy_from_user(&regs, useraddr, sizeof(regs)))
                return -EFAULT;

        reglen = ops->get_regs_len(dev);
        if (regs.len > reglen)
                regs.len = reglen;

        regbuf = kmalloc(reglen, GFP_USER);
        if (!regbuf)
                return -ENOMEM;

        ops->get_regs(dev, &regs, regbuf);

        ret = -EFAULT;
        if (copy_to_user(useraddr, &regs, sizeof(regs)))
                goto out;
        useraddr += offsetof(struct ethtool_regs, data);
        if (copy_to_user(useraddr, regbuf, reglen))
                goto out;
        ret = 0;

out:
        kfree(regbuf);
        return ret;
}

static int ethtool_get_wol(struct net_device *dev, char *useraddr)
{
        struct ethtool_wolinfo wol = { ETHTOOL_GWOL };

        if (!ethtool_ops->get_wol)
                return -EOPNOTSUPP;

        ethtool_ops->get_wol(dev, &wol);

        if (copy_to_user(useraddr, &wol, sizeof(wol)))
                return -EFAULT;
        return 0;
}

static int ethtool_set_wol(struct net_device *dev, char *useraddr)
{
        struct ethtool_wolinfo wol;

        if (!ethtool_ops->set_wol)
                return -EOPNOTSUPP;

        if (copy_from_user(&wol, useraddr, sizeof(wol)))
                return -EFAULT;

        return ethtool_ops->set_wol(dev, &wol);
}

static int ethtool_get_msglevel(struct net_device *dev, char *useraddr)
{
        struct ethtool_value edata = { ETHTOOL_GMSGLVL };

        if (!ethtool_ops->get_msglevel)
                return -EOPNOTSUPP;

        edata.data = ethtool_ops->get_msglevel(dev);

        if (copy_to_user(useraddr, &edata, sizeof(edata)))
                return -EFAULT;
        return 0;
}

static int ethtool_set_msglevel(struct net_device *dev, char *useraddr)
{
        struct ethtool_value edata;

        if (!ethtool_ops->set_msglevel)
                return -EOPNOTSUPP;

        if (copy_from_user(&edata, useraddr, sizeof(edata)))
                return -EFAULT;

        ethtool_ops->set_msglevel(dev, edata.data);
        return 0;
}

static int ethtool_nway_reset(struct net_device *dev)
{
        if (!ethtool_ops->nway_reset)
                return -EOPNOTSUPP;

        return ethtool_ops->nway_reset(dev);
}

static int ethtool_get_link(struct net_device *dev, void *useraddr)
{
        struct ethtool_value edata = { ETHTOOL_GLINK };

        if (!ethtool_ops->get_link)
                return -EOPNOTSUPP;

        edata.data = ethtool_ops->get_link(dev);

        if (copy_to_user(useraddr, &edata, sizeof(edata)))
                return -EFAULT;
        return 0;
}

static int ethtool_get_eeprom(struct net_device *dev, void *useraddr)
{
        struct ethtool_eeprom eeprom;
        struct ethtool_ops *ops = ethtool_ops;
        u8 *data;
        int ret;

        if (!ops->get_eeprom || !ops->get_eeprom_len)
                return -EOPNOTSUPP;

        if (copy_from_user(&eeprom, useraddr, sizeof(eeprom)))
                return -EFAULT;

        /* Check for wrap and zero */
        if (eeprom.offset + eeprom.len <= eeprom.offset)
                return -EINVAL;

        /* Check for exceeding total eeprom len */
        if (eeprom.offset + eeprom.len > ops->get_eeprom_len(dev))
                return -EINVAL;

        data = kmalloc(eeprom.len, GFP_USER);
        if (!data)
                return -ENOMEM;

        ret = -EFAULT;
        if (copy_from_user(data, useraddr + sizeof(eeprom), eeprom.len))
                goto out;

        ret = ops->get_eeprom(dev, &eeprom, data);
        if (ret)
                goto out;

        ret = -EFAULT;
        if (copy_to_user(useraddr, &eeprom, sizeof(eeprom)))
                goto out;
        if (copy_to_user(useraddr + sizeof(eeprom), data, eeprom.len))
                goto out;
        ret = 0;

out:
        kfree(data);
        return ret;
}

static int ethtool_set_eeprom(struct net_device *dev, void *useraddr)
{
        struct ethtool_eeprom eeprom;
        struct ethtool_ops *ops = ethtool_ops;
        u8 *data;
        int ret;

        if (!ops->set_eeprom || !ops->get_eeprom_len)
                return -EOPNOTSUPP;

        if (copy_from_user(&eeprom, useraddr, sizeof(eeprom)))
                return -EFAULT;

        /* Check for wrap and zero */
        if (eeprom.offset + eeprom.len <= eeprom.offset)
                return -EINVAL;

        /* Check for exceeding total eeprom len */
        if (eeprom.offset + eeprom.len > ops->get_eeprom_len(dev))
                return -EINVAL;

        data = kmalloc(eeprom.len, GFP_USER);
        if (!data)
                return -ENOMEM;

        ret = -EFAULT;
        if (copy_from_user(data, useraddr + sizeof(eeprom), eeprom.len))
                goto out;

        ret = ops->set_eeprom(dev, &eeprom, data);
        if (ret)
                goto out;

        if (copy_to_user(useraddr + sizeof(eeprom), data, eeprom.len))
                ret = -EFAULT;

out:
        kfree(data);
        return ret;
}

static int ethtool_get_coalesce(struct net_device *dev, void *useraddr)
{
        struct ethtool_coalesce coalesce = { ETHTOOL_GCOALESCE };

        if (!ethtool_ops->get_coalesce)
                return -EOPNOTSUPP;

        ethtool_ops->get_coalesce(dev, &coalesce);

        if (copy_to_user(useraddr, &coalesce, sizeof(coalesce)))
                return -EFAULT;
        return 0;
}

static int ethtool_set_coalesce(struct net_device *dev, void *useraddr)
{
        struct ethtool_coalesce coalesce;

        if (!ethtool_ops->get_coalesce)
                return -EOPNOTSUPP;

        if (copy_from_user(&coalesce, useraddr, sizeof(coalesce)))
                return -EFAULT;

        return ethtool_ops->set_coalesce(dev, &coalesce);
}

static int ethtool_get_ringparam(struct net_device *dev, void *useraddr)
{
        struct ethtool_ringparam ringparam = { ETHTOOL_GRINGPARAM };

        if (!ethtool_ops->get_ringparam)
                return -EOPNOTSUPP;

        ethtool_ops->get_ringparam(dev, &ringparam);

        if (copy_to_user(useraddr, &ringparam, sizeof(ringparam)))
                return -EFAULT;
        return 0;
}

static int ethtool_set_ringparam(struct net_device *dev, void *useraddr)
{
        struct ethtool_ringparam ringparam;

        if (!ethtool_ops->get_ringparam)
                return -EOPNOTSUPP;

        if (copy_from_user(&ringparam, useraddr, sizeof(ringparam)))
                return -EFAULT;

        return ethtool_ops->set_ringparam(dev, &ringparam);
}

static int ethtool_get_pauseparam(struct net_device *dev, void *useraddr)
{
        struct ethtool_pauseparam pauseparam = { ETHTOOL_GPAUSEPARAM };

        if (!ethtool_ops->get_pauseparam)
                return -EOPNOTSUPP;

        ethtool_ops->get_pauseparam(dev, &pauseparam);

        if (copy_to_user(useraddr, &pauseparam, sizeof(pauseparam)))
                return -EFAULT;
        return 0;
}

static int ethtool_set_pauseparam(struct net_device *dev, void *useraddr)
{
        struct ethtool_pauseparam pauseparam;

        if (!ethtool_ops->get_pauseparam)
                return -EOPNOTSUPP;

        if (copy_from_user(&pauseparam, useraddr, sizeof(pauseparam)))
                return -EFAULT;

        return ethtool_ops->set_pauseparam(dev, &pauseparam);
}

static int ethtool_get_rx_csum(struct net_device *dev, char *useraddr)
{
        struct ethtool_value edata = { ETHTOOL_GRXCSUM };

        if (!ethtool_ops->get_rx_csum)
                return -EOPNOTSUPP;

        edata.data = ethtool_ops->get_rx_csum(dev);

        if (copy_to_user(useraddr, &edata, sizeof(edata)))
                return -EFAULT;
        return 0;
}

static int ethtool_set_rx_csum(struct net_device *dev, char *useraddr)
{
        struct ethtool_value edata;

        if (!ethtool_ops->set_rx_csum)
                return -EOPNOTSUPP;

        if (copy_from_user(&edata, useraddr, sizeof(edata)))
                return -EFAULT;

        ethtool_ops->set_rx_csum(dev, edata.data);
        return 0;
}

static int ethtool_get_tx_csum(struct net_device *dev, char *useraddr)
{
        struct ethtool_value edata = { ETHTOOL_GTXCSUM };

        if (!ethtool_ops->get_tx_csum)
                return -EOPNOTSUPP;

        edata.data = ethtool_ops->get_tx_csum(dev);

        if (copy_to_user(useraddr, &edata, sizeof(edata)))
                return -EFAULT;
        return 0;
}

static int ethtool_set_tx_csum(struct net_device *dev, char *useraddr)
{
        struct ethtool_value edata;

        if (!ethtool_ops->set_tx_csum)
                return -EOPNOTSUPP;

        if (copy_from_user(&edata, useraddr, sizeof(edata)))
                return -EFAULT;

        return ethtool_ops->set_tx_csum(dev, edata.data);
}

static int ethtool_get_sg(struct net_device *dev, char *useraddr)
{
        struct ethtool_value edata = { ETHTOOL_GSG };

        if (!ethtool_ops->get_sg)
                return -EOPNOTSUPP;

        edata.data = ethtool_ops->get_sg(dev);

        if (copy_to_user(useraddr, &edata, sizeof(edata)))
                return -EFAULT;
        return 0;
}

static int ethtool_set_sg(struct net_device *dev, char *useraddr)
{
        struct ethtool_value edata;

        if (!ethtool_ops->set_sg)
                return -EOPNOTSUPP;

        if (copy_from_user(&edata, useraddr, sizeof(edata)))
                return -EFAULT;

        return ethtool_ops->set_sg(dev, edata.data);
}

static int ethtool_get_tso(struct net_device *dev, char *useraddr)
{
        struct ethtool_value edata = { ETHTOOL_GTSO };

        if (!ethtool_ops->get_tso)
                return -EOPNOTSUPP;

        edata.data = ethtool_ops->get_tso(dev);

        if (copy_to_user(useraddr, &edata, sizeof(edata)))
                return -EFAULT;
        return 0;
}

static int ethtool_set_tso(struct net_device *dev, char *useraddr)
{
        struct ethtool_value edata;

        if (!ethtool_ops->set_tso)
                return -EOPNOTSUPP;

        if (copy_from_user(&edata, useraddr, sizeof(edata)))
                return -EFAULT;

        return ethtool_ops->set_tso(dev, edata.data);
}

static int ethtool_self_test(struct net_device *dev, char *useraddr)
{
        struct ethtool_test test;
        struct ethtool_ops *ops = ethtool_ops;
        u64 *data;
        int ret;

        if (!ops->self_test || !ops->self_test_count)
                return -EOPNOTSUPP;

        if (copy_from_user(&test, useraddr, sizeof(test)))
                return -EFAULT;

        test.len = ops->self_test_count(dev);
        data = kmalloc(test.len * sizeof(u64), GFP_USER);
        if (!data)
                return -ENOMEM;

        ops->self_test(dev, &test, data);

        ret = -EFAULT;
        if (copy_to_user(useraddr, &test, sizeof(test)))
                goto out;
        useraddr += sizeof(test);
        if (copy_to_user(useraddr, data, test.len * sizeof(u64)))
                goto out;
        ret = 0;

out:
        kfree(data);
        return ret;
}

static int ethtool_get_strings(struct net_device *dev, void *useraddr)
{
        struct ethtool_gstrings gstrings;
        struct ethtool_ops *ops = ethtool_ops;
        u8 *data;
        int ret;

        if (!ops->get_strings)
                return -EOPNOTSUPP;

        if (copy_from_user(&gstrings, useraddr, sizeof(gstrings)))
                return -EFAULT;

        switch (gstrings.string_set) {
        case ETH_SS_TEST:
                if (!ops->self_test_count)
                        return -EOPNOTSUPP;
                gstrings.len = ops->self_test_count(dev);
                break;
        case ETH_SS_STATS:
                if (!ops->get_stats_count)
                        return -EOPNOTSUPP;
                gstrings.len = ops->get_stats_count(dev);
                break;
        default:
                return -EINVAL;
        }

        data = kmalloc(gstrings.len * ETH_GSTRING_LEN, GFP_USER);
        if (!data)
                return -ENOMEM;

        ops->get_strings(dev, gstrings.string_set, data);

        ret = -EFAULT;
        if (copy_to_user(useraddr, &gstrings, sizeof(gstrings)))
                goto out;
        useraddr += sizeof(gstrings);
        if (copy_to_user(useraddr, data, gstrings.len * ETH_GSTRING_LEN))
                goto out;
        ret = 0;

out:
        kfree(data);
        return ret;
}

static int ethtool_phys_id(struct net_device *dev, void *useraddr)
{
        struct ethtool_value id;

        if (!ethtool_ops->phys_id)
                return -EOPNOTSUPP;

        if (copy_from_user(&id, useraddr, sizeof(id)))
                return -EFAULT;

        return ethtool_ops->phys_id(dev, id.data);
}

static int ethtool_get_stats(struct net_device *dev, void *useraddr)
{
        struct ethtool_stats stats;
        struct ethtool_ops *ops = ethtool_ops;
        u64 *data;
        int ret;

        if (!ops->get_ethtool_stats || !ops->get_stats_count)
                return -EOPNOTSUPP;

        if (copy_from_user(&stats, useraddr, sizeof(stats)))
                return -EFAULT;

        stats.n_stats = ops->get_stats_count(dev);
        data = kmalloc(stats.n_stats * sizeof(u64), GFP_USER);
        if (!data)
                return -ENOMEM;

        ops->get_ethtool_stats(dev, &stats, data);

        ret = -EFAULT;
        if (copy_to_user(useraddr, &stats, sizeof(stats)))
                goto out;
        useraddr += sizeof(stats);
        if (copy_to_user(useraddr, data, stats.n_stats * sizeof(u64)))
                goto out;
        ret = 0;

out:
        kfree(data);
        return ret;
}

static int ethtool_ioctl(struct ifreq *ifr)
{
        struct net_device *dev = __dev_get_by_name(ifr->ifr_name);
        void *useraddr = (void *) ifr->ifr_data;
        u32 ethcmd;

        /*
         * XXX: This can be pushed down into the ethtool_* handlers that
         * need it.  Keep existing behaviour for the moment.
         */
        if (!capable(CAP_NET_ADMIN))
                return -EPERM;

        if (!dev || !netif_device_present(dev))
                return -ENODEV;

        if (copy_from_user(&ethcmd, useraddr, sizeof (ethcmd)))
                return -EFAULT;

        switch (ethcmd) {
        case ETHTOOL_GSET:
                return ethtool_get_settings(dev, useraddr);
        case ETHTOOL_SSET:
                return ethtool_set_settings(dev, useraddr);
        case ETHTOOL_GDRVINFO:
                return ethtool_get_drvinfo(dev, useraddr);
        case ETHTOOL_GREGS:
                return ethtool_get_regs(dev, useraddr);
        case ETHTOOL_GWOL:
                return ethtool_get_wol(dev, useraddr);
        case ETHTOOL_SWOL:
                return ethtool_set_wol(dev, useraddr);
        case ETHTOOL_GMSGLVL:
                return ethtool_get_msglevel(dev, useraddr);
        case ETHTOOL_SMSGLVL:
                return ethtool_set_msglevel(dev, useraddr);
        case ETHTOOL_NWAY_RST:
                return ethtool_nway_reset(dev);
        case ETHTOOL_GLINK:
                return ethtool_get_link(dev, useraddr);
        case ETHTOOL_GEEPROM:
                return ethtool_get_eeprom(dev, useraddr);
        case ETHTOOL_SEEPROM:
                return ethtool_set_eeprom(dev, useraddr);
        case ETHTOOL_GCOALESCE:
                return ethtool_get_coalesce(dev, useraddr);
        case ETHTOOL_SCOALESCE:
                return ethtool_set_coalesce(dev, useraddr);
        case ETHTOOL_GRINGPARAM:
                return ethtool_get_ringparam(dev, useraddr);
        case ETHTOOL_SRINGPARAM:
                return ethtool_set_ringparam(dev, useraddr);
        case ETHTOOL_GPAUSEPARAM:
                return ethtool_get_pauseparam(dev, useraddr);
        case ETHTOOL_SPAUSEPARAM:
                return ethtool_set_pauseparam(dev, useraddr);
        case ETHTOOL_GRXCSUM:
                return ethtool_get_rx_csum(dev, useraddr);
        case ETHTOOL_SRXCSUM:
                return ethtool_set_rx_csum(dev, useraddr);
        case ETHTOOL_GTXCSUM:
                return ethtool_get_tx_csum(dev, useraddr);
        case ETHTOOL_STXCSUM:
                return ethtool_set_tx_csum(dev, useraddr);
        case ETHTOOL_GSG:
                return ethtool_get_sg(dev, useraddr);
        case ETHTOOL_SSG:
                return ethtool_set_sg(dev, useraddr);
        case ETHTOOL_GTSO:
                return ethtool_get_tso(dev, useraddr);
        case ETHTOOL_STSO:
                return ethtool_set_tso(dev, useraddr);
        case ETHTOOL_TEST:
                return ethtool_self_test(dev, useraddr);
        case ETHTOOL_GSTRINGS:
                return ethtool_get_strings(dev, useraddr);
        case ETHTOOL_PHYS_ID:
                return ethtool_phys_id(dev, useraddr);
        case ETHTOOL_GSTATS:
                return ethtool_get_stats(dev, useraddr);
        default:
                return -EOPNOTSUPP;
        }

        return -EOPNOTSUPP;
}
#endif //ETHTOOL_OPS_COMPAT

static int
rtl8125_do_ioctl(struct net_device *dev,
                 struct ifreq *ifr,
                 int cmd)
{
        struct rtl8125_private *tp = netdev_priv(dev);
        struct mii_ioctl_data *data = if_mii(ifr);
        int ret;
        unsigned long flags;

        ret = 0;
        switch (cmd) {
        case SIOCGMIIPHY:
                data->phy_id = 32; /* Internal PHY */
                break;

        case SIOCGMIIREG:
                spin_lock_irqsave(&tp->lock, flags);
                rtl8125_mdio_write(tp, 0x1F, 0x0000);
                data->val_out = rtl8125_mdio_read(tp, data->reg_num);
                spin_unlock_irqrestore(&tp->lock, flags);
                break;

        case SIOCSMIIREG:
                if (!capable(CAP_NET_ADMIN))
                        return -EPERM;
                spin_lock_irqsave(&tp->lock, flags);
                rtl8125_mdio_write(tp, 0x1F, 0x0000);
                rtl8125_mdio_write(tp, data->reg_num, data->val_in);
                spin_unlock_irqrestore(&tp->lock, flags);
                break;

#ifdef ETHTOOL_OPS_COMPAT
        case SIOCETHTOOL:
                ret = ethtool_ioctl(ifr);
                break;
#endif

#ifdef ENABLE_DASH_SUPPORT
        case SIOCDEVPRIVATE_RTLDASH:
                if (!netif_running(dev)) {
                        ret = -ENODEV;
                        break;
                }
                if (!capable(CAP_NET_ADMIN)) {
                        ret = -EPERM;
                        break;
                }

                ret = rtl8125_dash_ioctl(dev, ifr);
                break;
#endif

#ifdef ENABLE_REALWOW_SUPPORT
        case SIOCDEVPRIVATE_RTLREALWOW:
                if (!netif_running(dev)) {
                        ret = -ENODEV;
                        break;
                }

                ret = rtl8125_realwow_ioctl(dev, ifr);
                break;
#endif

#ifdef ENABLE_PTP_SUPPORT
        case SIOCSHWTSTAMP:
        case SIOCGHWTSTAMP:
                if (tp->EnablePtp)
                        ret = rtl8125_ptp_ioctl(dev, ifr, cmd);
                else
                        ret = -EOPNOTSUPP;
                break;
#endif
        case SIOCRTLTOOL:
                ret = rtl8125_tool_ioctl(tp, ifr);
                break;

        default:
                ret = -EOPNOTSUPP;
                break;
        }

        return ret;
}

static void
rtl8125_phy_power_up(struct net_device *dev)
{
        struct rtl8125_private *tp = netdev_priv(dev);

        if (rtl8125_is_in_phy_disable_mode(dev)) {
                return;
        }

        rtl8125_mdio_write(tp, 0x1F, 0x0000);
        rtl8125_mdio_write(tp, MII_BMCR, BMCR_ANENABLE);

        //wait ups resume (phy state 3)
        switch (tp->mcfg) {
        case CFG_METHOD_2:
        case CFG_METHOD_3:
        case CFG_METHOD_4:
        case CFG_METHOD_5:
                rtl8125_wait_phy_ups_resume(dev, 3);
                break;
        };
}

static void
rtl8125_phy_power_down(struct net_device *dev)
{
        struct rtl8125_private *tp = netdev_priv(dev);

        rtl8125_mdio_write(tp, 0x1F, 0x0000);
        rtl8125_mdio_write(tp, MII_BMCR, BMCR_ANENABLE | BMCR_PDOWN);
}

static int __devinit
rtl8125_init_board(struct pci_dev *pdev,
                   struct net_device **dev_out,
                   void __iomem **ioaddr_out)
{
        void __iomem *ioaddr;
        struct net_device *dev;
        struct rtl8125_private *tp;
        int rc = -ENOMEM, i, pm_cap;

        assert(ioaddr_out != NULL);

        /* dev zeroed in alloc_etherdev */
        dev = alloc_etherdev_mq(sizeof (*tp), R8125_MAX_QUEUES);
        if (dev == NULL) {
#if LINUX_VERSION_CODE > KERNEL_VERSION(2,6,0)
                if (netif_msg_drv(&debug))
                        dev_err(&pdev->dev, "unable to alloc new ethernet\n");
#endif //LINUX_VERSION_CODE > KERNEL_VERSION(2,6,0)
                goto err_out;
        }

        SET_MODULE_OWNER(dev);
        SET_NETDEV_DEV(dev, &pdev->dev);
        tp = netdev_priv(dev);
        tp->dev = dev;
        tp->pci_dev = pdev;
        tp->msg_enable = netif_msg_init(debug.msg_enable, R8125_MSG_DEFAULT);

#if LINUX_VERSION_CODE >= KERNEL_VERSION(2,6,26)
        if (!aspm)
                pci_disable_link_state(pdev, PCIE_LINK_STATE_L0S | PCIE_LINK_STATE_L1 |
                                       PCIE_LINK_STATE_CLKPM);
#endif

        /* enable device (incl. PCI PM wakeup and hotplug setup) */
        rc = pci_enable_device(pdev);
        if (rc < 0) {
#if LINUX_VERSION_CODE > KERNEL_VERSION(2,6,0)
                if (netif_msg_probe(tp))
                        dev_err(&pdev->dev, "enable failure\n");
#endif //LINUX_VERSION_CODE > KERNEL_VERSION(2,6,0)
                goto err_out_free_dev;
        }

        if (pci_set_mwi(pdev) < 0) {
#if LINUX_VERSION_CODE > KERNEL_VERSION(2,6,0)
                if (netif_msg_drv(&debug))
                        dev_info(&pdev->dev, "Mem-Wr-Inval unavailable.\n");
#endif //LINUX_VERSION_CODE > KERNEL_VERSION(2,6,0)
        }

        /* save power state before pci_enable_device overwrites it */
        pm_cap = pci_find_capability(pdev, PCI_CAP_ID_PM);
        if (pm_cap) {
                u16 pwr_command;

                pci_read_config_word(pdev, pm_cap + PCI_PM_CTRL, &pwr_command);
        } else {
#if LINUX_VERSION_CODE > KERNEL_VERSION(2,6,0)
                if (netif_msg_probe(tp)) {
                        dev_err(&pdev->dev, "PowerManagement capability not found.\n");
                }
#else
                printk("PowerManagement capability not found.\n");
#endif //LINUX_VERSION_CODE > KERNEL_VERSION(2,6,0)

        }

        /* make sure PCI base addr 1 is MMIO */
        if (!(pci_resource_flags(pdev, 2) & IORESOURCE_MEM)) {
#if LINUX_VERSION_CODE > KERNEL_VERSION(2,6,0)
                if (netif_msg_probe(tp))
                        dev_err(&pdev->dev, "region #1 not an MMIO resource, aborting\n");
#endif //LINUX_VERSION_CODE > KERNEL_VERSION(2,6,0)
                rc = -ENODEV;
                goto err_out_mwi;
        }
        /* check for weird/broken PCI region reporting */
        if (pci_resource_len(pdev, 2) < R8125_REGS_SIZE) {
#if LINUX_VERSION_CODE > KERNEL_VERSION(2,6,0)
                if (netif_msg_probe(tp))
                        dev_err(&pdev->dev, "Invalid PCI region size(s), aborting\n");
#endif //LINUX_VERSION_CODE > KERNEL_VERSION(2,6,0)
                rc = -ENODEV;
                goto err_out_mwi;
        }

        rc = pci_request_regions(pdev, MODULENAME);
        if (rc < 0) {
#if LINUX_VERSION_CODE > KERNEL_VERSION(2,6,0)
                if (netif_msg_probe(tp))
                        dev_err(&pdev->dev, "could not request regions.\n");
#endif //LINUX_VERSION_CODE > KERNEL_VERSION(2,6,0)
                goto err_out_mwi;
        }

        if ((sizeof(dma_addr_t) > 4) &&
            use_dac &&
            !pci_set_dma_mask(pdev, DMA_BIT_MASK(64)) &&
            !pci_set_consistent_dma_mask(pdev, DMA_BIT_MASK(64))) {
                dev->features |= NETIF_F_HIGHDMA;
        } else {
                rc = pci_set_dma_mask(pdev, DMA_BIT_MASK(32));
                if (rc < 0) {
#if LINUX_VERSION_CODE > KERNEL_VERSION(2,6,0)
                        if (netif_msg_probe(tp))
                                dev_err(&pdev->dev, "DMA configuration failed.\n");
#endif //LINUX_VERSION_CODE > KERNEL_VERSION(2,6,0)
                        goto err_out_free_res;
                }
        }

        /* ioremap MMIO region */
        ioaddr = ioremap(pci_resource_start(pdev, 2), pci_resource_len(pdev, 2));
        if (ioaddr == NULL) {
#if LINUX_VERSION_CODE > KERNEL_VERSION(2,6,0)
                if (netif_msg_probe(tp))
                        dev_err(&pdev->dev, "cannot remap MMIO, aborting\n");
#endif //LINUX_VERSION_CODE > KERNEL_VERSION(2,6,0)
                rc = -EIO;
                goto err_out_free_res;
        }

        tp->mmio_addr = ioaddr;

        /* Identify chip attached to board */
        rtl8125_get_mac_version(tp);

        rtl8125_print_mac_version(tp);

        for (i = ARRAY_SIZE(rtl_chip_info) - 1; i >= 0; i--) {
                if (tp->mcfg == rtl_chip_info[i].mcfg)
                        break;
        }

        if (i < 0) {
                /* Unknown chip: assume array element #0, original RTL-8125 */
#if LINUX_VERSION_CODE > KERNEL_VERSION(2,6,0)
                if (netif_msg_probe(tp))
                        dev_printk(KERN_DEBUG, &pdev->dev, "unknown chip version, assuming %s\n", rtl_chip_info[0].name);
#else
                printk("Realtek unknown chip version, assuming %s\n", rtl_chip_info[0].name);
#endif //LINUX_VERSION_CODE < KERNEL_VERSION(2,6,0)
                i++;
        }

        tp->chipset = i;

        *ioaddr_out = ioaddr;
        *dev_out = dev;
out:
        return rc;

err_out_free_res:
        pci_release_regions(pdev);
err_out_mwi:
        pci_clear_mwi(pdev);
        pci_disable_device(pdev);
err_out_free_dev:
        free_netdev(dev);
err_out:
        *ioaddr_out = NULL;
        *dev_out = NULL;
        goto out;
}

static void
#if LINUX_VERSION_CODE < KERNEL_VERSION(4,14,0)
rtl8125_esd_timer(unsigned long __opaque)
#else
rtl8125_esd_timer(struct timer_list *t)
#endif
{
#if LINUX_VERSION_CODE < KERNEL_VERSION(4,14,0)
        struct net_device *dev = (struct net_device *)__opaque;
        struct rtl8125_private *tp = netdev_priv(dev);
        struct timer_list *timer = &tp->esd_timer;
#else
        struct rtl8125_private *tp = from_timer(tp, t, esd_timer);
        struct net_device *dev = tp->dev;
        struct timer_list *timer = t;
#endif
        struct pci_dev *pdev = tp->pci_dev;
        unsigned long timeout = RTL8125_ESD_TIMEOUT;
        unsigned long flags;
        u8 cmd;
        u16 io_base_l;
        u16 mem_base_l;
        u16 mem_base_h;
        u8 ilr;
        u16 resv_0x1c_h;
        u16 resv_0x1c_l;
        u16 resv_0x20_l;
        u16 resv_0x20_h;
        u16 resv_0x24_l;
        u16 resv_0x24_h;
        u16 resv_0x2c_h;
        u16 resv_0x2c_l;
        u32 pci_sn_l;
        u32 pci_sn_h;

        spin_lock_irqsave(&tp->lock, flags);

        tp->esd_flag = 0;

        pci_read_config_byte(pdev, PCI_COMMAND, &cmd);
        if (cmd != tp->pci_cfg_space.cmd) {
                printk(KERN_ERR "%s: cmd = 0x%02x, should be 0x%02x \n.", dev->name, cmd, tp->pci_cfg_space.cmd);
                pci_write_config_byte(pdev, PCI_COMMAND, tp->pci_cfg_space.cmd);
                tp->esd_flag |= BIT_0;
        }

        pci_read_config_word(pdev, PCI_BASE_ADDRESS_0, &io_base_l);
        if (io_base_l != tp->pci_cfg_space.io_base_l) {
                printk(KERN_ERR "%s: io_base_l = 0x%04x, should be 0x%04x \n.", dev->name, io_base_l, tp->pci_cfg_space.io_base_l);
                pci_write_config_word(pdev, PCI_BASE_ADDRESS_0, tp->pci_cfg_space.io_base_l);
                tp->esd_flag |= BIT_1;
        }

        pci_read_config_word(pdev, PCI_BASE_ADDRESS_2, &mem_base_l);
        if (mem_base_l != tp->pci_cfg_space.mem_base_l) {
                printk(KERN_ERR "%s: mem_base_l = 0x%04x, should be 0x%04x \n.", dev->name, mem_base_l, tp->pci_cfg_space.mem_base_l);
                pci_write_config_word(pdev, PCI_BASE_ADDRESS_2, tp->pci_cfg_space.mem_base_l);
                tp->esd_flag |= BIT_2;
        }

        pci_read_config_word(pdev, PCI_BASE_ADDRESS_2 + 2, &mem_base_h);
        if (mem_base_h!= tp->pci_cfg_space.mem_base_h) {
                printk(KERN_ERR "%s: mem_base_h = 0x%04x, should be 0x%04x \n.", dev->name, mem_base_h, tp->pci_cfg_space.mem_base_h);
                pci_write_config_word(pdev, PCI_BASE_ADDRESS_2 + 2, tp->pci_cfg_space.mem_base_h);
                tp->esd_flag |= BIT_3;
        }

        pci_read_config_word(pdev, PCI_BASE_ADDRESS_3, &resv_0x1c_l);
        if (resv_0x1c_l != tp->pci_cfg_space.resv_0x1c_l) {
                printk(KERN_ERR "%s: resv_0x1c_l = 0x%04x, should be 0x%04x \n.", dev->name, resv_0x1c_l, tp->pci_cfg_space.resv_0x1c_l);
                pci_write_config_word(pdev, PCI_BASE_ADDRESS_3, tp->pci_cfg_space.resv_0x1c_l);
                tp->esd_flag |= BIT_4;
        }

        pci_read_config_word(pdev, PCI_BASE_ADDRESS_3 + 2, &resv_0x1c_h);
        if (resv_0x1c_h != tp->pci_cfg_space.resv_0x1c_h) {
                printk(KERN_ERR "%s: resv_0x1c_h = 0x%04x, should be 0x%04x \n.", dev->name, resv_0x1c_h, tp->pci_cfg_space.resv_0x1c_h);
                pci_write_config_word(pdev, PCI_BASE_ADDRESS_3 + 2, tp->pci_cfg_space.resv_0x1c_h);
                tp->esd_flag |= BIT_5;
        }

        pci_read_config_word(pdev, PCI_BASE_ADDRESS_4, &resv_0x20_l);
        if (resv_0x20_l != tp->pci_cfg_space.resv_0x20_l) {
                printk(KERN_ERR "%s: resv_0x20_l = 0x%04x, should be 0x%04x \n.", dev->name, resv_0x20_l, tp->pci_cfg_space.resv_0x20_l);
                pci_write_config_word(pdev, PCI_BASE_ADDRESS_4, tp->pci_cfg_space.resv_0x20_l);
                tp->esd_flag |= BIT_6;
        }

        pci_read_config_word(pdev, PCI_BASE_ADDRESS_4 + 2, &resv_0x20_h);
        if (resv_0x20_h != tp->pci_cfg_space.resv_0x20_h) {
                printk(KERN_ERR "%s: resv_0x20_h = 0x%04x, should be 0x%04x \n.", dev->name, resv_0x20_h, tp->pci_cfg_space.resv_0x20_h);
                pci_write_config_word(pdev, PCI_BASE_ADDRESS_4 + 2, tp->pci_cfg_space.resv_0x20_h);
                tp->esd_flag |= BIT_7;
        }

        pci_read_config_word(pdev, PCI_BASE_ADDRESS_5, &resv_0x24_l);
        if (resv_0x24_l != tp->pci_cfg_space.resv_0x24_l) {
                printk(KERN_ERR "%s: resv_0x24_l = 0x%04x, should be 0x%04x \n.", dev->name, resv_0x24_l, tp->pci_cfg_space.resv_0x24_l);
                pci_write_config_word(pdev, PCI_BASE_ADDRESS_5, tp->pci_cfg_space.resv_0x24_l);
                tp->esd_flag |= BIT_8;
        }

        pci_read_config_word(pdev, PCI_BASE_ADDRESS_5 + 2, &resv_0x24_h);
        if (resv_0x24_h != tp->pci_cfg_space.resv_0x24_h) {
                printk(KERN_ERR "%s: resv_0x24_h = 0x%04x, should be 0x%04x \n.", dev->name, resv_0x24_h, tp->pci_cfg_space.resv_0x24_h);
                pci_write_config_word(pdev, PCI_BASE_ADDRESS_5 + 2, tp->pci_cfg_space.resv_0x24_h);
                tp->esd_flag |= BIT_9;
        }

        pci_read_config_byte(pdev, PCI_INTERRUPT_LINE, &ilr);
        if (ilr != tp->pci_cfg_space.ilr) {
                printk(KERN_ERR "%s: ilr = 0x%02x, should be 0x%02x \n.", dev->name, ilr, tp->pci_cfg_space.ilr);
                pci_write_config_byte(pdev, PCI_INTERRUPT_LINE, tp->pci_cfg_space.ilr);
                tp->esd_flag |= BIT_10;
        }

        pci_read_config_word(pdev, PCI_SUBSYSTEM_VENDOR_ID, &resv_0x2c_l);
        if (resv_0x2c_l != tp->pci_cfg_space.resv_0x2c_l) {
                printk(KERN_ERR "%s: resv_0x2c_l = 0x%04x, should be 0x%04x \n.", dev->name, resv_0x2c_l, tp->pci_cfg_space.resv_0x2c_l);
                pci_write_config_word(pdev, PCI_SUBSYSTEM_VENDOR_ID, tp->pci_cfg_space.resv_0x2c_l);
                tp->esd_flag |= BIT_11;
        }

        pci_read_config_word(pdev, PCI_SUBSYSTEM_VENDOR_ID + 2, &resv_0x2c_h);
        if (resv_0x2c_h != tp->pci_cfg_space.resv_0x2c_h) {
                printk(KERN_ERR "%s: resv_0x2c_h = 0x%04x, should be 0x%04x \n.", dev->name, resv_0x2c_h, tp->pci_cfg_space.resv_0x2c_h);
                pci_write_config_word(pdev, PCI_SUBSYSTEM_VENDOR_ID + 2, tp->pci_cfg_space.resv_0x2c_h);
                tp->esd_flag |= BIT_12;
        }

        if (tp->HwPcieSNOffset > 0) {
                pci_sn_l = rtl8125_csi_read(tp, tp->HwPcieSNOffset);
                if (pci_sn_l != tp->pci_cfg_space.pci_sn_l) {
                        printk(KERN_ERR "%s: pci_sn_l = 0x%08x, should be 0x%08x \n.", dev->name, pci_sn_l, tp->pci_cfg_space.pci_sn_l);
                        rtl8125_csi_write(tp, tp->HwPcieSNOffset, tp->pci_cfg_space.pci_sn_l);
                        tp->esd_flag |= BIT_13;
                }

                pci_sn_h = rtl8125_csi_read(tp, tp->HwPcieSNOffset + 4);
                if (pci_sn_h != tp->pci_cfg_space.pci_sn_h) {
                        printk(KERN_ERR "%s: pci_sn_h = 0x%08x, should be 0x%08x \n.", dev->name, pci_sn_h, tp->pci_cfg_space.pci_sn_h);
                        rtl8125_csi_write(tp, tp->HwPcieSNOffset + 4, tp->pci_cfg_space.pci_sn_h);
                        tp->esd_flag |= BIT_14;
                }
        }

        if (tp->esd_flag != 0) {
                printk(KERN_ERR "%s: esd_flag = 0x%04x\n.\n", dev->name, tp->esd_flag);
                rtl8125_stop_all_tx_queue(dev);
                netif_carrier_off(dev);
                rtl8125_hw_reset(dev);
                rtl8125_tx_clear(tp);
                rtl8125_rx_clear(tp);
                rtl8125_init_ring(dev);
                rtl8125_up(dev);
                rtl8125_enable_hw_linkchg_interrupt(tp);
                rtl8125_set_speed(dev, tp->autoneg, tp->speed, tp->duplex, tp->advertising);
                tp->esd_flag = 0;
        }
        spin_unlock_irqrestore(&tp->lock, flags);

        mod_timer(timer, jiffies + timeout);
}

/*
static void
#if LINUX_VERSION_CODE < KERNEL_VERSION(4,14,0)
rtl8125_link_timer(unsigned long __opaque)
#else
rtl8125_link_timer(struct timer_list *t)
#endif
{
#if LINUX_VERSION_CODE < KERNEL_VERSION(4,14,0)
        struct net_device *dev = (struct net_device *)__opaque;
        struct rtl8125_private *tp = netdev_priv(dev);
        struct timer_list *timer = &tp->link_timer;
#else
        struct rtl8125_private *tp = from_timer(tp, t, link_timer);
        struct net_device *dev = tp->dev;
        struct timer_list *timer = t;
#endif
        unsigned long flags;

        spin_lock_irqsave(&tp->lock, flags);
        rtl8125_check_link_status(dev);
        spin_unlock_irqrestore(&tp->lock, flags);

        mod_timer(timer, jiffies + RTL8125_LINK_TIMEOUT);
}
*/

int
rtl8125_enable_msix(struct rtl8125_private *tp)
{
        int i, nvecs = 0;
        struct msix_entry msix_ent[R8125_MAX_MSIX_VEC];
        //struct net_device *dev = tp->dev;
        //const int len = sizeof(tp->irq_tbl[0].name);

        for (i = 0; i < R8125_MAX_MSIX_VEC; i++) {
                msix_ent[i].entry = i;
                msix_ent[i].vector = 0;
        }

        nvecs = pci_enable_msix_range(tp->pci_dev, msix_ent,
                                      tp->min_irq_nvecs, tp->max_irq_nvecs);
        if (nvecs < 0)
                goto out;

        for (i = 0; i < nvecs; i++) {
                struct r8125_irq *irq = &tp->irq_tbl[i];
                irq->vector = msix_ent[i].vector;
                //snprintf(irq->name, len, "%s-%d", dev->name, i);
                //irq->handler = rtl8125_interrupt_msix;
        }

out:
        return nvecs;
}

void rtl8125_dump_msix_tbl(struct rtl8125_private *tp)
{
        void __iomem *ioaddr;

        /* ioremap MMIO region */
        ioaddr = ioremap(pci_resource_start(tp->pci_dev, 4), pci_resource_len(tp->pci_dev, 4));
        if (ioaddr) {
                int i = 0;
                for (i=0; i<tp->irq_nvecs; i++) {
                        printk("entry 0x%d %08X %08X %08X %08X \n",
                               i,
                               readl(ioaddr + 16 * i),
                               readl(ioaddr + 16 * i + 4),
                               readl(ioaddr + 16 * i + 8),
                               readl(ioaddr + 16 * i + 12));
                }
                iounmap(ioaddr);
        }
}

/* Cfg9346_Unlock assumed. */
static int rtl8125_try_msi(struct rtl8125_private *tp)
{
        struct pci_dev *pdev = tp->pci_dev;
        unsigned msi = 0;
        int nvecs = 1;

        switch (tp->mcfg) {
        case CFG_METHOD_4:
        case CFG_METHOD_5:
                tp->max_irq_nvecs = R8125_MAX_MSIX_VEC_8125B;
                tp->min_irq_nvecs = R8125_MIN_MSIX_VEC_8125B;
                break;
        default:
                tp->max_irq_nvecs = 1;
                tp->min_irq_nvecs = 1;
                break;
        }

#if defined(RTL_USE_NEW_INTR_API)
        if ((nvecs = pci_alloc_irq_vectors(pdev, tp->min_irq_nvecs, tp->max_irq_nvecs, PCI_IRQ_MSIX)) > 0)
                msi |= RTL_FEATURE_MSIX;
        else if ((nvecs = pci_alloc_irq_vectors(pdev, 1, 1, PCI_IRQ_ALL_TYPES)) > 0 &&
                 pci_dev_msi_enabled(pdev))
                msi |= RTL_FEATURE_MSI;
#elif LINUX_VERSION_CODE > KERNEL_VERSION(2,6,13)
        if ((nvecs = rtl8125_enable_msix(tp)) > 0)
                msi |= RTL_FEATURE_MSIX;
        else if (!pci_enable_msi(pdev))
                msi |= RTL_FEATURE_MSI;
#endif
        if (!(msi & (RTL_FEATURE_MSI | RTL_FEATURE_MSIX)))
                dev_info(&pdev->dev, "no MSI/MSI-X. Back to INTx.\n");

        if (!(msi & RTL_FEATURE_MSIX) || nvecs < 1)
                nvecs = 1;

        tp->irq_nvecs = nvecs;

        tp->features |= msi;

        return nvecs;
}

static void rtl8125_disable_msi(struct pci_dev *pdev, struct rtl8125_private *tp)
{
#if defined(RTL_USE_NEW_INTR_API)
        if (tp->features & (RTL_FEATURE_MSI | RTL_FEATURE_MSIX))
                pci_free_irq_vectors(pdev);
#elif LINUX_VERSION_CODE > KERNEL_VERSION(2,6,13)
        if (tp->features & (RTL_FEATURE_MSIX))
                pci_disable_msix(pdev);
        else if (tp->features & (RTL_FEATURE_MSI))
                pci_disable_msi(pdev);
#endif
        tp->features &= ~(RTL_FEATURE_MSI | RTL_FEATURE_MSIX);
}

static int rtl8125_get_irq(struct pci_dev *pdev)
{
#if defined(RTL_USE_NEW_INTR_API)
        return pci_irq_vector(pdev, 0);
#else
        return pdev->irq;
#endif
}

#if LINUX_VERSION_CODE >= KERNEL_VERSION(2,6,29)
static const struct net_device_ops rtl8125_netdev_ops = {
        .ndo_open       = rtl8125_open,
        .ndo_stop       = rtl8125_close,
        .ndo_get_stats      = rtl8125_get_stats,
        .ndo_start_xmit     = rtl8125_start_xmit,
        .ndo_tx_timeout     = rtl8125_tx_timeout,
        .ndo_change_mtu     = rtl8125_change_mtu,
        .ndo_set_mac_address    = rtl8125_set_mac_address,
        .ndo_do_ioctl       = rtl8125_do_ioctl,
#if LINUX_VERSION_CODE < KERNEL_VERSION(3,1,0)
        .ndo_set_multicast_list = rtl8125_set_rx_mode,
#else
        .ndo_set_rx_mode    = rtl8125_set_rx_mode,
#endif
#if LINUX_VERSION_CODE < KERNEL_VERSION(3,0,0)
#ifdef CONFIG_R8125_VLAN
        .ndo_vlan_rx_register   = rtl8125_vlan_rx_register,
#endif
#else
        .ndo_fix_features   = rtl8125_fix_features,
        .ndo_set_features   = rtl8125_set_features,
#endif
#ifdef CONFIG_NET_POLL_CONTROLLER
        .ndo_poll_controller    = rtl8125_netpoll,
#endif
};
#endif


#ifdef  CONFIG_R8125_NAPI

static int rtl8125_poll(napi_ptr napi, napi_budget budget)
{
        struct r8125_napi *r8125napi = RTL_GET_PRIV(napi, struct r8125_napi);
        struct rtl8125_private *tp = r8125napi->priv;
        RTL_GET_NETDEV(tp)
        unsigned int work_to_do = RTL_NAPI_QUOTA(budget, dev);
        unsigned int work_done = 0;
        //unsigned long flags;
        int i;

        for (i = 0; i < tp->num_rx_rings; i++)
                work_done += rtl8125_rx_interrupt(dev, tp, &tp->rx_ring[i], budget);

        //spin_lock_irqsave(&tp->lock, flags);
        for (i = 0; i < tp->num_tx_rings; i++)
                rtl8125_tx_interrupt(&tp->tx_ring[i], budget);
        //spin_unlock_irqrestore(&tp->lock, flags);

        RTL_NAPI_QUOTA_UPDATE(dev, work_done, budget);

        if (work_done < work_to_do) {
#ifdef ENABLE_DASH_SUPPORT
                if (tp->DASH) {
                        struct net_device *dev = tp->dev;

                        spin_lock_irqsave(&tp->lock, flags);
                        HandleDashInterrupt(dev);
                        spin_unlock_irqrestore(&tp->lock, flags);
                }
#endif

#if LINUX_VERSION_CODE >= KERNEL_VERSION(4,10,0)
                if (RTL_NETIF_RX_COMPLETE(dev, napi, work_done) == FALSE) return RTL_NAPI_RETURN_VALUE;
#else
                RTL_NETIF_RX_COMPLETE(dev, napi, work_done);
#endif
                /*
                 * 20040426: the barrier is not strictly required but the
                 * behavior of the irq handler could be less predictable
                 * without it. Btw, the lack of flush for the posted pci
                 * write is safe - FR
                 */
                smp_wmb();

                rtl8125_switch_to_timer_interrupt(tp);
        }

        return RTL_NAPI_RETURN_VALUE;
}

#if 0
static int rtl8125_poll_msix_ring(napi_ptr napi, napi_budget budget)
{
        struct r8125_napi *r8125napi = RTL_GET_PRIV(napi, struct r8125_napi);
        struct rtl8125_private *tp = r8125napi->priv;
        RTL_GET_NETDEV(tp)
        unsigned int work_to_do = RTL_NAPI_QUOTA(budget, dev);
        unsigned int work_done = 0;
        unsigned long flags;
        const int message_id = r8125napi->index;

        work_done += rtl8125_rx_interrupt(dev, tp, &tp->rx_ring[message_id], budget);

        //spin_lock_irqsave(&tp->lock, flags);
        rtl8125_tx_interrupt_with_vector(tp, message_id, budget);
        //spin_unlock_irqrestore(&tp->lock, flags);

        RTL_NAPI_QUOTA_UPDATE(dev, work_done, budget);

        if (work_done < work_to_do) {
#ifdef ENABLE_DASH_SUPPORT
                if (tp->DASH && message_id == 0) {
                        struct net_device *dev = tp->dev;

                        spin_lock_irqsave(&tp->lock, flags);
                        HandleDashInterrupt(dev);
                        spin_unlock_irqrestore(&tp->lock, flags);
                }
#endif

#if LINUX_VERSION_CODE >= KERNEL_VERSION(4,10,0)
                if (RTL_NETIF_RX_COMPLETE(dev, napi, work_done) == FALSE) return RTL_NAPI_RETURN_VALUE;
#else
                RTL_NETIF_RX_COMPLETE(dev, napi, work_done);
#endif
                /*
                 * 20040426: the barrier is not strictly required but the
                 * behavior of the irq handler could be less predictable
                 * without it. Btw, the lack of flush for the posted pci
                 * write is safe - FR
                 */
                smp_wmb();

                rtl8125_enable_hw_interrupt_v2(tp, message_id);
        }

        return RTL_NAPI_RETURN_VALUE;
}
#endif

static int rtl8125_poll_msix_tx(napi_ptr napi, napi_budget budget)
{
        struct r8125_napi *r8125napi = RTL_GET_PRIV(napi, struct r8125_napi);
        struct rtl8125_private *tp = r8125napi->priv;
        RTL_GET_NETDEV(tp)
        unsigned int work_to_do = RTL_NAPI_QUOTA(budget, dev);
        unsigned int work_done = 0;
        //unsigned long flags;
        const int message_id = r8125napi->index;

        //suppress unused variable
        (void)(dev);

        //spin_lock_irqsave(&tp->lock, flags);
        rtl8125_tx_interrupt_with_vector(tp, message_id, budget);
        //spin_unlock_irqrestore(&tp->lock, flags);

        RTL_NAPI_QUOTA_UPDATE(dev, work_done, budget);

        if (work_done < work_to_do) {
#if LINUX_VERSION_CODE >= KERNEL_VERSION(4,10,0)
                if (RTL_NETIF_RX_COMPLETE(dev, napi, work_done) == FALSE) return RTL_NAPI_RETURN_VALUE;
#else
                RTL_NETIF_RX_COMPLETE(dev, napi, work_done);
#endif
                /*
                 * 20040426: the barrier is not strictly required but the
                 * behavior of the irq handler could be less predictable
                 * without it. Btw, the lack of flush for the posted pci
                 * write is safe - FR
                 */
                smp_wmb();

                rtl8125_enable_hw_interrupt_v2(tp, message_id);
        }

        return RTL_NAPI_RETURN_VALUE;
}

static int rtl8125_poll_msix_other(napi_ptr napi, napi_budget budget)
{
        struct r8125_napi *r8125napi = RTL_GET_PRIV(napi, struct r8125_napi);
        struct rtl8125_private *tp = r8125napi->priv;
        RTL_GET_NETDEV(tp)
        unsigned int work_to_do = RTL_NAPI_QUOTA(budget, dev);
        const int message_id = r8125napi->index;

        //suppress unused variable
        (void)(dev);

#if LINUX_VERSION_CODE >= KERNEL_VERSION(4,10,0)
        RTL_NETIF_RX_COMPLETE(dev, napi, work_to_do);
#else
        RTL_NETIF_RX_COMPLETE(dev, napi, work_to_do);
#endif

        rtl8125_enable_hw_interrupt_v2(tp, message_id);

        return 1;
}

static int rtl8125_poll_msix_rx(napi_ptr napi, napi_budget budget)
{
        struct r8125_napi *r8125napi = RTL_GET_PRIV(napi, struct r8125_napi);
        struct rtl8125_private *tp = r8125napi->priv;
        RTL_GET_NETDEV(tp)
        unsigned int work_to_do = RTL_NAPI_QUOTA(budget, dev);
        unsigned int work_done = 0;
        const int message_id = r8125napi->index;

        work_done += rtl8125_rx_interrupt(dev, tp, &tp->rx_ring[message_id], budget);

        RTL_NAPI_QUOTA_UPDATE(dev, work_done, budget);

        if (work_done < work_to_do) {
#if LINUX_VERSION_CODE >= KERNEL_VERSION(4,10,0)
                if (RTL_NETIF_RX_COMPLETE(dev, napi, work_done) == FALSE) return RTL_NAPI_RETURN_VALUE;
#else
                RTL_NETIF_RX_COMPLETE(dev, napi, work_done);
#endif
                /*
                 * 20040426: the barrier is not strictly required but the
                 * behavior of the irq handler could be less predictable
                 * without it. Btw, the lack of flush for the posted pci
                 * write is safe - FR
                 */
                smp_wmb();

                rtl8125_enable_hw_interrupt_v2(tp, message_id);
        }

        return RTL_NAPI_RETURN_VALUE;
}

static void rtl8125_enable_napi(struct rtl8125_private *tp)
{
#if LINUX_VERSION_CODE > KERNEL_VERSION(2,6,0)
        int i;

        for (i = 0; i < tp->irq_nvecs; i++)
                RTL_NAPI_ENABLE(tp->dev, &tp->r8125napi[i].napi);
#endif
}

static void rtl8125_disable_napi(struct rtl8125_private *tp)
{
#if LINUX_VERSION_CODE > KERNEL_VERSION(2,6,0)
        int i;

        for (i = 0; i < tp->irq_nvecs; i++)
                RTL_NAPI_DISABLE(tp->dev, &tp->r8125napi[i].napi);
#endif
}

static void rtl8125_del_napi(struct rtl8125_private *tp)
{
#if LINUX_VERSION_CODE > KERNEL_VERSION(2,6,0)
        int i;

        for (i = 0; i < tp->irq_nvecs; i++)
                RTL_NAPI_DEL((&tp->r8125napi[i]));
#endif
}
#endif //CONFIG_R8125_NAPI

static void rtl8125_init_napi(struct rtl8125_private *tp)
{
        int i;

        for (i=0; i<tp->irq_nvecs; i++) {
                struct r8125_napi *r8125napi = &tp->r8125napi[i];
#ifdef CONFIG_R8125_NAPI
                int (*poll)(struct napi_struct *, int);

                if (tp->features & RTL_FEATURE_MSIX &&
                    tp->HwCurrIsrVer == 2) {
                        if (i < R8125_MAX_RX_QUEUES_VEC_V3)
                                poll = rtl8125_poll_msix_rx;
                        else if (i == 16 || i == 18)
                                poll = rtl8125_poll_msix_tx;
                        else
                                poll = rtl8125_poll_msix_other;
                } else {
                        poll = rtl8125_poll;
                }

                RTL_NAPI_CONFIG(tp->dev, r8125napi, poll, R8125_NAPI_WEIGHT);
#endif

                r8125napi->priv = tp;
                r8125napi->index = i;
        }
}

static int __devinit
rtl8125_init_one(struct pci_dev *pdev,
                 const struct pci_device_id *ent)
{
        struct net_device *dev = NULL;
        struct rtl8125_private *tp;
        void __iomem *ioaddr = NULL;
        static int board_idx = -1;

        int rc;

        assert(pdev != NULL);
        assert(ent != NULL);

        board_idx++;

        if (netif_msg_drv(&debug))
                printk(KERN_INFO "%s 2.5Gigabit Ethernet driver %s loaded\n",
                       MODULENAME, RTL8125_VERSION);

        rc = rtl8125_init_board(pdev, &dev, &ioaddr);
        if (rc)
                goto out;

        tp = netdev_priv(dev);
        assert(ioaddr != NULL);

        tp->set_speed = rtl8125_set_speed_xmii;
        tp->get_settings = rtl8125_gset_xmii;
        tp->phy_reset_enable = rtl8125_xmii_reset_enable;
        tp->phy_reset_pending = rtl8125_xmii_reset_pending;
        tp->link_ok = rtl8125_xmii_link_ok;

        rc = rtl8125_try_msi(tp);
        if (rc < 0) {
                dev_err(&pdev->dev, "Can't allocate interrupt\n");
                goto err_out_1;
        }

        spin_lock_init(&tp->lock);

        rtl8125_init_software_variable(dev);

        RTL_NET_DEVICE_OPS(rtl8125_netdev_ops);

#if LINUX_VERSION_CODE > KERNEL_VERSION(2,4,22)
        SET_ETHTOOL_OPS(dev, &rtl8125_ethtool_ops);
#endif

        dev->watchdog_timeo = RTL8125_TX_TIMEOUT;
        dev->irq = rtl8125_get_irq(pdev);
        dev->base_addr = (unsigned long) ioaddr;

        rtl8125_init_napi(tp);

#ifdef CONFIG_R8125_VLAN
        if (tp->mcfg != CFG_METHOD_DEFAULT) {
                dev->features |= NETIF_F_HW_VLAN_TX | NETIF_F_HW_VLAN_RX;
#if LINUX_VERSION_CODE < KERNEL_VERSION(2,6,22)
                dev->vlan_rx_kill_vid = rtl8125_vlan_rx_kill_vid;
#endif //LINUX_VERSION_CODE < KERNEL_VERSION(2,6,22)
        }
#endif

        /* There has been a number of reports that using SG/TSO results in
         * tx timeouts. However for a lot of people SG/TSO works fine.
         * Therefore disable both features by default, but allow users to
         * enable them. Use at own risk!
         */
        tp->cp_cmd |= RTL_R16(tp, CPlusCmd);
        if (tp->mcfg != CFG_METHOD_DEFAULT) {
                dev->features |= NETIF_F_IP_CSUM;
#if LINUX_VERSION_CODE < KERNEL_VERSION(3,0,0)
                tp->cp_cmd |= RxChkSum;
#else
                dev->features |= NETIF_F_RXCSUM;
                dev->hw_features = NETIF_F_SG | NETIF_F_IP_CSUM | NETIF_F_TSO |
                                   NETIF_F_RXCSUM | NETIF_F_HW_VLAN_TX | NETIF_F_HW_VLAN_RX;
                dev->vlan_features = NETIF_F_SG | NETIF_F_IP_CSUM | NETIF_F_TSO |
                                     NETIF_F_HIGHDMA;
#if LINUX_VERSION_CODE >= KERNEL_VERSION(3,15,0)
                dev->priv_flags |= IFF_LIVE_ADDR_CHANGE;
#endif //LINUX_VERSION_CODE >= KERNEL_VERSION(3,15,0)
                dev->hw_features |= NETIF_F_RXALL;
                dev->hw_features |= NETIF_F_RXFCS;
#if LINUX_VERSION_CODE >= KERNEL_VERSION(2,6,22)
                dev->hw_features |= NETIF_F_IPV6_CSUM | NETIF_F_TSO6;
                dev->features |=  NETIF_F_IPV6_CSUM;
                netif_set_gso_max_size(dev, LSO_64K);
#if LINUX_VERSION_CODE >= KERNEL_VERSION(3,18,0)
                dev->gso_max_segs = NIC_MAX_PHYS_BUF_COUNT_LSO2;
#if LINUX_VERSION_CODE < KERNEL_VERSION(4,7,0)
                dev->gso_min_segs = NIC_MIN_PHYS_BUF_COUNT;
#endif //LINUX_VERSION_CODE < KERNEL_VERSION(4,7,0)
#endif //LINUX_VERSION_CODE >= KERNEL_VERSION(3,18,0)

#endif //LINUX_VERSION_CODE >= KERNEL_VERSION(2,6,22)
#endif //LINUX_VERSION_CODE < KERNEL_VERSION(3,0,0)

#ifdef ENABLE_RSS_SUPPORT
                if (tp->EnableRss) {
                        dev->hw_features |= NETIF_F_RXHASH;
                        dev->features |=  NETIF_F_RXHASH;
                }
#endif
        }

#ifdef ENABLE_DASH_SUPPORT
        if (tp->DASH)
                AllocateDashShareMemory(dev);
#endif

#ifdef ENABLE_LIB_SUPPORT
        ATOMIC_INIT_NOTIFIER_HEAD(&tp->lib_nh);
#endif

        rtl8125_exit_oob(dev);

        rtl8125_powerup_pll(dev);

        rtl8125_hw_init(dev);

        rtl8125_hw_reset(dev);

        /* Get production from EEPROM */
        rtl8125_eeprom_type(tp);

        if (tp->eeprom_type == EEPROM_TYPE_93C46 || tp->eeprom_type == EEPROM_TYPE_93C56)
                rtl8125_set_eeprom_sel_low(tp);

        rtl8125_get_mac_address(dev);

        tp->fw_name = rtl_chip_fw_infos[tp->mcfg].fw_name;

        tp->tally_vaddr = dma_alloc_coherent(&pdev->dev, sizeof(*tp->tally_vaddr),
                                             &tp->tally_paddr, GFP_KERNEL);
        if (!tp->tally_vaddr) {
                rc = -ENOMEM;
                goto err_out;
        }

        rtl8125_tally_counter_clear(tp);

        pci_set_drvdata(pdev, dev);

        rc = register_netdev(dev);
        if (rc)
                goto err_out;

        printk(KERN_INFO "%s: This product is covered by one or more of the following patents: US6,570,884, US6,115,776, and US6,327,625.\n", MODULENAME);

        rtl8125_disable_rxdvgate(dev);

        device_set_wakeup_enable(&pdev->dev, tp->wol_enabled);

        netif_carrier_off(dev);

        printk("%s", GPL_CLAIM);

out:
        return rc;

err_out:
        if (tp->tally_vaddr != NULL) {
                dma_free_coherent(&pdev->dev, sizeof(*tp->tally_vaddr), tp->tally_vaddr,
                                  tp->tally_paddr);

                tp->tally_vaddr = NULL;
        }
#ifdef  CONFIG_R8125_NAPI
        rtl8125_del_napi(tp);
#endif
        rtl8125_disable_msi(pdev, tp);

err_out_1:
        rtl8125_release_board(pdev, dev);

        goto out;
}

static void __devexit
rtl8125_remove_one(struct pci_dev *pdev)
{
        struct net_device *dev = pci_get_drvdata(pdev);
        struct rtl8125_private *tp = netdev_priv(dev);

        assert(dev != NULL);
        assert(tp != NULL);

#ifdef  CONFIG_R8125_NAPI
        rtl8125_del_napi(tp);
#endif
        if (tp->DASH)
                rtl8125_driver_stop(tp);

        unregister_netdev(dev);
        rtl8125_disable_msi(pdev, tp);
#ifdef ENABLE_R8125_PROCFS
        rtl8125_proc_remove(dev);
#endif
        if (tp->tally_vaddr != NULL) {
                dma_free_coherent(&pdev->dev, sizeof(*tp->tally_vaddr), tp->tally_vaddr, tp->tally_paddr);
                tp->tally_vaddr = NULL;
        }

        rtl8125_release_board(pdev, dev);

#ifdef ENABLE_USE_FIRMWARE_FILE
        rtl8125_release_firmware(tp);
#endif

        pci_set_drvdata(pdev, NULL);
}

static void
rtl8125_set_rxbufsize(struct rtl8125_private *tp,
                      struct net_device *dev)
{
        unsigned int mtu = dev->mtu;

        tp->rx_buf_sz = (mtu > ETH_DATA_LEN) ? mtu + ETH_HLEN + 8 + 1 : RX_BUF_SIZE;
}

static void rtl8125_free_irq(struct rtl8125_private *tp)
{
        int i;

        for (i=0; i<tp->irq_nvecs; i++) {
                struct r8125_irq *irq = &tp->irq_tbl[i];
                struct r8125_napi *r8125napi = &tp->r8125napi[i];

                if (irq->requested) {
                        irq->requested = 0;
#if defined(RTL_USE_NEW_INTR_API)
                        pci_free_irq(tp->pci_dev, i, r8125napi);
#else
                        free_irq(irq->vector, r8125napi);
#endif
                }
        }
}

static int rtl8125_alloc_irq(struct rtl8125_private *tp)
{
        struct net_device *dev = tp->dev;
        int rc = 0;
        struct r8125_irq *irq;
        struct r8125_napi *r8125napi;
        int i = 0;
        const int len = sizeof(tp->irq_tbl[0].name);

#if defined(RTL_USE_NEW_INTR_API)
        for (i=0; i<tp->irq_nvecs; i++) {
                irq = &tp->irq_tbl[i];
                if (tp->features & RTL_FEATURE_MSIX &&
                    tp->HwCurrIsrVer == 2)
                        irq->handler = rtl8125_interrupt_msix;
                else
                        irq->handler = rtl8125_interrupt;

                r8125napi = &tp->r8125napi[i];
                snprintf(irq->name, len, "%s-%d", dev->name, i);
                rc = pci_request_irq(tp->pci_dev, i, irq->handler, NULL, r8125napi,
                                     irq->name);
                if (rc)
                        break;

                irq->vector = pci_irq_vector(tp->pci_dev, i);
                irq->requested = 1;
        }
#else
        unsigned long irq_flags = 0;
#ifdef ENABLE_LIB_SUPPORT
        irq_flags |= IRQF_NO_SUSPEND;
#endif
        if (tp->features & RTL_FEATURE_MSIX &&
            tp->HwCurrIsrVer == 2) {
                for (i=0; i<tp->irq_nvecs; i++) {
                        irq = &tp->irq_tbl[i];
                        irq->handler = rtl8125_interrupt_msix;
                        r8125napi = &tp->r8125napi[i];
                        snprintf(irq->name, len, "%s-%d", dev->name, i);
                        rc = request_irq(irq->vector, irq->handler, irq_flags, irq->name, r8125napi);

                        if (rc)
                                break;

                        irq->requested = 1;
                }
        } else {
                irq = &tp->irq_tbl[0];
                irq->handler = rtl8125_interrupt;
                r8125napi = &tp->r8125napi[0];
                snprintf(irq->name, len, "%s-0", dev->name);
                if (!(tp->features & RTL_FEATURE_MSIX))
                        irq->vector = dev->irq;
                irq_flags |= (tp->features & (RTL_FEATURE_MSI | RTL_FEATURE_MSIX)) ? 0 : SA_SHIRQ;
                rc = request_irq(irq->vector, irq->handler, irq_flags, irq->name, r8125napi);

                if (rc == 0)
                        irq->requested = 1;
        }
#endif
        if (rc)
                rtl8125_free_irq(tp);

        return rc;
}

static int rtl8125_alloc_tx_desc(struct rtl8125_private *tp)
{
        struct rtl8125_tx_ring *ring;
        struct pci_dev *pdev = tp->pci_dev;
        int i;

        for (i = 0; i < tp->num_tx_rings; i++) {
                ring = &tp->tx_ring[i];
                ring->TxDescArray = dma_alloc_coherent(&pdev->dev, R8125_TX_RING_BYTES,
                                                       &ring->TxPhyAddr, GFP_KERNEL);

                if (!ring->TxDescArray)
                        return -1;
        }

        return 0;
}

static int rtl8125_alloc_rx_desc(struct rtl8125_private *tp)
{
        struct rtl8125_rx_ring *ring;
        struct pci_dev *pdev = tp->pci_dev;
        int i;

        for (i = 0; i < tp->num_rx_rings; i++) {
                ring = &tp->rx_ring[i];
                ring->RxDescArray = dma_alloc_coherent(&pdev->dev, tp->RxDescRingLength,
                                                       &ring->RxPhyAddr, GFP_KERNEL);

                if (!ring->RxDescArray)
                        return -1;
        }

        return 0;
}

static void rtl8125_free_tx_desc(struct rtl8125_private *tp)
{
        struct rtl8125_tx_ring *ring;
        struct pci_dev *pdev = tp->pci_dev;
        int i;

        for (i = 0; i < tp->num_tx_rings; i++) {
                ring = &tp->tx_ring[i];
                if (ring->TxDescArray) {
                        dma_free_coherent(&pdev->dev, R8125_TX_RING_BYTES, ring->TxDescArray,
                                          ring->TxPhyAddr);
                        ring->TxDescArray = NULL;
                }
        }
}

static void rtl8125_free_rx_desc(struct rtl8125_private *tp)
{
        struct rtl8125_rx_ring *ring;
        struct pci_dev *pdev = tp->pci_dev;
        int i;

        for (i = 0; i < tp->num_rx_rings; i++) {
                ring = &tp->rx_ring[i];
                if (ring->RxDescArray) {
                        dma_free_coherent(&pdev->dev, tp->RxDescRingLength, ring->RxDescArray,
                                          ring->RxPhyAddr);
                        ring->RxDescArray = NULL;
                }
        }
}

static void rtl8125_free_alloc_resources(struct rtl8125_private *tp)
{
        rtl8125_free_rx_desc(tp);

        rtl8125_free_tx_desc(tp);
}

int rtl8125_set_real_num_queue(struct rtl8125_private *tp)
{
        int retval = 0;

        retval = netif_set_real_num_tx_queues(tp->dev, tp->num_tx_rings);
        if (retval < 0)
                goto exit;

        retval = netif_set_real_num_rx_queues(tp->dev, tp->num_rx_rings);
        if (retval < 0)
                goto exit;

exit:
        return retval;
}

#ifdef ENABLE_USE_FIRMWARE_FILE
static void rtl8125_request_firmware(struct rtl8125_private *tp)
{
        struct rtl8125_fw *rtl_fw;

        /* firmware loaded already or no firmware available */
        if (tp->rtl_fw || !tp->fw_name)
                return;

        rtl_fw = kzalloc(sizeof(*rtl_fw), GFP_KERNEL);
        if (!rtl_fw)
                return;

        rtl_fw->phy_write = rtl8125_mdio_write;
        rtl_fw->phy_read = rtl8125_mdio_read;
        rtl_fw->mac_mcu_write = mac_mcu_write;
        rtl_fw->mac_mcu_read = mac_mcu_read;
        rtl_fw->fw_name = tp->fw_name;
        rtl_fw->dev = tp_to_dev(tp);

        if (rtl8125_fw_request_firmware(rtl_fw))
                kfree(rtl_fw);
        else
                tp->rtl_fw = rtl_fw;
}
#endif

int rtl8125_open(struct net_device *dev)
{
        struct rtl8125_private *tp = netdev_priv(dev);
        unsigned long flags;
        int retval;

        retval = -ENOMEM;

#ifdef ENABLE_R8125_PROCFS
        rtl8125_proc_init(dev);
#endif
        rtl8125_set_rxbufsize(tp, dev);
        /*
         * Rx and Tx descriptors needs 256 bytes alignment.
         * pci_alloc_consistent provides more.
         */
        if (rtl8125_alloc_tx_desc(tp) < 0 || rtl8125_alloc_rx_desc(tp) < 0)
                goto err_free_all_allocated_mem;

        retval = rtl8125_init_ring(dev);
        if (retval < 0)
                goto err_free_all_allocated_mem;

        retval = rtl8125_set_real_num_queue(tp);
        if (retval < 0)
                goto err_free_all_allocated_mem;

        retval = rtl8125_alloc_irq(tp);
        if (retval < 0)
                goto err_free_all_allocated_mem;

        if (netif_msg_probe(tp)) {
                printk(KERN_INFO "%s: 0x%lx, "
                       "%2.2x:%2.2x:%2.2x:%2.2x:%2.2x:%2.2x, "
                       "IRQ %d\n",
                       dev->name,
                       dev->base_addr,
                       dev->dev_addr[0], dev->dev_addr[1],
                       dev->dev_addr[2], dev->dev_addr[3],
                       dev->dev_addr[4], dev->dev_addr[5], dev->irq);
        }

#ifdef ENABLE_USE_FIRMWARE_FILE
        rtl8125_request_firmware(tp);
#endif

#if LINUX_VERSION_CODE < KERNEL_VERSION(2,6,20)
        INIT_WORK(&tp->task, rtl8125_reset_task, dev);
#else
        INIT_DELAYED_WORK(&tp->task, rtl8125_reset_task);
#endif

        pci_set_master(tp->pci_dev);

#ifdef  CONFIG_R8125_NAPI
        rtl8125_enable_napi(tp);
#endif

        spin_lock_irqsave(&tp->lock, flags);

        rtl8125_exit_oob(dev);

        rtl8125_up(dev);

#ifdef ENABLE_PTP_SUPPORT
        if (tp->EnablePtp)
                rtl8125_ptp_init(tp);
#endif

        if (tp->resume_not_chg_speed)
                rtl8125_check_link_status(dev);
        else
                rtl8125_set_speed(dev, tp->autoneg, tp->speed, tp->duplex, tp->advertising);

        spin_unlock_irqrestore(&tp->lock, flags);

        if (tp->esd_flag == 0)
                rtl8125_request_esd_timer(dev);

        //rtl8125_request_link_timer(dev);

        rtl8125_enable_hw_linkchg_interrupt(tp);

out:

        return retval;

err_free_all_allocated_mem:
        rtl8125_free_alloc_resources(tp);

        goto out;
}

static void
set_offset70F(struct rtl8125_private *tp, u8 setting)
{
        u32 csi_tmp;
        u32 temp = (u32)setting;
        temp = temp << 24;
        /*set PCI configuration space offset 0x70F to setting*/
        /*When the register offset of PCI configuration space larger than 0xff, use CSI to access it.*/

        csi_tmp = rtl8125_csi_read(tp, 0x70c) & 0x00ffffff;
        rtl8125_csi_write(tp, 0x70c, csi_tmp | temp);
}

static void
set_offset79(struct rtl8125_private *tp, u8 setting)
{
        //Set PCI configuration space offset 0x79 to setting

        struct pci_dev *pdev = tp->pci_dev;
        u8 device_control;

        if (hwoptimize & HW_PATCH_SOC_LAN) return;

        pci_read_config_byte(pdev, 0x79, &device_control);
        device_control &= ~0x70;
        device_control |= setting;
        pci_write_config_byte(pdev, 0x79, device_control);
}

void
rtl8125_hw_set_rx_packet_filter(struct net_device *dev)
{
        struct rtl8125_private *tp = netdev_priv(dev);
        u32 mc_filter[2];   /* Multicast hash filter */
        int rx_mode;
        u32 tmp = 0;

        if (dev->flags & IFF_PROMISC) {
                /* Unconditionally log net taps. */
                if (netif_msg_link(tp))
                        printk(KERN_NOTICE "%s: Promiscuous mode enabled.\n",
                               dev->name);

                rx_mode =
                        AcceptBroadcast | AcceptMulticast | AcceptMyPhys |
                        AcceptAllPhys;
                mc_filter[1] = mc_filter[0] = 0xffffffff;
        } else if ((netdev_mc_count(dev) > multicast_filter_limit)
                   || (dev->flags & IFF_ALLMULTI)) {
                /* Too many to filter perfectly -- accept all multicasts. */
                rx_mode = AcceptBroadcast | AcceptMulticast | AcceptMyPhys;
                mc_filter[1] = mc_filter[0] = 0xffffffff;
        } else {
#if LINUX_VERSION_CODE < KERNEL_VERSION(2,6,35)
                struct dev_mc_list *mclist;
                unsigned int i;

                rx_mode = AcceptBroadcast | AcceptMyPhys;
                mc_filter[1] = mc_filter[0] = 0;
                for (i = 0, mclist = dev->mc_list; mclist && i < dev->mc_count;
                     i++, mclist = mclist->next) {
                        int bit_nr = ether_crc(ETH_ALEN, mclist->dmi_addr) >> 26;
                        mc_filter[bit_nr >> 5] |= 1 << (bit_nr & 31);
                        rx_mode |= AcceptMulticast;
                }
#else
                struct netdev_hw_addr *ha;

                rx_mode = AcceptBroadcast | AcceptMyPhys;
                mc_filter[1] = mc_filter[0] = 0;
                netdev_for_each_mc_addr(ha, dev) {
                        int bit_nr = ether_crc(ETH_ALEN, ha->addr) >> 26;
                        mc_filter[bit_nr >> 5] |= 1 << (bit_nr & 31);
                        rx_mode |= AcceptMulticast;
                }
#endif
        }

        if (dev->features & NETIF_F_RXALL)
                rx_mode |= (AcceptErr | AcceptRunt);

        tmp = mc_filter[0];
        mc_filter[0] = swab32(mc_filter[1]);
        mc_filter[1] = swab32(tmp);

        tmp = tp->rtl8125_rx_config | rx_mode | (RTL_R32(tp, RxConfig) & rtl_chip_info[tp->chipset].RxConfigMask);

        if (dev->features & NETIF_F_HW_VLAN_RX)
                tmp |= (EnableInnerVlan | EnableOuterVlan);
        else
                tmp &= ~(EnableInnerVlan | EnableOuterVlan);

        RTL_W32(tp, RxConfig, tmp);
        RTL_W32(tp, MAR0 + 0, mc_filter[0]);
        RTL_W32(tp, MAR0 + 4, mc_filter[1]);
}

static void
rtl8125_set_rx_mode(struct net_device *dev)
{
        struct rtl8125_private *tp = netdev_priv(dev);
        unsigned long flags;

        spin_lock_irqsave(&tp->lock, flags);

        rtl8125_hw_set_rx_packet_filter(dev);

        spin_unlock_irqrestore(&tp->lock, flags);
}

void
rtl8125_set_rx_q_num(struct rtl8125_private *tp,
                     unsigned int num_rx_queues)
{
        u16 q_ctrl;
        u16 rx_q_num;

        rx_q_num = (u16)ilog2(num_rx_queues);
        rx_q_num &= (BIT_0 | BIT_1 | BIT_2);
        rx_q_num <<= 2;
        q_ctrl = RTL_R16(tp, Q_NUM_CTRL_8125);
        q_ctrl &= ~(BIT_2 | BIT_3 | BIT_4);
        q_ctrl |= rx_q_num;
        RTL_W16(tp, Q_NUM_CTRL_8125, q_ctrl);
}

void
rtl8125_set_tx_q_num(struct rtl8125_private *tp,
                     unsigned int num_tx_queues)
{
        u16 mac_ocp_data;

        mac_ocp_data = rtl8125_mac_ocp_read(tp, 0xE63E);
        mac_ocp_data &= ~(BIT_11 | BIT_10);
        mac_ocp_data |= ((ilog2(num_tx_queues) & 0x03) << 10);
        rtl8125_mac_ocp_write(tp, 0xE63E, mac_ocp_data);
}

void
rtl8125_hw_config(struct net_device *dev)
{
        struct rtl8125_private *tp = netdev_priv(dev);
        struct pci_dev *pdev = tp->pci_dev;
        u16 mac_ocp_data;
        int i;

        RTL_W32(tp, RxConfig, (RX_DMA_BURST << RxCfgDMAShift));

        rtl8125_hw_reset(dev);

        rtl8125_enable_cfg9346_write(tp);
        switch (tp->mcfg) {
        case CFG_METHOD_2:
        case CFG_METHOD_3:
        case CFG_METHOD_4:
        case CFG_METHOD_5:
                RTL_W8(tp, 0xF1, RTL_R8(tp, 0xF1) & ~BIT_7);
                RTL_W8(tp, Config2, RTL_R8(tp, Config2) & ~BIT_7);
                RTL_W8(tp, Config5, RTL_R8(tp, Config5) & ~BIT_0);
                break;
        }

        //clear io_rdy_l23
        switch (tp->mcfg) {
        case CFG_METHOD_2:
        case CFG_METHOD_3:
        case CFG_METHOD_4:
        case CFG_METHOD_5:
                RTL_W8(tp, Config3, RTL_R8(tp, Config3) & ~BIT_1);
                break;
        }

        switch (tp->mcfg) {
        case CFG_METHOD_2:
        case CFG_METHOD_3:
        case CFG_METHOD_4:
        case CFG_METHOD_5:
                //IntMITI_0-IntMITI_31
                for (i=0xA00; i<0xB00; i+=4)
                        RTL_W32(tp, i, 0x00000000);
                break;
        }

        //keep magic packet only
        switch (tp->mcfg) {
        case CFG_METHOD_2:
        case CFG_METHOD_3:
        case CFG_METHOD_4:
        case CFG_METHOD_5:
                mac_ocp_data = rtl8125_mac_ocp_read(tp, 0xC0B6);
                mac_ocp_data &= BIT_0;
                rtl8125_mac_ocp_write(tp, 0xC0B6, mac_ocp_data);
                break;
        }

        rtl8125_tally_counter_addr_fill(tp);

        rtl8125_desc_addr_fill(tp);

        /* Set DMA burst size and Interframe Gap Time */
        RTL_W32(tp, TxConfig, (TX_DMA_BURST_unlimited << TxDMAShift) |
                (InterFrameGap << TxInterFrameGapShift));

        if (tp->EnableTxNoClose)
                RTL_W32(tp, TxConfig, (RTL_R32(tp, TxConfig) | BIT_6));

        if (tp->mcfg == CFG_METHOD_2 ||
            tp->mcfg == CFG_METHOD_3 ||
            tp->mcfg == CFG_METHOD_4 ||
            tp->mcfg == CFG_METHOD_5) {
                set_offset70F(tp, 0x27);
                set_offset79(tp, 0x50);

                RTL_W16(tp, 0x382, 0x221B);

#ifdef ENABLE_RSS_SUPPORT
                rtl8125_config_rss(tp);
#else
                RTL_W32(tp, RSS_CTRL_8125, 0x00);
#endif
                rtl8125_set_rx_q_num(tp, rtl8125_tot_rx_rings(tp));

                RTL_W8(tp, Config1, RTL_R8(tp, Config1) & ~0x10);

                rtl8125_mac_ocp_write(tp, 0xC140, 0xFFFF);
                rtl8125_mac_ocp_write(tp, 0xC142, 0xFFFF);

                //new tx desc format
                mac_ocp_data = rtl8125_mac_ocp_read(tp, 0xEB58);
                mac_ocp_data |= (BIT_0);
                rtl8125_mac_ocp_write(tp, 0xEB58, mac_ocp_data);

                mac_ocp_data = rtl8125_mac_ocp_read(tp, 0xE614);
                mac_ocp_data &= ~( BIT_10 | BIT_9 | BIT_8);
                if (tp->mcfg == CFG_METHOD_4 || tp->mcfg == CFG_METHOD_5) {
                        mac_ocp_data |= ((2 & 0x07) << 8);
                } else {
                        if (tp->DASH && !(rtl8125_csi_fun0_read_byte(tp, 0x79) & BIT_0))
                                mac_ocp_data |= ((3 & 0x07) << 8);
                        else
                                mac_ocp_data |= ((4 & 0x07) << 8);
                }
                rtl8125_mac_ocp_write(tp, 0xE614, mac_ocp_data);

                rtl8125_set_tx_q_num(tp, rtl8125_tot_tx_rings(tp));

                mac_ocp_data = rtl8125_mac_ocp_read(tp, 0xE63E);
                mac_ocp_data &= ~(BIT_5 | BIT_4);
                if (tp->mcfg == CFG_METHOD_2 || tp->mcfg == CFG_METHOD_3)
                        mac_ocp_data |= ((0x02 & 0x03) << 4);
                rtl8125_mac_ocp_write(tp, 0xE63E, mac_ocp_data);

                mac_ocp_data = rtl8125_mac_ocp_read(tp, 0xC0B4);
                mac_ocp_data &= ~BIT_0;
                rtl8125_mac_ocp_write(tp, 0xC0B4, mac_ocp_data);
                mac_ocp_data |= BIT_0;
                rtl8125_mac_ocp_write(tp, 0xC0B4, mac_ocp_data);

                mac_ocp_data = rtl8125_mac_ocp_read(tp, 0xC0B4);
                mac_ocp_data |= (BIT_3|BIT_2);
                rtl8125_mac_ocp_write(tp, 0xC0B4, mac_ocp_data);

                mac_ocp_data = rtl8125_mac_ocp_read(tp, 0xEB6A);
                mac_ocp_data &= ~(BIT_7 | BIT_6 | BIT_5 | BIT_4 | BIT_3 | BIT_2 | BIT_1 | BIT_0);
                mac_ocp_data |= (BIT_5 | BIT_4 | BIT_1 | BIT_0);
                rtl8125_mac_ocp_write(tp, 0xEB6A, mac_ocp_data);

                mac_ocp_data = rtl8125_mac_ocp_read(tp, 0xEB50);
                mac_ocp_data &= ~(BIT_9 | BIT_8 | BIT_7 | BIT_6 | BIT_5);
                mac_ocp_data |= (BIT_6);
                rtl8125_mac_ocp_write(tp, 0xEB50, mac_ocp_data);

                mac_ocp_data = rtl8125_mac_ocp_read(tp, 0xE056);
                mac_ocp_data &= ~(BIT_7 | BIT_6 | BIT_5 | BIT_4);
                //mac_ocp_data |= (BIT_4 | BIT_5);
                rtl8125_mac_ocp_write(tp, 0xE056, mac_ocp_data);

                RTL_W8(tp, TDFNR, 0x10);

                RTL_W8(tp, 0xD0, RTL_R8(tp, 0xD0) | BIT_7);

                mac_ocp_data = rtl8125_mac_ocp_read(tp, 0xE040);
                mac_ocp_data &= ~(BIT_12);
                rtl8125_mac_ocp_write(tp, 0xE040, mac_ocp_data);

                mac_ocp_data = rtl8125_mac_ocp_read(tp, 0xEA1C);
                mac_ocp_data &= ~(BIT_1 | BIT_0);
                mac_ocp_data |= (BIT_0);
                rtl8125_mac_ocp_write(tp, 0xEA1C, mac_ocp_data);

                rtl8125_mac_ocp_write(tp, 0xE0C0, 0x4000);

                SetMcuAccessRegBit(tp, 0xE052, (BIT_6 | BIT_5));
                ClearMcuAccessRegBit(tp, 0xE052, BIT_3 | BIT_7);

                mac_ocp_data = rtl8125_mac_ocp_read(tp, 0xD430);
                mac_ocp_data &= ~(BIT_11 | BIT_10 | BIT_9 | BIT_8 | BIT_7 | BIT_6 | BIT_5 | BIT_4 | BIT_3 | BIT_2 | BIT_1 | BIT_0);
                mac_ocp_data |= 0x45F;
                rtl8125_mac_ocp_write(tp, 0xD430, mac_ocp_data);

                //rtl8125_mac_ocp_write(tp, 0xE0C0, 0x4F87);
                if (!tp->DASH)
                        RTL_W8(tp, 0xD0, RTL_R8(tp, 0xD0) | BIT_6 | BIT_7);
                else
                        RTL_W8(tp, 0xD0, (RTL_R8(tp, 0xD0) & ~BIT_6) | BIT_7);

                if (tp->mcfg == CFG_METHOD_2 || tp->mcfg == CFG_METHOD_3)
                        RTL_W8(tp, 0xD3, RTL_R8(tp, 0xD3) | BIT_0);

                rtl8125_disable_eee_plus(tp);

                mac_ocp_data = rtl8125_mac_ocp_read(tp, 0xEA1C);
                mac_ocp_data &= ~(BIT_2);
                rtl8125_mac_ocp_write(tp, 0xEA1C, mac_ocp_data);

                SetMcuAccessRegBit(tp, 0xEB54, BIT_0);
                udelay(1);
                ClearMcuAccessRegBit(tp, 0xEB54, BIT_0);
                RTL_W16(tp, 0x1880, RTL_R16(tp, 0x1880) & ~(BIT_4 | BIT_5));
        }

        /* csum offload command for RTL8125 */
        tp->tx_tcp_csum_cmd = TxTCPCS_C;
        tp->tx_udp_csum_cmd = TxUDPCS_C;
        tp->tx_ip_csum_cmd = TxIPCS_C;
        tp->tx_ipv6_csum_cmd = TxIPV6F_C;

        /* config interrupt type for RTL8125B */
        if (tp->HwSuppIsrVer == 2)
                rtl8125_hw_set_interrupt_type(tp, tp->HwCurrIsrVer);

        //other hw parameters
        rtl8125_hw_clear_timer_int(dev);

        rtl8125_hw_clear_int_miti(dev);

        if (tp->use_timer_interrrupt &&
            (tp->HwCurrIsrVer == 2) &&
            (tp->HwSuppIntMitiVer == 4) &&
            (tp->features & RTL_FEATURE_MSIX)) {
                int i;
                for (i = 0; i < tp->irq_nvecs; i++)
                        rtl8125_hw_set_timer_int_8125(tp, i, timer_count_v2);
        }

        rtl8125_enable_exit_l1_mask(tp);

        switch (tp->mcfg) {
        case CFG_METHOD_2:
        case CFG_METHOD_3:
        case CFG_METHOD_4:
        case CFG_METHOD_5:
                rtl8125_mac_ocp_write(tp, 0xE098, 0xC302);
                break;
        }

        switch (tp->mcfg) {
        case CFG_METHOD_2:
        case CFG_METHOD_3:
        case CFG_METHOD_4:
        case CFG_METHOD_5:
                if (aspm) {
                        rtl8125_init_pci_offset_99(tp);
                }
                break;
        }
        switch (tp->mcfg) {
        case CFG_METHOD_2:
        case CFG_METHOD_3:
        case CFG_METHOD_4:
        case CFG_METHOD_5:
                if (aspm) {
                        rtl8125_init_pci_offset_180(tp);
                }
                break;
        }

        tp->cp_cmd &= ~(EnableBist | Macdbgo_oe | Force_halfdup |
                        Force_rxflow_en | Force_txflow_en | Cxpl_dbg_sel |
                        ASF | Macdbgo_sel);

#if LINUX_VERSION_CODE < KERNEL_VERSION(3,0,0)
        RTL_W16(tp, CPlusCmd, tp->cp_cmd);
#else
        rtl8125_hw_set_features(dev, dev->features);
#endif

        switch (tp->mcfg) {
        case CFG_METHOD_2:
        case CFG_METHOD_3:
        case CFG_METHOD_4:
        case CFG_METHOD_5: {
                int timeout;
                for (timeout = 0; timeout < 10; timeout++) {
                        if ((rtl8125_mac_ocp_read(tp, 0xE00E) & BIT_13)==0)
                                break;
                        mdelay(1);
                }
        }
        break;
        }

        RTL_W16(tp, RxMaxSize, tp->rx_buf_sz);

        rtl8125_disable_rxdvgate(dev);

        if (!tp->pci_cfg_is_read) {
                pci_read_config_byte(pdev, PCI_COMMAND, &tp->pci_cfg_space.cmd);
                pci_read_config_word(pdev, PCI_BASE_ADDRESS_0, &tp->pci_cfg_space.io_base_l);
                pci_read_config_word(pdev, PCI_BASE_ADDRESS_0 + 2, &tp->pci_cfg_space.io_base_h);
                pci_read_config_word(pdev, PCI_BASE_ADDRESS_2, &tp->pci_cfg_space.mem_base_l);
                pci_read_config_word(pdev, PCI_BASE_ADDRESS_2 + 2, &tp->pci_cfg_space.mem_base_h);
                pci_read_config_word(pdev, PCI_BASE_ADDRESS_3, &tp->pci_cfg_space.resv_0x1c_l);
                pci_read_config_word(pdev, PCI_BASE_ADDRESS_3 + 2, &tp->pci_cfg_space.resv_0x1c_h);
                pci_read_config_byte(pdev, PCI_INTERRUPT_LINE, &tp->pci_cfg_space.ilr);
                pci_read_config_word(pdev, PCI_BASE_ADDRESS_4, &tp->pci_cfg_space.resv_0x20_l);
                pci_read_config_word(pdev, PCI_BASE_ADDRESS_4 + 2, &tp->pci_cfg_space.resv_0x20_h);
                pci_read_config_word(pdev, PCI_BASE_ADDRESS_5, &tp->pci_cfg_space.resv_0x24_l);
                pci_read_config_word(pdev, PCI_BASE_ADDRESS_5 + 2, &tp->pci_cfg_space.resv_0x24_h);
                pci_read_config_word(pdev, PCI_SUBSYSTEM_VENDOR_ID, &tp->pci_cfg_space.resv_0x2c_l);
                pci_read_config_word(pdev, PCI_SUBSYSTEM_VENDOR_ID + 2, &tp->pci_cfg_space.resv_0x2c_h);
                if (tp->HwPcieSNOffset > 0) {
                        tp->pci_cfg_space.pci_sn_l = rtl8125_csi_read(tp, tp->HwPcieSNOffset);
                        tp->pci_cfg_space.pci_sn_h = rtl8125_csi_read(tp, tp->HwPcieSNOffset + 4);
                }

                tp->pci_cfg_is_read = 1;
        }

        /* Set Rx packet filter */
        rtl8125_hw_set_rx_packet_filter(dev);

#ifdef ENABLE_DASH_SUPPORT
        if (tp->DASH && !tp->dash_printer_enabled)
                NICChkTypeEnableDashInterrupt(tp);
#endif

        switch (tp->mcfg) {
        case CFG_METHOD_2:
        case CFG_METHOD_3:
        case CFG_METHOD_4:
        case CFG_METHOD_5:
                if (aspm) {
                        RTL_W8(tp, Config5, RTL_R8(tp, Config5) | BIT_0);
                        RTL_W8(tp, Config2, RTL_R8(tp, Config2) | BIT_7);
                } else {
                        RTL_W8(tp, Config2, RTL_R8(tp, Config2) & ~BIT_7);
                        RTL_W8(tp, Config5, RTL_R8(tp, Config5) & ~BIT_0);
                }
                break;
        }

        rtl8125_disable_cfg9346_write(tp);

        udelay(10);
}

void
rtl8125_hw_start(struct net_device *dev)
{
        struct rtl8125_private *tp = netdev_priv(dev);

        RTL_W8(tp, ChipCmd, CmdTxEnb | CmdRxEnb);

        rtl8125_enable_hw_interrupt(tp);

        rtl8125_lib_reset_complete(tp);
}

static int
rtl8125_change_mtu(struct net_device *dev,
                   int new_mtu)
{
        struct rtl8125_private *tp = netdev_priv(dev);
        int ret = 0;
        unsigned long flags;

#if LINUX_VERSION_CODE < KERNEL_VERSION(4,10,0)
        if (new_mtu < ETH_MIN_MTU)
                return -EINVAL;
        else if (new_mtu > tp->max_jumbo_frame_size)
                new_mtu = tp->max_jumbo_frame_size;
#endif //LINUX_VERSION_CODE < KERNEL_VERSION(4,10,0)

        spin_lock_irqsave(&tp->lock, flags);
        dev->mtu = new_mtu;
        spin_unlock_irqrestore(&tp->lock, flags);

        if (!netif_running(dev))
                goto out;

        rtl8125_down(dev);

        spin_lock_irqsave(&tp->lock, flags);

        rtl8125_set_rxbufsize(tp, dev);

        ret = rtl8125_init_ring(dev);

        if (ret < 0) {
                spin_unlock_irqrestore(&tp->lock, flags);
                goto err_out;
        }

#ifdef CONFIG_R8125_NAPI
        rtl8125_enable_napi(tp);
#endif//CONFIG_R8125_NAPI

        //rtl8125_stop_all_tx_queue(dev);
        //netif_carrier_off(dev);
        rtl8125_hw_config(dev);
        rtl8125_enable_hw_linkchg_interrupt(tp);

        rtl8125_set_speed(dev, tp->autoneg, tp->speed, tp->duplex, tp->advertising);

        spin_unlock_irqrestore(&tp->lock, flags);

        mod_timer(&tp->esd_timer, jiffies + RTL8125_ESD_TIMEOUT);
        //mod_timer(&tp->link_timer, jiffies + RTL8125_LINK_TIMEOUT);
out:
#if LINUX_VERSION_CODE >= KERNEL_VERSION(3,0,0)
        netdev_update_features(dev);
#endif

err_out:
        return ret;
}

static void
rtl8125_free_rx_skb(struct rtl8125_private *tp,
                    struct rtl8125_rx_ring *ring,
                    struct sk_buff **sk_buff,
                    struct RxDesc *desc,
                    const u32 cur_rx)
{
        struct pci_dev *pdev = tp->pci_dev;

        dma_unmap_single(&pdev->dev, ring->RxDescPhyAddr[cur_rx], tp->rx_buf_sz,
                         DMA_FROM_DEVICE);
        dev_kfree_skb(*sk_buff);
        *sk_buff = NULL;
        rtl8125_make_unusable_by_asic(tp, desc);
}

static inline void
rtl8125_mark_to_asic_v3(struct RxDescV3 *descv3,
                        u32 rx_buf_sz)
{
        u32 eor = le32_to_cpu(descv3->RxDescNormalDDWord4.opts1) & RingEnd;

        WRITE_ONCE(descv3->RxDescNormalDDWord4.opts1, cpu_to_le32(DescOwn | eor | rx_buf_sz));
}

void
rtl8125_mark_to_asic(struct rtl8125_private *tp,
                     struct RxDesc *desc,
                     u32 rx_buf_sz)
{
        if (tp->InitRxDescType == RX_DESC_RING_TYPE_3)
                rtl8125_mark_to_asic_v3((struct RxDescV3 *)desc, rx_buf_sz);
        else {
                u32 eor = le32_to_cpu(desc->opts1) & RingEnd;

                WRITE_ONCE(desc->opts1, cpu_to_le32(DescOwn | eor | rx_buf_sz));
        }
}

static inline void
rtl8125_map_to_asic(struct rtl8125_private *tp,
                    struct rtl8125_rx_ring *ring,
                    struct RxDesc *desc,
                    dma_addr_t mapping,
                    u32 rx_buf_sz,
                    const u32 cur_rx)
{
        ring->RxDescPhyAddr[cur_rx] = mapping;
        if (tp->InitRxDescType == RX_DESC_RING_TYPE_3)
                ((struct RxDescV3 *)desc)->addr = cpu_to_le64(mapping);
        else
                desc->addr = cpu_to_le64(mapping);
        wmb();
        rtl8125_mark_to_asic(tp, desc, rx_buf_sz);
}

static int
rtl8125_alloc_rx_skb(struct rtl8125_private *tp,
                     struct rtl8125_rx_ring *ring,
                     struct sk_buff **sk_buff,
                     struct RxDesc *desc,
                     int rx_buf_sz,
                     const u32 cur_rx,
                     u8 in_intr)
{
        struct sk_buff *skb;
        dma_addr_t mapping;
        int ret = 0;

        if (in_intr)
                skb = RTL_ALLOC_SKB_INTR(&tp->r8125napi[ring->index].napi, rx_buf_sz + RTK_RX_ALIGN);
        else
                skb = dev_alloc_skb(rx_buf_sz + RTK_RX_ALIGN);

        if (unlikely(!skb))
                goto err_out;

        skb_reserve(skb, RTK_RX_ALIGN);

        mapping = dma_map_single(tp_to_dev(tp), skb->data, rx_buf_sz,
                                 DMA_FROM_DEVICE);
        if (unlikely(dma_mapping_error(tp_to_dev(tp), mapping))) {
                if (unlikely(net_ratelimit()))
                        netif_err(tp, drv, tp->dev, "Failed to map RX DMA!\n");
                goto err_out;
        }

        *sk_buff = skb;
        rtl8125_map_to_asic(tp, ring, desc, mapping, rx_buf_sz, cur_rx);
out:
        return ret;

err_out:
        if (skb)
                dev_kfree_skb(skb);
        ret = -ENOMEM;
        rtl8125_make_unusable_by_asic(tp, desc);
        goto out;
}

static void
_rtl8125_rx_clear(struct rtl8125_private *tp, struct rtl8125_rx_ring *ring)
{
        int i;

        for (i = 0; i < NUM_RX_DESC; i++) {
                if (ring->Rx_skbuff[i]) {
                        rtl8125_free_rx_skb(tp,
                                            ring,
                                            ring->Rx_skbuff + i,
                                            rtl8125_get_rxdesc(tp, ring->RxDescArray, i),
                                            i);
                        ring->Rx_skbuff[i] = NULL;
                }
        }
}

void
rtl8125_rx_clear(struct rtl8125_private *tp)
{
        int i;

        for (i = 0; i < tp->num_rx_rings; i++)
                _rtl8125_rx_clear(tp, &tp->rx_ring[i]);
}

static u32
rtl8125_rx_fill(struct rtl8125_private *tp,
                struct rtl8125_rx_ring *ring,
                struct net_device *dev,
                u32 start,
                u32 end,
                u8 in_intr)
{
        u32 cur;

        for (cur = start; end - cur > 0; cur++) {
                int ret, i = cur % NUM_RX_DESC;

                if (ring->Rx_skbuff[i])
                        continue;

                ret = rtl8125_alloc_rx_skb(tp,
                                           ring,
                                           ring->Rx_skbuff + i,
                                           rtl8125_get_rxdesc(tp, ring->RxDescArray, i),
                                           tp->rx_buf_sz,
                                           i,
                                           in_intr
                                          );
                if (ret < 0)
                        break;
        }
        return cur - start;
}

static inline void
rtl8125_mark_as_last_descriptor_8125(struct RxDescV3 *descv3)
{
        descv3->RxDescNormalDDWord4.opts1 |= cpu_to_le32(RingEnd);
}

static inline void
rtl8125_mark_as_last_descriptor(struct rtl8125_private *tp,
                                struct RxDesc *desc)
{
        if (tp->InitRxDescType == RX_DESC_RING_TYPE_3)
                rtl8125_mark_as_last_descriptor_8125((struct RxDescV3 *)desc);
        else
                desc->opts1 |= cpu_to_le32(RingEnd);
}

static void
rtl8125_desc_addr_fill(struct rtl8125_private *tp)
{
        int i;

        for (i = 0; i < tp->num_tx_rings; i++) {
                struct rtl8125_tx_ring *ring = &tp->tx_ring[i];
                RTL_W32(tp, ring->tdsar_reg, ((u64)ring->TxPhyAddr & DMA_BIT_MASK(32)));
                RTL_W32(tp, ring->tdsar_reg + 4, ((u64)ring->TxPhyAddr >> 32));
        }

        for (i = 0; i < tp->num_rx_rings; i++) {
                struct rtl8125_rx_ring *ring = &tp->rx_ring[i];
                RTL_W32(tp, ring->rdsar_reg, ((u64)ring->RxPhyAddr & DMA_BIT_MASK(32)));
                RTL_W32(tp, ring->rdsar_reg + 4, ((u64)ring->RxPhyAddr >> 32));
        }
}

static void
rtl8125_tx_desc_init(struct rtl8125_private *tp)
{
        int i = 0;

        for (i = 0; i < tp->num_tx_rings; i++) {
                struct rtl8125_tx_ring *ring = &tp->tx_ring[i];
                memset(ring->TxDescArray, 0x0, R8125_TX_RING_BYTES);

                ring->TxDescArray[NUM_TX_DESC - 1].opts1 = cpu_to_le32(RingEnd);
        }
}

static void
rtl8125_rx_desc_init(struct rtl8125_private *tp)
{
        int i;

        for (i = 0; i < tp->num_rx_rings; i++) {
                struct rtl8125_rx_ring *ring = &tp->rx_ring[i];
                memset(ring->RxDescArray, 0x0, tp->RxDescRingLength);
        }
}

int
rtl8125_init_ring(struct net_device *dev)
{
        struct rtl8125_private *tp = netdev_priv(dev);
        int i;

        rtl8125_init_ring_indexes(tp);

        rtl8125_tx_desc_init(tp);
        rtl8125_rx_desc_init(tp);

        for (i = 0; i < tp->num_tx_rings; i++) {
                struct rtl8125_tx_ring *ring = &tp->tx_ring[i];
                memset(ring->tx_skb, 0x0, NUM_TX_DESC * sizeof(struct ring_info));
        }

        for (i = 0; i < tp->num_rx_rings; i++) {
                struct rtl8125_rx_ring *ring = &tp->rx_ring[i];

                memset(ring->Rx_skbuff, 0x0, NUM_RX_DESC * sizeof(struct sk_buff *));
                if (rtl8125_rx_fill(tp, ring, dev, 0, NUM_RX_DESC, 0) != NUM_RX_DESC)
                        goto err_out;

                rtl8125_mark_as_last_descriptor(tp, rtl8125_get_rxdesc(tp, ring->RxDescArray, NUM_RX_DESC - 1));
        }

        return 0;

err_out:
        rtl8125_rx_clear(tp);
        return -ENOMEM;
}

static void
rtl8125_unmap_tx_skb(struct pci_dev *pdev,
                     struct ring_info *tx_skb,
                     struct TxDesc *desc)
{
        unsigned int len = tx_skb->len;

        dma_unmap_single(&pdev->dev, le64_to_cpu(desc->addr), len, DMA_TO_DEVICE);

        desc->opts1 = cpu_to_le32(RTK_MAGIC_DEBUG_VALUE);
        desc->opts2 = 0x00;
        desc->addr = RTL8125_MAGIC_NUMBER;
        tx_skb->len = 0;
}

static void
rtl8125_tx_clear_range(struct rtl8125_private *tp,
                       struct rtl8125_tx_ring *ring,
                       u32 start,
                       unsigned int n)
{
        unsigned int i;
#if LINUX_VERSION_CODE >= KERNEL_VERSION(2,6,22)
        struct net_device *dev = tp->dev;
#endif

        for (i = 0; i < n; i++) {
                unsigned int entry = (start + i) % NUM_TX_DESC;
                struct ring_info *tx_skb = ring->tx_skb + entry;
                unsigned int len = tx_skb->len;

                if (len) {
                        struct sk_buff *skb = tx_skb->skb;

                        rtl8125_unmap_tx_skb(tp->pci_dev, tx_skb,
                                             ring->TxDescArray + entry);
                        if (skb) {
                                RTLDEV->stats.tx_dropped++;
                                dev_kfree_skb_any(skb);
                                tx_skb->skb = NULL;
                        }
                }
        }
}

void
rtl8125_tx_clear(struct rtl8125_private *tp)
{
        int i;

        for (i = 0; i < tp->num_tx_rings; i++) {
                struct rtl8125_tx_ring *ring = &tp->tx_ring[i];
                rtl8125_tx_clear_range(tp, ring, ring->dirty_tx, NUM_TX_DESC);
                ring->cur_tx = ring->dirty_tx = 0;
        }
}

#if LINUX_VERSION_CODE < KERNEL_VERSION(2,6,20)
static void rtl8125_schedule_work(struct net_device *dev, void (*task)(void *))
{
#if LINUX_VERSION_CODE > KERNEL_VERSION(2,6,0)
        struct rtl8125_private *tp = netdev_priv(dev);

        INIT_WORK(&tp->task, task, dev);
        schedule_delayed_work(&tp->task, 4);
#endif //LINUX_VERSION_CODE > KERNEL_VERSION(2,6,0)
}

#define rtl8125_cancel_schedule_work(a)

#else
static void rtl8125_schedule_work(struct net_device *dev, work_func_t task)
{
        struct rtl8125_private *tp = netdev_priv(dev);

        INIT_DELAYED_WORK(&tp->task, task);
        schedule_delayed_work(&tp->task, 4);
}

static void rtl8125_cancel_schedule_work(struct net_device *dev)
{
        struct rtl8125_private *tp = netdev_priv(dev);
        struct work_struct *work = &tp->task.work;

        if (!work->func) return;

        cancel_delayed_work_sync(&tp->task);
}
#endif

static void
rtl8125_wait_for_irq_complete(struct rtl8125_private *tp)
{
        if (tp->features & RTL_FEATURE_MSIX) {
                int i;
                for (i = 0; i < tp->irq_nvecs; i++)
                        synchronize_irq(tp->irq_tbl[i].vector);
        } else {
                synchronize_irq(tp->dev->irq);
        }
}

static void
_rtl8125_wait_for_quiescence(struct net_device *dev)
{
        struct rtl8125_private *tp = netdev_priv(dev);
        unsigned long flags;

        /* Wait for any pending NAPI task to complete */
#ifdef CONFIG_R8125_NAPI
        rtl8125_disable_napi(tp);
#endif//CONFIG_R8125_NAPI

#if LINUX_VERSION_CODE > KERNEL_VERSION(2,5,67)
        /* Give a racing hard_start_xmit a few cycles to complete. */
        synchronize_net();
#endif
        spin_lock_irqsave(&tp->lock, flags);

        rtl8125_irq_mask_and_ack(tp);

        spin_unlock_irqrestore(&tp->lock, flags);

        rtl8125_wait_for_irq_complete(tp);
}

static void
rtl8125_wait_for_quiescence(struct net_device *dev)
{
        struct rtl8125_private *tp = netdev_priv(dev);

        //suppress unused variable
        (void)(tp);

        _rtl8125_wait_for_quiescence(dev);

#ifdef CONFIG_R8125_NAPI
        rtl8125_enable_napi(tp);
#endif//CONFIG_R8125_NAPI
}

#if 0
#if LINUX_VERSION_CODE < KERNEL_VERSION(2,6,20)
static void rtl8125_reinit_task(void *_data)
#else
static void rtl8125_reinit_task(struct work_struct *work)
#endif
{
#if LINUX_VERSION_CODE < KERNEL_VERSION(2,6,20)
        struct net_device *dev = _data;
#else
        struct rtl8125_private *tp =
                container_of(work, struct rtl8125_private, task.work);
        struct net_device *dev = tp->dev;
#endif
        int ret;

        if (netif_running(dev)) {
                rtl8125_wait_for_quiescence(dev);
                rtl8125_close(dev);
        }

        ret = rtl8125_open(dev);
        if (unlikely(ret < 0)) {
                if (unlikely(net_ratelimit())) {
                        struct rtl8125_private *tp = netdev_priv(dev);

                        if (netif_msg_drv(tp)) {
                                printk(PFX KERN_ERR
                                       "%s: reinit failure (status = %d)."
                                       " Rescheduling.\n", dev->name, ret);
                        }
                }
                rtl8125_schedule_work(dev, rtl8125_reinit_task);
        }
}
#endif

static int rtl8125_rx_nostuck(struct rtl8125_private *tp)
{
        int i, ret = 1;
        for (i = 0; i < tp->num_rx_rings; i++)
                ret &= (tp->rx_ring[i].dirty_rx == tp->rx_ring[i].cur_rx);
        return ret;
}

#if LINUX_VERSION_CODE < KERNEL_VERSION(2,6,20)
static void rtl8125_reset_task(void *_data)
{
        struct net_device *dev = _data;
        struct rtl8125_private *tp = netdev_priv(dev);
#else
static void rtl8125_reset_task(struct work_struct *work)
{
        struct rtl8125_private *tp =
                container_of(work, struct rtl8125_private, task.work);
        struct net_device *dev = tp->dev;
#endif
        u32 budget = ~(u32)0;
        unsigned long flags;
        int i;

        if (!netif_running(dev))
                return;

        rtl8125_wait_for_quiescence(dev);

        for (i = 0; i < tp->num_rx_rings; i++) {
#if LINUX_VERSION_CODE < KERNEL_VERSION(2,6,24)
                rtl8125_rx_interrupt(dev, tp,  &tp->rx_ring[i], &budget);
#else
                rtl8125_rx_interrupt(dev, tp,  &tp->rx_ring[i], budget);
#endif	//LINUX_VERSION_CODE < KERNEL_VERSION(2,6,24)
        }

        spin_lock_irqsave(&tp->lock, flags);

        rtl8125_tx_clear(tp);

        if (rtl8125_rx_nostuck(tp)) {
                rtl8125_rx_clear(tp);
                rtl8125_init_ring(dev);
#ifdef ENABLE_PTP_SUPPORT
                rtl8125_ptp_reset(tp);
#endif
                rtl8125_enable_hw_linkchg_interrupt(tp);

                rtl8125_set_speed(dev, tp->autoneg, tp->speed, tp->duplex, tp->advertising);
                spin_unlock_irqrestore(&tp->lock, flags);
        } else {
                spin_unlock_irqrestore(&tp->lock, flags);
                if (unlikely(net_ratelimit())) {
                        struct rtl8125_private *tp = netdev_priv(dev);

                        if (netif_msg_intr(tp)) {
                                printk(PFX KERN_EMERG
                                       "%s: Rx buffers shortage\n", dev->name);
                        }
                }
                rtl8125_schedule_work(dev, rtl8125_reset_task);
        }
}
#if LINUX_VERSION_CODE >= KERNEL_VERSION(5,6,0)
static void
rtl8125_tx_timeout(struct net_device *dev, unsigned int txqueue)
#else
static void
rtl8125_tx_timeout(struct net_device *dev)
#endif
{
        struct rtl8125_private *tp = netdev_priv(dev);
        unsigned long flags;

        spin_lock_irqsave(&tp->lock, flags);
        rtl8125_stop_all_tx_queue(dev);
        netif_carrier_off(dev);
        rtl8125_hw_reset(dev);
        spin_unlock_irqrestore(&tp->lock, flags);

        /* Let's wait a bit while any (async) irq lands on */
        rtl8125_schedule_work(dev, rtl8125_reset_task);
}

static u32
rtl8125_get_txd_opts1(u32 opts1, u32 len, unsigned int entry)
{
        u32 status = opts1 | len;

        if (entry == NUM_TX_DESC - 1)
                status |= RingEnd;

        return status;
}

static int
rtl8125_xmit_frags(struct rtl8125_private *tp,
                   struct rtl8125_tx_ring *ring,
                   struct sk_buff *skb,
                   const u32 *opts)
{
        struct skb_shared_info *info = skb_shinfo(skb);
        unsigned int cur_frag, entry;
        struct TxDesc *txd = NULL;
        const unsigned char nr_frags = info->nr_frags;
        unsigned long PktLenCnt = 0;
        bool LsoPatchEnabled = FALSE;

        entry = ring->cur_tx;
        for (cur_frag = 0; cur_frag < nr_frags; cur_frag++) {
                skb_frag_t *frag = info->frags + cur_frag;
                dma_addr_t mapping;
                u32 status, len;
                void *addr;

                entry = (entry + 1) % NUM_TX_DESC;

                txd = ring->TxDescArray + entry;
#if LINUX_VERSION_CODE < KERNEL_VERSION(3,2,0)
                len = frag->size;
                addr = ((void *) page_address(frag->page)) + frag->page_offset;
#else
                len = skb_frag_size(frag);
                addr = skb_frag_address(frag);
#endif
                if (tp->RequireLSOPatch  &&
                    (cur_frag == nr_frags - 1) &&
                    (opts[0] & (GiantSendv4|GiantSendv6)) &&
                    PktLenCnt < ETH_FRAME_LEN &&
                    len > 1) {
                        len -= 1;
                        mapping = dma_map_single(tp_to_dev(tp), addr, len, DMA_TO_DEVICE);

                        if (unlikely(dma_mapping_error(tp_to_dev(tp), mapping))) {
                                if (unlikely(net_ratelimit()))
                                        netif_err(tp, drv, tp->dev,
                                                  "Failed to map TX fragments DMA!\n");
                                goto err_out;
                        }

                        /* anti gcc 2.95.3 bugware (sic) */
                        status = rtl8125_get_txd_opts1(opts[0], len, entry);

                        txd->addr = cpu_to_le64(mapping);

                        ring->tx_skb[entry].len = len;

                        txd->opts2 = cpu_to_le32(opts[1]);
                        wmb();
                        txd->opts1 = cpu_to_le32(status);

                        //second txd
                        addr += len;
                        len = 1;
                        entry = (entry + 1) % NUM_TX_DESC;
                        txd = ring->TxDescArray + entry;
                        cur_frag += 1;

                        LsoPatchEnabled = TRUE;
                }

                mapping = dma_map_single(tp_to_dev(tp), addr, len, DMA_TO_DEVICE);

                if (unlikely(dma_mapping_error(tp_to_dev(tp), mapping))) {
                        if (unlikely(net_ratelimit()))
                                netif_err(tp, drv, tp->dev,
                                          "Failed to map TX fragments DMA!\n");
                        goto err_out;
                }

                /* anti gcc 2.95.3 bugware (sic) */
                status = rtl8125_get_txd_opts1(opts[0], len, entry);
                if (cur_frag == (nr_frags - 1) || LsoPatchEnabled == TRUE) {
                        //ring->tx_skb[entry].skb = skb;
                        status |= LastFrag;
                }

                txd->addr = cpu_to_le64(mapping);

                ring->tx_skb[entry].len = len;

                txd->opts2 = cpu_to_le32(opts[1]);
                wmb();
                txd->opts1 = cpu_to_le32(status);

                PktLenCnt += len;
        }

        return cur_frag;

err_out:
        rtl8125_tx_clear_range(tp, ring, ring->cur_tx + 1, cur_frag);
        return -EIO;
}

static inline
__be16 get_protocol(struct sk_buff *skb)
{
#if LINUX_VERSION_CODE >= KERNEL_VERSION(2,6,37)
        return vlan_get_protocol(skb);
#else
        __be16 protocol;

        if (skb->protocol == htons(ETH_P_8021Q))
                protocol = vlan_eth_hdr(skb)->h_vlan_encapsulated_proto;
        else
                protocol = skb->protocol;

        return protocol;
#endif
}

static inline
u8 rtl8125_get_l4_protocol(struct sk_buff *skb)
{
        int no = skb_network_offset(skb);
        struct ipv6hdr *i6h, _i6h;
        struct iphdr *ih, _ih;
        u8 ip_protocol = IPPROTO_RAW;

        switch (get_protocol(skb)) {
        case  __constant_htons(ETH_P_IP):
                ih = skb_header_pointer(skb, no, sizeof(_ih), &_ih);
                if (ih)
                        ip_protocol = ih->protocol;
                break;
        case  __constant_htons(ETH_P_IPV6):
                i6h = skb_header_pointer(skb, no, sizeof(_i6h), &_i6h);
                if (i6h)
                        ip_protocol = i6h->nexthdr;
                break;
        }

        return ip_protocol;
}

static bool rtl8125_skb_pad_with_len(struct sk_buff *skb, unsigned int len)
{
        if (skb_padto(skb, len))
                return false;
        skb_put(skb, len - skb->len);
        return true;
}

static bool rtl8125_skb_pad(struct sk_buff *skb)
{
#if LINUX_VERSION_CODE < KERNEL_VERSION(3,19,0)
        return rtl8125_skb_pad_with_len(skb, ETH_ZLEN);
#else
        return !eth_skb_pad(skb);
#endif
}

#if LINUX_VERSION_CODE >= KERNEL_VERSION(3,14,0)
/* msdn_giant_send_check()
 * According to the document of microsoft, the TCP Pseudo Header excludes the
 * packet length for IPv6 TCP large packets.
 */
static int msdn_giant_send_check(struct sk_buff *skb)
{
        const struct ipv6hdr *ipv6h;
        struct tcphdr *th;
        int ret;

        ret = skb_cow_head(skb, 0);
        if (ret)
                return ret;

        ipv6h = ipv6_hdr(skb);
        th = tcp_hdr(skb);

        th->check = 0;
        th->check = ~tcp_v6_check(0, &ipv6h->saddr, &ipv6h->daddr, 0);

        return ret;
}
#endif

#define MIN_PATCH_LEN (47)
static u32
rtl8125_get_patch_pad_len(struct sk_buff *skb)
{
        u32 pad_len = 0;
        int trans_data_len;
        u32 hdr_len;
        u32 pkt_len = skb->len;
        u8 ip_protocol;
        bool has_trans = skb_transport_header_was_set(skb);

        if (!(has_trans && (pkt_len < 175))) //128 + MIN_PATCH_LEN
                goto no_padding;

        ip_protocol = rtl8125_get_l4_protocol(skb);
        if (!(ip_protocol == IPPROTO_TCP || ip_protocol == IPPROTO_UDP))
                goto no_padding;

        trans_data_len = pkt_len -
                         (skb->transport_header -
                          skb_headroom(skb));
        if (ip_protocol == IPPROTO_UDP) {
                if (trans_data_len > 3 && trans_data_len < MIN_PATCH_LEN) {
                        u16 dest_port = 0;

                        skb_copy_bits(skb, skb->transport_header - skb_headroom(skb) + 2, &dest_port, 2);
                        dest_port = ntohs(dest_port);

                        if (dest_port == 0x13f ||
                            dest_port == 0x140) {
                                pad_len = MIN_PATCH_LEN - trans_data_len;
                                goto out;
                        }
                }
        }

        hdr_len = 0;
        if (ip_protocol == IPPROTO_TCP)
                hdr_len = 20;
        else if (ip_protocol == IPPROTO_UDP)
                hdr_len = 8;
        if (trans_data_len < hdr_len)
                pad_len = hdr_len - trans_data_len;

out:
        if ((pkt_len + pad_len) < ETH_ZLEN)
                pad_len = ETH_ZLEN - pkt_len;

        return pad_len;

no_padding:

        return 0;
}

static bool
rtl8125_tso_csum(struct sk_buff *skb,
                 struct net_device *dev,
                 u32 *opts)
{
        struct rtl8125_private *tp = netdev_priv(dev);
        unsigned long large_send = 0;
        u32 csum_cmd = 0;
        u8 sw_calc_csum = false;
        u8 check_patch_required = true;

#if LINUX_VERSION_CODE > KERNEL_VERSION(2,6,0)
        if (dev->features & (NETIF_F_TSO | NETIF_F_TSO6)) {
#if LINUX_VERSION_CODE < KERNEL_VERSION(2,6,18)
                u32 mss = skb_shinfo(skb)->tso_size;
#else
                u32 mss = skb_shinfo(skb)->gso_size;
#endif //LINUX_VERSION_CODE < KERNEL_VERSION(2,6,18)

                /* TCP Segmentation Offload (or TCP Large Send) */
                if (mss) {
                        u32 transport_offset = (u32)skb_transport_offset(skb);
                        assert((transport_offset%2) == 0);
                        switch (get_protocol(skb)) {
                        case __constant_htons(ETH_P_IP):
                                if (transport_offset <= GTTCPHO_MAX) {
                                        opts[0] |= GiantSendv4;
                                        opts[0] |= transport_offset << GTTCPHO_SHIFT;
                                        opts[1] |= min(mss, MSS_MAX) << 18;
                                        large_send = 1;
                                }
                                break;
                        case __constant_htons(ETH_P_IPV6):
#if LINUX_VERSION_CODE >= KERNEL_VERSION(3,14,0)
                                if (msdn_giant_send_check(skb))
                                        return false;
#endif
                                if (transport_offset <= GTTCPHO_MAX) {
                                        opts[0] |= GiantSendv6;
                                        opts[0] |= transport_offset << GTTCPHO_SHIFT;
                                        opts[1] |= min(mss, MSS_MAX) << 18;
                                        large_send = 1;
                                }
                                break;
                        default:
                                if (unlikely(net_ratelimit()))
                                        dprintk("tso proto=%x!\n", skb->protocol);
                                break;
                        }

                        if (large_send == 0)
                                return false;

                        return true;
                }
        }
#endif //LINUX_VERSION_CODE > KERNEL_VERSION(2,6,0)

        if (skb->ip_summed == CHECKSUM_PARTIAL) {
#if LINUX_VERSION_CODE < KERNEL_VERSION(2,6,22)
                const struct iphdr *ip = skb->nh.iph;

                if (dev->features & NETIF_F_IP_CSUM) {
                        if (ip->protocol == IPPROTO_TCP)
                                csum_cmd = tp->tx_ip_csum_cmd | tp->tx_tcp_csum_cmd;
                        else if (ip->protocol == IPPROTO_UDP)
                                csum_cmd = tp->tx_ip_csum_cmd | tp->tx_udp_csum_cmd;
                        else if (ip->protocol == IPPROTO_IP)
                                csum_cmd = tp->tx_ip_csum_cmd;
                }
#else
                u8 ip_protocol = IPPROTO_RAW;

                switch (get_protocol(skb)) {
                case  __constant_htons(ETH_P_IP):
                        if (dev->features & NETIF_F_IP_CSUM) {
                                ip_protocol = ip_hdr(skb)->protocol;
                                csum_cmd = tp->tx_ip_csum_cmd;
                        }
                        break;
                case  __constant_htons(ETH_P_IPV6):
                        if (dev->features & NETIF_F_IPV6_CSUM) {
                                u32 transport_offset = (u32)skb_transport_offset(skb);
                                if (transport_offset > 0 && transport_offset <= TCPHO_MAX) {
                                        ip_protocol = ipv6_hdr(skb)->nexthdr;
                                        csum_cmd = tp->tx_ipv6_csum_cmd;
                                        csum_cmd |= transport_offset << TCPHO_SHIFT;
                                }
                        }
                        break;
                default:
                        if (unlikely(net_ratelimit()))
                                dprintk("checksum_partial proto=%x!\n", skb->protocol);
                        break;
                }

                if (ip_protocol == IPPROTO_TCP)
                        csum_cmd |= tp->tx_tcp_csum_cmd;
                else if (ip_protocol == IPPROTO_UDP)
                        csum_cmd |= tp->tx_udp_csum_cmd;
#endif
                if (csum_cmd == 0) {
                        sw_calc_csum = true;
#if LINUX_VERSION_CODE > KERNEL_VERSION(2,6,0)
                        WARN_ON(1); /* we need a WARN() */
#endif
                }

                if (ip_protocol == IPPROTO_TCP)
                        check_patch_required = false;
        }

        if (check_patch_required) {
                u32 pad_len = rtl8125_get_patch_pad_len(skb);

                if (pad_len > 0) {
                        if (!rtl8125_skb_pad_with_len(skb, skb->len + pad_len))
                                return false;

                        if (csum_cmd != 0)
                                sw_calc_csum = true;
                }
        }

        if (skb->len < ETH_ZLEN) {
                if (tp->UseSwPaddingShortPkt ||
                    (tp->ShortPacketSwChecksum && csum_cmd != 0)) {
                        if (!rtl8125_skb_pad(skb))
                                return false;

                        if (csum_cmd != 0)
                                sw_calc_csum = true;
                }
        }

        if (sw_calc_csum) {
#if LINUX_VERSION_CODE < KERNEL_VERSION(2,6,10) && LINUX_VERSION_CODE >= KERNEL_VERSION(2,6,7)
                skb_checksum_help(&skb, 0);
#elif LINUX_VERSION_CODE < KERNEL_VERSION(2,6,19) && LINUX_VERSION_CODE >= KERNEL_VERSION(2,6,10)
                skb_checksum_help(skb, 0);
#else
                skb_checksum_help(skb);
#endif
        } else
                opts[1] |= csum_cmd;

        return true;
}

static bool rtl8125_tx_slots_avail(struct rtl8125_private *tp,
                                   struct rtl8125_tx_ring *ring)
{
        unsigned int slots_avail = READ_ONCE(ring->dirty_tx) + NUM_TX_DESC
                                   - READ_ONCE(ring->cur_tx);

        /* A skbuff with nr_frags needs nr_frags+1 entries in the tx queue */
        return slots_avail > MAX_SKB_FRAGS;
}

static netdev_tx_t
rtl8125_start_xmit(struct sk_buff *skb,
                   struct net_device *dev)
{
        struct rtl8125_private *tp = netdev_priv(dev);
        unsigned int entry;
        struct TxDesc *txd;
        dma_addr_t mapping;
        u32 len;
        u32 opts[2];
        netdev_tx_t ret = NETDEV_TX_OK;
        //unsigned long flags;
        int frags;
        u8 EnableTxNoClose = tp->EnableTxNoClose;
        const u16 queue_mapping = skb_get_queue_mapping(skb);
        struct rtl8125_tx_ring *ring;
        bool stop_queue;

        assert(queue_mapping < tp->num_tx_queues);

        ring = &tp->tx_ring[queue_mapping];

        //spin_lock_irqsave(&tp->lock, flags);

        if (unlikely(!rtl8125_tx_slots_avail(tp, ring))) {
                if (netif_msg_drv(tp)) {
                        printk(KERN_ERR
                               "%s: BUG! Tx Ring[%d] full when queue awake!\n",
                               dev->name,
                               queue_mapping);
                }
                goto err_stop;
        }

        entry = ring->cur_tx % NUM_TX_DESC;
        txd = ring->TxDescArray + entry;

        if (!EnableTxNoClose) {
                if (unlikely(le32_to_cpu(txd->opts1) & DescOwn)) {
                        if (netif_msg_drv(tp)) {
                                printk(KERN_ERR
                                       "%s: BUG! Tx Desc is own by hardware!\n",
                                       dev->name);
                        }
                        goto err_stop;
                }
        }

        opts[0] = DescOwn;
        opts[1] = rtl8125_tx_vlan_tag(tp, skb);

        if (unlikely(!rtl8125_tso_csum(skb, dev, opts)))
                goto err_dma_0;

        frags = rtl8125_xmit_frags(tp, ring, skb, opts);
        if (unlikely(frags < 0))
                goto err_dma_0;
        if (frags) {
                len = skb_headlen(skb);
                opts[0] |= FirstFrag;
        } else {
                len = skb->len;

                //ring->tx_skb[entry].skb = skb;

                opts[0] |= FirstFrag | LastFrag;
        }

        opts[0] = rtl8125_get_txd_opts1(opts[0], len, entry);
        mapping = dma_map_single(tp_to_dev(tp), skb->data, len, DMA_TO_DEVICE);
        if (unlikely(dma_mapping_error(tp_to_dev(tp), mapping))) {
                if (unlikely(net_ratelimit()))
                        netif_err(tp, drv, dev, "Failed to map TX DMA!\n");
                goto err_dma_1;
        }
        ring->tx_skb[entry].len = len;
#ifdef ENABLE_PTP_SUPPORT
        if (unlikely(skb_shinfo(skb)->tx_flags & SKBTX_HW_TSTAMP)) {
                if (tp->hwtstamp_config.tx_type == HWTSTAMP_TX_ON &&
                    !tp->ptp_tx_skb) {
                        skb_shinfo(skb)->tx_flags |= SKBTX_IN_PROGRESS;

                        tp->ptp_tx_skb = skb_get(skb);
                        tp->ptp_tx_start = jiffies;
                        schedule_work(&tp->ptp_tx_work);
                } else {
                        tp->tx_hwtstamp_skipped++;
                }
        }
#endif
        ring->tx_skb[entry].skb = skb;
        txd->addr = cpu_to_le64(mapping);
        txd->opts2 = cpu_to_le32(opts[1]);
        wmb();
        txd->opts1 = cpu_to_le32(opts[0]);

#if LINUX_VERSION_CODE < KERNEL_VERSION(3,5,0)
        dev->trans_start = jiffies;
#else
        skb_tx_timestamp(skb);
#endif //LINUX_VERSION_CODE < KERNEL_VERSION(3,5,0)

        /* rtl_tx needs to see descriptor changes before updated tp->cur_tx */
        smp_wmb();

        WRITE_ONCE(ring->cur_tx, ring->cur_tx + frags + 1);

        stop_queue = !rtl8125_tx_slots_avail(tp, ring);
        if (unlikely(stop_queue)) {
                /* Avoid wrongly optimistic queue wake-up: rtl_tx thread must
                 * not miss a ring update when it notices a stopped queue.
                 */
                smp_wmb();
                netif_stop_subqueue(dev, queue_mapping);
        }

        if (EnableTxNoClose)
                RTL_W16(tp, ring->sw_tail_ptr_reg, ring->cur_tx % MAX_TX_NO_CLOSE_DESC_PTR_V2);
        else
                RTL_W16(tp, TPPOLL_8125, BIT(ring->index));    /* set polling bit */

        if (unlikely(stop_queue)) {
                /* Sync with rtl_tx:
                 * - publish queue status and cur_tx ring index (write barrier)
                 * - refresh dirty_tx ring index (read barrier).
                 * May the current thread have a pessimistic view of the ring
                 * status and forget to wake up queue, a racing rtl_tx thread
                 * can't.
                 */
                smp_mb();
                if (rtl8125_tx_slots_avail(tp, ring))
                        netif_start_subqueue(dev, queue_mapping);
        }

        //spin_unlock_irqrestore(&tp->lock, flags);
out:
        return ret;
err_dma_1:
        ring->tx_skb[entry].skb = NULL;
        rtl8125_tx_clear_range(tp, ring, ring->cur_tx + 1, frags);
err_dma_0:
        RTLDEV->stats.tx_dropped++;
        //spin_unlock_irqrestore(&tp->lock, flags);
        dev_kfree_skb_any(skb);
        ret = NETDEV_TX_OK;
        goto out;
err_stop:
        netif_stop_subqueue(dev, queue_mapping);
        ret = NETDEV_TX_BUSY;
        RTLDEV->stats.tx_dropped++;

        //spin_unlock_irqrestore(&tp->lock, flags);
        goto out;
}

static inline u32
rtl8125_fast_mod(const u32 input, const u32 ceil)
{
        return input >= ceil ? input % ceil : input;
}

static int
rtl8125_tx_interrupt(struct rtl8125_tx_ring *ring, int budget)
{
        struct rtl8125_private *tp = ring->priv;
        struct net_device *dev = tp->dev;
        unsigned int dirty_tx, tx_left;
        unsigned int count = 0;
        u8 EnableTxNoClose = tp->EnableTxNoClose;

        dirty_tx = ring->dirty_tx;
        if (EnableTxNoClose) {
                u32 NextHwDesCloPtr = RTL_R16(tp, ring->hw_clo_ptr_reg);
                ring->NextHwDesCloPtr = NextHwDesCloPtr;
                smp_rmb();
                tx_left = rtl8125_fast_mod(NextHwDesCloPtr - ring->BeginHwDesCloPtr, MAX_TX_NO_CLOSE_DESC_PTR_V2);
                ring->BeginHwDesCloPtr = NextHwDesCloPtr;
        } else {
                smp_rmb();
                tx_left = READ_ONCE(ring->cur_tx) - dirty_tx;
        }

        while (tx_left > 0) {
                unsigned int entry = dirty_tx % NUM_TX_DESC;
                struct ring_info *tx_skb = ring->tx_skb + entry;

                if (!EnableTxNoClose &&
                    (le32_to_cpu(ring->TxDescArray[entry].opts1) & DescOwn))
                        break;

                RTLDEV->stats.tx_bytes += tx_skb->len;
                RTLDEV->stats.tx_packets++;

                rtl8125_unmap_tx_skb(tp->pci_dev,
                                     tx_skb,
                                     ring->TxDescArray + entry);

                if (tx_skb->skb != NULL) {
                        RTL_NAPI_CONSUME_SKB_ANY(tx_skb->skb, budget);
                        tx_skb->skb = NULL;
                }
                dirty_tx++;
                tx_left--;
        }

        if (ring->dirty_tx != dirty_tx) {
                count = dirty_tx - ring->dirty_tx;
                WRITE_ONCE(ring->dirty_tx, dirty_tx);
                smp_wmb();
                if (__netif_subqueue_stopped(dev, ring->index) &&
                    (rtl8125_tx_slots_avail(tp, ring))) {
                        netif_start_subqueue(dev, ring->index);
                }
                smp_rmb();
                if (!EnableTxNoClose && (ring->cur_tx != dirty_tx)) {
                        RTL_W16(tp, TPPOLL_8125, BIT(ring->index));
                }
        }

        return count;
}

static int
rtl8125_tx_interrupt_with_vector(struct rtl8125_private *tp,
                                 const int message_id,
                                 int budget)
{
        int count = 0;
        if (message_id == 16)
                count += rtl8125_tx_interrupt(&tp->tx_ring[0], budget);
        else if (message_id == 18)
                count += rtl8125_tx_interrupt(&tp->tx_ring[1], budget);

        return count;
}

static inline int
rtl8125_fragmented_frame(struct rtl8125_private *tp, u32 status)
{
        if (tp->InitRxDescType == RX_DESC_RING_TYPE_3)
                return (status & (FirstFrag_V3 | LastFrag_V3)) != (FirstFrag_V3 | LastFrag_V3);
        else
                return (status & (FirstFrag | LastFrag)) != (FirstFrag | LastFrag);
}

static inline int
rtl8125_rx_desc_type(u32 status)
{
        return ((status >> 26) & 0x0F);
}

static inline void
rtl8125_rx_v3_csum(struct rtl8125_private *tp,
                   struct sk_buff *skb,
                   struct RxDescV3 *descv3)
{
        //u32 opts1 = le32_to_cpu(descv3->RxDescNormalDDWord4.opts1);
        u32 opts2 = le32_to_cpu(descv3->RxDescNormalDDWord4.opts2);

        /* rx csum offload for RTL8125 */
        if (((opts2 & RxV4F_v3) && !(opts2 & RxIPF_v3)) || (opts2 & RxV6F_v3)) {
                if (((opts2 & RxTCPT_v3) && !(opts2 & RxTCPF_v3)) ||
                    ((opts2 & RxUDPT_v3) && !(opts2 & RxUDPF_v3)))
                        skb->ip_summed = CHECKSUM_UNNECESSARY;
                else
                        skb->ip_summed = CHECKSUM_NONE;
        } else
                skb->ip_summed = CHECKSUM_NONE;
}

static inline void
rtl8125_rx_csum(struct rtl8125_private *tp,
                struct sk_buff *skb,
                struct RxDesc *desc)
{
        if (tp->InitRxDescType == RX_DESC_RING_TYPE_3)
                rtl8125_rx_v3_csum(tp, skb, (struct RxDescV3 *)desc);
        else {
                u32 opts1 = le32_to_cpu(rtl8125_rx_desc_opts1(tp, desc));
                u32 opts2 = le32_to_cpu(rtl8125_rx_desc_opts2(tp, desc));

                /* rx csum offload for RTL8125 */
                if (((opts2 & RxV4F) && !(opts1 & RxIPF)) || (opts2 & RxV6F)) {
                        if (((opts1 & RxTCPT) && !(opts1 & RxTCPF)) ||
                            ((opts1 & RxUDPT) && !(opts1 & RxUDPF)))
                                skb->ip_summed = CHECKSUM_UNNECESSARY;
                        else
                                skb->ip_summed = CHECKSUM_NONE;
                } else
                        skb->ip_summed = CHECKSUM_NONE;
        }
}

static inline int
rtl8125_try_rx_copy(struct rtl8125_private *tp,
                    struct rtl8125_rx_ring *ring,
                    struct sk_buff **sk_buff,
                    int pkt_size,
                    struct RxDesc *desc,
                    int rx_buf_sz)
{
        int ret = -1;

        if (pkt_size < rx_copybreak) {
                struct sk_buff *skb;

                skb = RTL_ALLOC_SKB_INTR(&tp->r8125napi[ring->index].napi, pkt_size + RTK_RX_ALIGN);
                if (skb) {
                        u8 *data;

                        data = sk_buff[0]->data;
                        skb_reserve(skb, RTK_RX_ALIGN);
#if LINUX_VERSION_CODE >= KERNEL_VERSION(2,4,37)
                        prefetch(data - RTK_RX_ALIGN);
#endif
                        eth_copy_and_sum(skb, data, pkt_size, 0);
                        *sk_buff = skb;
                        rtl8125_mark_to_asic(tp, desc, rx_buf_sz);
                        ret = 0;
                }
        }
        return ret;
}

static inline void
rtl8125_rx_skb(struct rtl8125_private *tp,
               struct sk_buff *skb,
               u32 ring_index)
{
#ifdef CONFIG_R8125_NAPI
#if LINUX_VERSION_CODE < KERNEL_VERSION(2,6,29)
        netif_receive_skb(skb);
#else
        napi_gro_receive(&tp->r8125napi[ring_index].napi, skb);
#endif
#else
        netif_rx(skb);
#endif
}

static int
rtl8125_check_rx_desc_error(struct net_device *dev,
                            struct rtl8125_private *tp,
                            u32 status)
{
        int ret = 0;

        if (tp->InitRxDescType == RX_DESC_RING_TYPE_3) {
                if (unlikely(status & RxRES_V3)) {
                        if (status & (RxRWT_V3 | RxRUNT_V3))
                                RTLDEV->stats.rx_length_errors++;
                        if (status & RxCRC_V3)
                                RTLDEV->stats.rx_crc_errors++;

                        ret = -1;
                }
        } else {
                if (unlikely(status & RxRES)) {
                        if (status & (RxRWT | RxRUNT))
                                RTLDEV->stats.rx_length_errors++;
                        if (status & RxCRC)
                                RTLDEV->stats.rx_crc_errors++;

                        ret = -1;
                }
        }

        return ret;
}

static int
rtl8125_rx_interrupt(struct net_device *dev,
                     struct rtl8125_private *tp,
                     struct rtl8125_rx_ring *ring,
                     napi_budget budget)
{
        unsigned int cur_rx, rx_left;
        unsigned int delta, count = 0;
        unsigned int entry;
        struct RxDesc *desc;
        u32 status;
        u32 rx_quota;
        u64 rx_buf_phy_addr;
        u32 ring_index = ring->index;

        assert(dev != NULL);
        assert(tp != NULL);

        if ((ring->RxDescArray == NULL))
                goto rx_out;

        rx_quota = RTL_RX_QUOTA(budget);
        cur_rx = ring->cur_rx;
        entry = cur_rx % NUM_RX_DESC;
        desc = rtl8125_get_rxdesc(tp, ring->RxDescArray, entry);
        rx_left = NUM_RX_DESC + ring->dirty_rx - cur_rx;
        rx_left = rtl8125_rx_quota(rx_left, (u32)rx_quota);

        for (; rx_left > 0; rx_left--) {
                rmb();
                status = le32_to_cpu(rtl8125_rx_desc_opts1(tp, desc));
                if (status & DescOwn)
                        break;

                if (unlikely(rtl8125_check_rx_desc_error(dev, tp, status) < 0)) {
                        if (netif_msg_rx_err(tp)) {
                                printk(KERN_INFO
                                       "%s: Rx ERROR. status = %08x\n",
                                       dev->name, status);
                        }

                        RTLDEV->stats.rx_errors++;

                        if (dev->features & NETIF_F_RXALL)
                                goto process_pkt;

                        rtl8125_mark_to_asic(tp, desc, tp->rx_buf_sz);
                } else {
                        struct sk_buff *skb;
                        int pkt_size;

process_pkt:
                        if (likely(!(dev->features & NETIF_F_RXFCS)))
                                pkt_size = (status & 0x00003fff) - 4;
                        else
                                pkt_size = status & 0x00003fff;

                        /*
                         * The driver does not support incoming fragmented
                         * frames. They are seen as a symptom of over-mtu
                         * sized frames.
                         */
                        if (unlikely(rtl8125_fragmented_frame(tp, status))) {
                                RTLDEV->stats.rx_dropped++;
                                RTLDEV->stats.rx_length_errors++;
                                rtl8125_mark_to_asic(tp, desc, tp->rx_buf_sz);
                                continue;
                        }

                        skb = ring->Rx_skbuff[entry];

                        if (!skb)
                                break;

#ifdef ENABLE_PTP_SUPPORT
                        if (tp->EnablePtp) {
                                u8 desc_type;

                                desc_type = rtl8125_rx_desc_type(status);
                                if (desc_type == RXDESC_TYPE_NEXT && rx_left > 0) {
                                        u32 status_next;
                                        struct RxDescV3 *desc_next;
                                        unsigned int entry_next;
                                        struct sk_buff *skb_next;

                                        entry_next = (cur_rx + 1) % NUM_RX_DESC;
                                        desc_next = (struct RxDescV3 *)rtl8125_get_rxdesc(tp, ring->RxDescArray, entry_next);
                                        rmb();
                                        status_next = le32_to_cpu(desc_next->RxDescNormalDDWord4.opts1);
                                        if (unlikely(status_next & DescOwn)) {
                                                udelay(1);
                                                rmb();
                                                status_next = le32_to_cpu(desc_next->RxDescNormalDDWord4.opts1);
                                                if (unlikely(status_next & DescOwn)) {
                                                        if (netif_msg_rx_err(tp)) {
                                                                printk(KERN_ERR
                                                                       "%s: Rx Next Desc ERROR. status = %08x\n",
                                                                       dev->name, status_next);
                                                        }
                                                        break;
                                                }
                                        }

                                        cur_rx++;
                                        rx_left--;
                                        desc_type = rtl8125_rx_desc_type(status_next);
                                        if (desc_type == RXDESC_TYPE_PTP)
                                                rtl8125_rx_ptp_pktstamp(tp, skb, desc_next);
                                        else
                                                WARN_ON(1);

                                        rx_buf_phy_addr = le64_to_cpu(ring->RxDescPhyAddr[entry_next]);
                                        dma_unmap_single(tp_to_dev(tp), rx_buf_phy_addr,
                                                         tp->rx_buf_sz, DMA_FROM_DEVICE);
                                        skb_next = ring->Rx_skbuff[entry_next];
                                        dev_kfree_skb_any(skb_next);
                                        ring->Rx_skbuff[entry_next] = NULL;
                                } else
                                        WARN_ON(desc_type != RXDESC_TYPE_NORMAL);
                        }
#endif
                        rx_buf_phy_addr = le64_to_cpu(ring->RxDescPhyAddr[entry]);
                        dma_sync_single_for_cpu(tp_to_dev(tp),
                                                rx_buf_phy_addr, tp->rx_buf_sz,
                                                DMA_FROM_DEVICE);

                        if (rtl8125_try_rx_copy(tp, ring, &skb, pkt_size,
                                                desc, tp->rx_buf_sz)) {
                                ring->Rx_skbuff[entry] = NULL;
                                dma_unmap_single(tp_to_dev(tp), rx_buf_phy_addr,
                                                 tp->rx_buf_sz, DMA_FROM_DEVICE);
                        } else {
                                dma_sync_single_for_device(tp_to_dev(tp), rx_buf_phy_addr,
                                                           tp->rx_buf_sz, DMA_FROM_DEVICE);
                        }

#ifdef ENABLE_RSS_SUPPORT
                        rtl8125_rx_hash(tp, (struct RxDescV3 *)desc, skb);
#endif

                        if (tp->cp_cmd & RxChkSum)
                                rtl8125_rx_csum(tp, skb, desc);

                        skb->dev = dev;
                        skb_put(skb, pkt_size);
                        skb->protocol = eth_type_trans(skb, dev);

                        if (skb->pkt_type == PACKET_MULTICAST)
                                RTLDEV->stats.multicast++;

                        if (rtl8125_rx_vlan_skb(tp, desc, skb) < 0)
                                rtl8125_rx_skb(tp, skb, ring_index);

#if LINUX_VERSION_CODE < KERNEL_VERSION(4,11,0)
                        dev->last_rx = jiffies;
#endif //LINUX_VERSION_CODE < KERNEL_VERSION(4,11,0)
                        RTLDEV->stats.rx_bytes += pkt_size;
                        RTLDEV->stats.rx_packets++;
                }

                cur_rx++;
                entry = cur_rx % NUM_RX_DESC;
                desc = rtl8125_get_rxdesc(tp, ring->RxDescArray, entry);
#if LINUX_VERSION_CODE >= KERNEL_VERSION(2,4,37)
                prefetch(desc);
#endif
        }

        count = cur_rx - ring->cur_rx;
        ring->cur_rx = cur_rx;

        delta = rtl8125_rx_fill(tp, ring, dev, ring->dirty_rx, ring->cur_rx, 1);
        if (!delta && count && netif_msg_intr(tp))
                printk(KERN_INFO "%s: no Rx buffer allocated\n", dev->name);
        ring->dirty_rx += delta;

        /*
         * FIXME: until there is periodic timer to try and refill the ring,
         * a temporary shortage may definitely kill the Rx process.
         * - disable the asic to try and avoid an overflow and kick it again
         *   after refill ?
         * - how do others driver handle this condition (Uh oh...).
         */
        if ((ring->dirty_rx + NUM_RX_DESC == ring->cur_rx) && netif_msg_intr(tp))
                printk(KERN_EMERG "%s: Rx buffers exhausted\n", dev->name);

rx_out:
        return count;
}

static bool
rtl8125_linkchg_interrupt(struct rtl8125_private *tp, u32 status)
{
        if (tp->HwCurrIsrVer == 2)
                return status & ISRIMR_V2_LINKCHG;

        return status & LinkChg;
}

/*
 *The interrupt handler does all of the Rx thread work and cleans up after
 *the Tx thread.
 */
#if LINUX_VERSION_CODE < KERNEL_VERSION(2,6,19)
static irqreturn_t rtl8125_interrupt(int irq, void *dev_instance, struct pt_regs *regs)
#else
static irqreturn_t rtl8125_interrupt(int irq, void *dev_instance)
#endif
{
        struct r8125_napi *r8125napi = dev_instance;
        struct rtl8125_private *tp = r8125napi->priv;
        struct net_device *dev = tp->dev;
        u32 status;
        int handled = 0;

        do {
                status = RTL_R32(tp, tp->isr_reg[0]);

                if (!(tp->features & (RTL_FEATURE_MSI | RTL_FEATURE_MSIX))) {
                        /* hotplug/major error/no more work/shared irq */
                        if (!status)
                                break;

                        if ((status == 0xFFFFFFFF))
                                break;

                        if (!(status & (tp->intr_mask | tp->timer_intr_mask)))
                                break;
                }

                handled = 1;

#if defined(RTL_USE_NEW_INTR_API)
                if (!tp->irq_tbl[0].requested)
                        break;
#endif
                rtl8125_disable_hw_interrupt(tp);

                RTL_W32(tp, tp->isr_reg[0], status&~RxFIFOOver);

                if (rtl8125_linkchg_interrupt(tp, status))
                        rtl8125_check_link_status(dev);

#ifdef ENABLE_DASH_SUPPORT
                if (tp->DASH) {
                        if (HW_DASH_SUPPORT_TYPE_3(tp)) {
                                u8 DashIntType2Status;

                                if (status & ISRIMR_DASH_INTR_CMAC_RESET)
                                        tp->CmacResetIntr = TRUE;

                                DashIntType2Status = RTL_CMAC_R8(tp, CMAC_IBISR0);
                                if (DashIntType2Status & ISRIMR_DASH_TYPE2_ROK) {
                                        tp->RcvFwDashOkEvt = TRUE;
                                }
                                if (DashIntType2Status & ISRIMR_DASH_TYPE2_TOK) {
                                        tp->SendFwHostOkEvt = TRUE;
                                }
                                if (DashIntType2Status & ISRIMR_DASH_TYPE2_RX_DISABLE_IDLE) {
                                        tp->DashFwDisableRx = TRUE;
                                }

                                RTL_CMAC_W8(tp, CMAC_IBISR0, DashIntType2Status);
                        }
                }
#endif

#ifdef CONFIG_R8125_NAPI
                if (status & tp->intr_mask || tp->keep_intr_cnt-- > 0) {
                        if (status & tp->intr_mask)
                                tp->keep_intr_cnt = RTK_KEEP_INTERRUPT_COUNT;

                        if (likely(RTL_NETIF_RX_SCHEDULE_PREP(dev, &tp->r8125napi[0].napi)))
                                __RTL_NETIF_RX_SCHEDULE(dev, &tp->r8125napi[0].napi);
                        else if (netif_msg_intr(tp))
                                printk(KERN_INFO "%s: interrupt %04x in poll\n",
                                       dev->name, status);
                } else {
                        tp->keep_intr_cnt = RTK_KEEP_INTERRUPT_COUNT;
                        rtl8125_switch_to_hw_interrupt(tp);
                }
#else
                if (status & tp->intr_mask || tp->keep_intr_cnt-- > 0) {
                        u32 budget = ~(u32)0;
                        int i;

                        if (status & tp->intr_mask)
                                tp->keep_intr_cnt = RTK_KEEP_INTERRUPT_COUNT;

#if LINUX_VERSION_CODE < KERNEL_VERSION(2,6,24)
                        rtl8125_rx_interrupt(dev, tp, &tp->rx_ring[0], &budget);
#else
                        rtl8125_rx_interrupt(dev, tp, &tp->rx_ring[0], budget);
#endif	//LINUX_VERSION_CODE < KERNEL_VERSION(2,6,24)

                        for (i = 0; i < tp->num_tx_rings; i++)
                                rtl8125_tx_interrupt(&tp->tx_ring[i], ~(u32)0);
#ifdef ENABLE_DASH_SUPPORT
                        if (tp->DASH) {
                                struct net_device *dev = tp->dev;

                                HandleDashInterrupt(dev);
                        }
#endif

                        rtl8125_switch_to_timer_interrupt(tp);
                } else {
                        tp->keep_intr_cnt = RTK_KEEP_INTERRUPT_COUNT;
                        rtl8125_switch_to_hw_interrupt(tp);
                }
#endif
        } while (false);

        return IRQ_RETVAL(handled);
}

#if LINUX_VERSION_CODE < KERNEL_VERSION(2,6,19)
static irqreturn_t rtl8125_interrupt_msix(int irq, void *dev_instance, struct pt_regs *regs)
#else
static irqreturn_t rtl8125_interrupt_msix(int irq, void *dev_instance)
#endif
{
        struct r8125_napi *r8125napi = dev_instance;
        struct rtl8125_private *tp = r8125napi->priv;
        struct net_device *dev = tp->dev;
        int message_id = r8125napi->index;
#ifndef CONFIG_R8125_NAPI
        u32 budget = ~(u32)0;
#endif

        do {
#if defined(RTL_USE_NEW_INTR_API)
                if (!tp->irq_tbl[message_id].requested)
                        break;
#endif
                rtl8125_disable_hw_interrupt_v2(tp, message_id);

                rtl8125_clear_hw_isr_v2(tp, message_id);

                //link change
                if (message_id == 21) {
                        rtl8125_check_link_status(dev);
                        break;
                }

#ifdef CONFIG_R8125_NAPI
                if (likely(RTL_NETIF_RX_SCHEDULE_PREP(dev, &r8125napi->napi)))
                        __RTL_NETIF_RX_SCHEDULE(dev, &r8125napi->napi);
                else if (netif_msg_intr(tp))
                        printk(KERN_INFO "%s: interrupt message id %d in poll_msix\n",
                               dev->name, message_id);
#else
                if (message_id < tp->num_rx_rings) {
#if LINUX_VERSION_CODE < KERNEL_VERSION(2,6,24)
                        rtl8125_rx_interrupt(dev, tp, &tp->rx_ring[message_id], &budget);
#else
                        rtl8125_rx_interrupt(dev, tp, &tp->rx_ring[message_id], budget);
#endif	//LINUX_VERSION_CODE < KERNEL_VERSION(2,6,24)
                }

                //spin_lock_irqsave(&tp->lock, flags);
                rtl8125_tx_interrupt_with_vector(tp, message_id, ~(u32)0);
                //spin_unlock_irqrestore(&tp->lock, flags);

                rtl8125_enable_hw_interrupt_v2(tp, message_id);
#endif

        } while (false);

        return IRQ_HANDLED;
}

static void rtl8125_down(struct net_device *dev)
{
        struct rtl8125_private *tp = netdev_priv(dev);
        unsigned long flags;

        rtl8125_delete_esd_timer(dev, &tp->esd_timer);

        //rtl8125_delete_link_timer(dev, &tp->link_timer);

        rtl8125_stop_all_tx_queue(dev);

        _rtl8125_wait_for_quiescence(dev);

        spin_lock_irqsave(&tp->lock, flags);

        netif_carrier_off(dev);

        rtl8125_hw_reset(dev);

        rtl8125_tx_clear(tp);

        rtl8125_rx_clear(tp);

        spin_unlock_irqrestore(&tp->lock, flags);
}

static int rtl8125_resource_freed(struct rtl8125_private *tp)
{
        int i;

        for (i = 0; i < tp->num_tx_rings; i++)
                if (tp->tx_ring[i].TxDescArray) return 0;

        for (i = 0; i < tp->num_rx_rings; i++)
                if (tp->rx_ring[i].RxDescArray) return 0;

        return 1;
}

int rtl8125_close(struct net_device *dev)
{
        struct rtl8125_private *tp = netdev_priv(dev);
        unsigned long flags;

        if (!rtl8125_resource_freed(tp)) {
                rtl8125_cancel_schedule_work(dev);

                rtl8125_down(dev);

                pci_clear_master(tp->pci_dev);

                spin_lock_irqsave(&tp->lock, flags);
#ifdef ENABLE_PTP_SUPPORT
                rtl8125_ptp_stop(tp);
#endif
                rtl8125_hw_d3_para(dev);

                rtl8125_powerdown_pll(dev, 0);

                spin_unlock_irqrestore(&tp->lock, flags);

                rtl8125_free_irq(tp);

                rtl8125_free_alloc_resources(tp);
        } else {
                spin_lock_irqsave(&tp->lock, flags);

                rtl8125_hw_d3_para(dev);

                rtl8125_powerdown_pll(dev, 0);

                spin_unlock_irqrestore(&tp->lock, flags);
        }

        return 0;
}

#if LINUX_VERSION_CODE > KERNEL_VERSION(2,6,11)
static void rtl8125_shutdown(struct pci_dev *pdev)
{
        struct net_device *dev = pci_get_drvdata(pdev);
        struct rtl8125_private *tp = netdev_priv(dev);

        if (tp->DASH)
                rtl8125_driver_stop(tp);

        rtl8125_set_bios_setting(dev);
        if (s5_keep_curr_mac == 0 && tp->random_mac == 0)
                rtl8125_rar_set(tp, tp->org_mac_addr);

        if (s5wol == 0)
                tp->wol_enabled = WOL_DISABLED;

        rtl8125_close(dev);
        rtl8125_disable_msi(pdev, tp);

        if (system_state == SYSTEM_POWER_OFF) {
                pci_clear_master(tp->pci_dev);
                pci_wake_from_d3(pdev, tp->wol_enabled);
                pci_set_power_state(pdev, PCI_D3hot);
        }
}
#endif

/**
 *  rtl8125_get_stats - Get rtl8125 read/write statistics
 *  @dev: The Ethernet Device to get statistics for
 *
 *  Get TX/RX statistics for rtl8125
 */
static struct
net_device_stats *rtl8125_get_stats(struct net_device *dev)
{
#if LINUX_VERSION_CODE < KERNEL_VERSION(2,6,22)
        struct rtl8125_private *tp = netdev_priv(dev);
#endif
        if (netif_running(dev)) {
//      spin_lock_irqsave(&tp->lock, flags);
//      spin_unlock_irqrestore(&tp->lock, flags);
        }

        return &RTLDEV->stats;
}

#ifdef CONFIG_PM

#if LINUX_VERSION_CODE < KERNEL_VERSION(2,6,11)
static int
rtl8125_suspend(struct pci_dev *pdev, u32 state)
#elif LINUX_VERSION_CODE >= KERNEL_VERSION(2,6,29)
static int
rtl8125_suspend(struct device *device)
#else
static int
rtl8125_suspend(struct pci_dev *pdev, pm_message_t state)
#endif
{
#if LINUX_VERSION_CODE >= KERNEL_VERSION(2,6,29)
        struct pci_dev *pdev = to_pci_dev(device);
        struct net_device *dev = pci_get_drvdata(pdev);
#else
        struct net_device *dev = pci_get_drvdata(pdev);
#endif
        struct rtl8125_private *tp = netdev_priv(dev);
#if LINUX_VERSION_CODE < KERNEL_VERSION(2,6,10)
        u32 pci_pm_state = pci_choose_state(pdev, state);
#endif
        unsigned long flags;

        if (!netif_running(dev))
                goto out;

        rtl8125_cancel_schedule_work(dev);

        rtl8125_delete_esd_timer(dev, &tp->esd_timer);

        //rtl8125_delete_link_timer(dev, &tp->link_timer);

        rtl8125_stop_all_tx_queue(dev);

        netif_carrier_off(dev);

        netif_device_detach(dev);

        spin_lock_irqsave(&tp->lock, flags);

#ifdef ENABLE_PTP_SUPPORT
        rtl8125_ptp_suspend(tp);
#endif
        rtl8125_hw_reset(dev);

        pci_clear_master(pdev);

        rtl8125_hw_d3_para(dev);

        rtl8125_powerdown_pll(dev, 1);

        spin_unlock_irqrestore(&tp->lock, flags);

        if (tp->DASH)
                rtl8125_driver_stop(tp);
out:

        pci_disable_device(pdev);

#if LINUX_VERSION_CODE < KERNEL_VERSION(2,6,10)
        pci_save_state(pdev, &pci_pm_state);
#else
        pci_save_state(pdev);
#endif
#if LINUX_VERSION_CODE < KERNEL_VERSION(2,6,29)
        pci_enable_wake(pdev, pci_choose_state(pdev, state), tp->wol_enabled);
#endif

        pci_prepare_to_sleep(pdev);

        return 0;
}

static int
rtl8125_hw_d3_not_power_off(struct net_device *dev)
{
        return rtl8125_check_hw_phy_mcu_code_ver(dev);
}

#if LINUX_VERSION_CODE < KERNEL_VERSION(2,6,29)
static int
rtl8125_resume(struct pci_dev *pdev)
#else
static int
rtl8125_resume(struct device *device)
#endif
{
#if LINUX_VERSION_CODE >= KERNEL_VERSION(2,6,29)
        struct pci_dev *pdev = to_pci_dev(device);
        struct net_device *dev = pci_get_drvdata(pdev);
#else
        struct net_device *dev = pci_get_drvdata(pdev);
#endif
        struct rtl8125_private *tp = netdev_priv(dev);
        unsigned long flags;
#if LINUX_VERSION_CODE < KERNEL_VERSION(2,6,10)
        u32 pci_pm_state = PCI_D0;
#endif
        u32 err;

        err = pci_enable_device(pdev);
        if (err) {
                dev_err(&pdev->dev, "Cannot enable PCI device from suspend\n");
                return err;
        }
#if LINUX_VERSION_CODE < KERNEL_VERSION(2,6,10)
        pci_restore_state(pdev, &pci_pm_state);
#else
        pci_restore_state(pdev);
#endif
        pci_enable_wake(pdev, PCI_D0, 0);

        spin_lock_irqsave(&tp->lock, flags);

        /* restore last modified mac address */
        rtl8125_rar_set(tp, dev->dev_addr);

        if (tp->check_keep_link_speed &&
            //tp->link_ok(dev) &&
            rtl8125_hw_d3_not_power_off(dev))
                tp->resume_not_chg_speed = 1;
        else
                tp->resume_not_chg_speed = 0;

        spin_unlock_irqrestore(&tp->lock, flags);

        if (!netif_running(dev))
                goto out;

        pci_set_master(pdev);

        spin_lock_irqsave(&tp->lock, flags);

        rtl8125_exit_oob(dev);

        rtl8125_up(dev);

        spin_unlock_irqrestore(&tp->lock, flags);

        netif_device_attach(dev);

        if (tp->resume_not_chg_speed) {
                spin_lock_irqsave(&tp->lock, flags);

                _rtl8125_check_link_status(dev);

                spin_unlock_irqrestore(&tp->lock, flags);
        } else
                rtl8125_schedule_work(dev, rtl8125_reset_task);

        mod_timer(&tp->esd_timer, jiffies + RTL8125_ESD_TIMEOUT);
        //mod_timer(&tp->link_timer, jiffies + RTL8125_LINK_TIMEOUT);
out:
        return 0;
}

#if LINUX_VERSION_CODE >= KERNEL_VERSION(2,6,29)

static struct dev_pm_ops rtl8125_pm_ops = {
        .suspend = rtl8125_suspend,
        .resume = rtl8125_resume,
        .freeze = rtl8125_suspend,
        .thaw = rtl8125_resume,
        .poweroff = rtl8125_suspend,
        .restore = rtl8125_resume,
};

#define RTL8125_PM_OPS	(&rtl8125_pm_ops)

#endif

#else /* !CONFIG_PM */

#define RTL8125_PM_OPS	NULL

#endif /* CONFIG_PM */

static struct pci_driver rtl8125_pci_driver = {
        .name       = MODULENAME,
        .id_table   = rtl8125_pci_tbl,
        .probe      = rtl8125_init_one,
        .remove     = __devexit_p(rtl8125_remove_one),
#if LINUX_VERSION_CODE > KERNEL_VERSION(2,6,11)
        .shutdown   = rtl8125_shutdown,
#endif
#ifdef CONFIG_PM
#if LINUX_VERSION_CODE < KERNEL_VERSION(2,6,29)
        .suspend    = rtl8125_suspend,
        .resume     = rtl8125_resume,
#else
        .driver.pm	= RTL8125_PM_OPS,
#endif
#endif
};

static int __init
rtl8125_init_module(void)
{
        int ret = 0;
#ifdef ENABLE_R8125_PROCFS
        rtl8125_proc_module_init();
#endif

#if LINUX_VERSION_CODE > KERNEL_VERSION(2,6,0)

        ret = pci_register_driver(&rtl8125_pci_driver);
#else
        ret = pci_module_init(&rtl8125_pci_driver);
#endif

        return ret;
}

static void __exit
rtl8125_cleanup_module(void)
{
        pci_unregister_driver(&rtl8125_pci_driver);

#ifdef ENABLE_R8125_PROCFS
        if (rtl8125_proc) {
#if LINUX_VERSION_CODE >= KERNEL_VERSION(3,10,0)
                remove_proc_subtree(MODULENAME, init_net.proc_net);
#else
#if LINUX_VERSION_CODE >= KERNEL_VERSION(2,6,32)
                remove_proc_entry(MODULENAME, init_net.proc_net);
#else
                remove_proc_entry(MODULENAME, proc_net);
#endif  //LINUX_VERSION_CODE >= KERNEL_VERSION(2,6,32)
#endif  //LINUX_VERSION_CODE >= KERNEL_VERSION(3,10,0)
                rtl8125_proc = NULL;
        }
#endif
}

module_init(rtl8125_init_module);
module_exit(rtl8125_cleanup_module);