# Toshiba Electronic Devices & Storage Corporation TC956X PCIe Ethernet Host Driver
Release Date: 07 Jan 2022

Release Version: V_01-00-34 : Limited-tested version

TC956X PCIe EMAC driver is based on "Fedora 30, kernel-5.4.19".

# Compilation & Run: Need to be root user to execute the following steps.
1.  By default, DMA_OFFLOAD_ENABLE is enabled. Execute following commands:

    #make clean

    #make
2.  If IPA offload is not needed, disable macro DMA_OFFLOAD_ENABLE in common.h. set DMA_OFFLOAD = 0 in Makefile and execute following commands:

    #make clean

    #make

    To compile driver with load firmware header (fw.h) use the below command
    #make TC956X_LOAD_FW_HEADER=1 

    In order to compile the Driver to include the code for applying Gen3 setting, execute Make with below argument
    #make TC956X_PCIE_GEN3_SETTING=1

    Please note, incase both fw.h and Gen3 settings are needed, then both arugments need to be specified.

3.	Load phylink module

	#modprobe phylink
4.  Load the driver

	#insmod tc956x_pcie_eth.ko pcie_link_speed=X

	In the module parameter pcie_link_speed, X is the desired PCIe Gen speed. X can be 3 or 2 or 1.
	Passing module parameter (pcie_link_speed=X) is optional.
	If module parameter is not passed, by default Gen3 speed will be selected by the driver.

	Please note that driver should be compiled using below command to use this feature:
	#make TC956X_PCIE_GEN3_SETTING=1
5.  Remove the driver

	#rmmod tc956x_pcie_eth

# Note:

1. Use below commands to advertise with Autonegotiation ON for speeds 10Gbps, 5Gbps, 2.5Gbps, 1Gbps, 100Mbps and 10Mbps as ethtool speed command does not support.

    ethtool -s <interface> advertise 0x7000 autoneg on --> changes the advertisement to 10Gbps
    
    ethtool -s <interface> advertise 0x1000000006000 autoneg on --> changes the advertisement to 5Gbps

    ethtool -s <interface> advertise 0x800000006000 autoneg on --> changes the advertisement to 2.5Gbps

    ethtool -s <interface> advertise 0x6020 autoneg on --> changes the advertisement to 1Gbps

    ethtool -s <interface> advertise 0x6008 autoneg on --> changes the advertisement to 100Mbps

    ethtool -s <interface> advertise 0x6002 autoneg on --> changes the advertisement 10Mbps

2. Use the below command to insert the kernel module with specific modes for interfaces:
	
    #insmod tc956x_pcie_eth.ko mac0_interface=x mac1_interface=y

       argument info:
	     mac0_interface: For PORT0 interface mode setting
	     mac1_interface: For PORT1 interface mode setting
	     x = [0: USXGMII, 1: XFI (default), 2: RGMII (unsupported), 3: SGMII]
	     y = [0: USXGMII (unsupported), 1: XFI (unsupported), 2: RGMII, 3: SGMII(default)]
  
    If invalid and unsupported modes are passed as kernel module parameter, the default interface mode will be selected.

3. Regarding the performance, use the below command to increase the dynamic byte queue limit

    $echo "900000" > /sys/devices/pci0000\:00/0000\:00\:01.0/0000\:01\:00.0/0000\:02\:03.0/0000\:05\:00.0/net/enp5s0f0/queues/tx-0/byte_queue_limits/limit_min

    900000 is the random value chosen. It needs to adjust this value on their system and check
    "0000\:00/0000\:00\:01.0/0000\:01\:00.0/0000\:02\:03.0/0000\:05\:00.0/" value can be obtained from the "lspci -t" command

4. The debug counters to check the interrupt count is available.

    "#ethtool -S <interface>" needs to be executed and sample output is as below
  
       total_interrupts: 120109
       lpi_intr_n: 0
       pmt_intr_n: 0
       event_intr_n: 0
       tx_intr_n: 120000
       rx_intr_n: 51
       xpcs_intr_n: 0
       phy_intr_n: 46
       sw_msi_n: 12

   tx_intr_n = No of. Tx interrupts originating from eMAC
   sw_msi_n = No. of SW MSIs triggered by Systick Handler as part of optimized Tx Timer based on Systick approach.
   So total number of interrupts for Tx = tx_intr_n + sw_msi_n
   Please note that whenever Rx interruts are generated, the Host ISR will process the Tx completed descriptors too.

5. With V_01-00-07, when IPA API start_channel() is invoked for Rx direction, MAC_Address1_High is updated with 0xBF000000. 
   This register setting is almost similar to promiscuous mode. So please install appropriate FRP instructions.

6. From V_01-00-08 onwards, Port0 ethernet interface will not be created only if there is no ethernet PHY attached to it

7. Enable TC956X_PHY_INTERRUPT_MODE_EMAC0 macro for supporting PORT0 Interrupt mode. Disable the macro if the phy driver supports only polling mode.
   Enable TC956X_PHY_INTERRUPT_MODE_EMAC1 macro for supporting PORT1 Interrupt mode. Disable the macro if the phy driver supports only polling mode.

8. Change below macro values for configuration of Link state L0 and L1 transaction delay.
	/* Link state change delay configuration for Upstream Port */
	#define USP_L0s_ENTRY_DELAY	(0x1FU)
	#define USP_L1_ENTRY_DELAY	(0x3FFU)

	/* Link state change delay configuration for Downstream Port-1 */
	#define DSP1_L0s_ENTRY_DELAY	(0x1FU)
	#define DSP1_L1_ENTRY_DELAY	(0x3FFU)

	/* Link state change delay configuration for Downstream Port-2 */
	#define DSP2_L0s_ENTRY_DELAY	(0x1FU)
	#define DSP2_L1_ENTRY_DELAY	(0x3FFU)

	/* Link state change delay configuration for Virtual Downstream Port */
	#define VDSP_L0s_ENTRY_DELAY	(0x1FU)
	#define VDSP_L1_ENTRY_DELAY	(0x3FFU)

	/* Link state change delay configuration for Internal Endpoint */
	#define EP_L0s_ENTRY_DELAY	(0x1FU)
	#define EP_L1_ENTRY_DELAY	(0x3FFU)

	Formula:
		L0 entry delay = XXX_L0s_ENTRY_DELAY * 256 ns
		L1 entry delay = XXX_L1_ENTRY_DELAY * 256 ns
		
		XXX_L0s_ENTRY_DELAY range: 1-31
		XXX_L1_ENTRY_DELAY: 1-1023

9. To check vlan feature status execute:
	ethtool -k <interface> | grep vlan

	To enable/disable following vlan features execute:
		(a) rx-vlan-filter:
			ethtool -K <interface> rx-vlan-filter <on|off>
		(b) rx-vlan-offload:
			ethtool -K <interface> rxvlan <on|off>
		(c) tx-vlan-offload:
			ethtool -K <interface> txvlan <on|off>

	Use following to configure VLAN:
		(a) modprobe 8021q
		(b) vconfig add <interface> <vlanid>
		(c) vconfig set_flag <interface>.<vlanid> 1 0
		(d) ifconfig <interface>.<vlanid> <ip> netmask 255.255.255.0 broadcast <ip mask> up

	Default Configuraton:
		(a) Rx vlan filter is disabled.
		(b) Rx valn offload (vlan stripping) is disabled.
		(c) Tx vlan offload is enabled.

10. Please use the below command to insert the kernel module for passing pause frames to application except pause frames from PHY:

	#insmod tc956x_pcie_eth.ko mac0_filter_phy_pause=x mac1_filter_phy_pause=x

	argument info:
		mac0_filter_phy_pause: For PORT0
		mac1_filter_phy_pause: For PORT1
		x = [0: DISABLE (default), 1: ENABLE]

	If invalid values are passed as kernel module parameter, the default value will be selected.

11. Use below commands to check WOL support and its type:
	#ethtool <interface>

12. WOL command Usage :
	#ethtool -s <interface> wol <type - p/g/d>.

	Supported WOL options and meaning:
	
	| Option | Meaning |
	| :-----: | :----: |
	|  p	  |  Wake on phy activity |
	|  g	  |  Wake on MagicPacket(tm) |
	|  d	  |  Disable (wake on nothing). (Default) |

	Example - To wake on phy activity and magic packet use :
	ethtool -s eth0 wol pg

13. Please use the below command to insert the kernel module to enable EEE and configure LPI Auto Entry timer:

	#insmod tc956x_pcie_eth.ko mac0_eee_enable=X mac0_lpi_timer=Y mac1_eee_enable=X mac1_lpi_timer=Y

	argument info:

		mac0_eee_enable: For PORT0
		mac1_eee_enable: For PORT1
		X = [0: DISABLE (default), 1: ENABLE]
		This module parameter is to Enable/Disable EEE for Port 0/1 - default is 0.
		If invalid values are passed as kernel module parameter, the default value will be selected.		

		mac0_lpi_timer: For PORT0
		mac1_lpi_timer: For PORT1
		Y = [0..1048568 (us)]
		This module parameter is to configure LPI Automatic Entry Timer for Port 0/1 - default is 600 (us).
		If invalid values are passed as kernel module parameter, the default value will be selected.		

	In addition to above module parameter, use below ethtool command to configure EEE and LPI auto entry timer.
	#ethtool --set-eee <interfcae> eee <on/off> tx-timer <time in us>
	Example: #ethtool --set-eee enp7s0f0 eee on tx-timer 10000

	Use below command to check the status of EEE configuration
	#ethtool --show-eee <interface>

14. Please use the below command to insert the kernel module for RX Queue size, Flow control thresholds & TX Queue size configuration.

	#insmod tc956x_pcie_eth.ko mac0_rxq0_size=x mac0_rxq0_rfd=y mac0_rxq0_rfa=y
		mac0_rxq1_size=x mac0_rxq1_rfd=y mac0_rxq1_rfa=y
		mac0_txq0_size=x mac0_txq1_size=x
		mac1_rxq0_size=x mac1_rxq0_rfd=y mac1_rxq0_rfa=y
		mac1_rxq1_size=x mac1_rxq1_rfd=y mac1_rxq1_rfa=y
		mac1_txq0_size=x mac1_txq1_size=x

	argument info:
		mac0_rxq0_size: For PORT0 RX Queue-0
		mac0_rxq1_size: For PORT0 RX Queue-1
		mac1_rxq0_size: For PORT1 RX Queue-0
		mac1_rxq1_size: For PORT1 RX Queue-1
		mac0_txq0_size: For PORT0 TX Queue-0
		mac0_txq1_size: For PORT0 TX Queue-1
		mac1_txq0_size: For PORT1 TX Queue-0
		mac1_txq1_size: For PORT1 TX Queue-1
		x = [Range Supported : 3072..44032 (bytes)], default is 18432 (bytes)

		mac0_rxq0_rfd: For PORT0 Queue-0 threshold for Disable flow control
		mac0_rxq1_rfd: For PORT0 Queue-1 threshold for Disable flow control
		mac0_rxq0_rfa: For PORT0 Queue-0 threshold for Enable flow control
		mac0_rxq1_rfa: For PORT0 Queue-1 threshold for Enable flow control
		mac1_rxq0_rfd: For PORT1 Queue-0 threshold for Disable flow control
		mac1_rxq1_rfd: For PORT1 Queue-1 threshold for Disable flow control
		mac1_rxq0_rfa: For PORT1 Queue-0 threshold for Enable flow control
		mac1_rxq1_rfa: For PORT1 Queue-1 threshold for Enable flow control
		y = [Range Supported : 0..84], default is 24 (13KB)

	If invalid values are passed as kernel module parameter, the default value will be selected for Queue Sizes and for Flow control 80% of Queue size will be used.

	Note:
	1. Please configure flow control thresholds (RFD & RFA) as per Queue size (Default values are for Default Queue size which is 18KB).

15. Please use the below command to insert the kernel module for counting Link partner pause frames and output to ethtool:

	#insmod tc956x_pcie_eth.ko mac0_en_lp_pause_frame_cnt=x mac1_en_lp_pause_frame_cnt=x

	argument info:
		mac0_en_lp_pause_frame_cnt: For PORT0
		mac1_en_lp_pause_frame_cnt: For PORT1
		x = [0: DISABLE (default), 1: ENABLE]

	If invalid values are passed as kernel module parameter, the default value will be selected.
	Note: It is required to enable kernel module parameter "mac0_filter_phy_pause/mac1_filter_phy_pause" along with this module parameter to count link partner pause frames.
# Release Versions:

## TC956X_Host_Driver_20210326_V_01-00:

1. Initial Version

## TC956X_Host_Driver_20210705_V_01-00-01:

1. Used Systick handler instead of Driver kernel timer to process transmitted Tx descriptors.
2. XFI interface supported and added module parameters for selection of Port0 and Port1 interface
3. kernel_read API replaced with kernel_read_file_from_path API
4. sprintf, vsprintf APIs replaced with vcnsprintf or vcnsprintf APIs
5. API to print IPA DMA channel statistics supported
6. Correction of print statement about selection of C45 PHY for Port0 interface

## TC956X_Host_Driver_20210705_V_01-00-02:

1. XFI interface supported through compile time macro.
2. Removed module parameters for selection of Port0 and Port1 interface
3. Debugfs support for IPA statistics

## TC956X_Host_Driver_20210720_V_01-00-03:

1. Debugfs not supported for IPA statistics
2. Default Port1 interface selected as SGMII

## TC956X_Host_Driver_20210722_V_01-00-04:

1. Module parameters for selection of Port0 and Port1 interface

## TC956X_Host_Driver_20210722_V_01-00-05:

1. Dynamic CM3 TAMAP configuration 

## TC956X_Host_Driver_20210722_V_01-00-06:

1. Add support for contiguous allocation of memory

## TC956X_Host_Driver_20210729_V_01-00-07:

1. Add support to set MAC Address register

## TC956X_Host_Driver_20210806_V_01-00-08:

1. Store and use Port0 pci_dev for all DMA allocation/mapping for IPA path
2. Register Port0 as only PCIe device, in case its PHY is not found

## TC956X_Host_Driver_20210816_V_01-00-09:

1. PHY interrupt mode supported through .config_intr and .ack_interrupt API

## TC956X_Host_Driver_20210824_V_01-00-10:

1. TC956X_PCIE_GEN3_SETTING macro setting supported through makefile. By default Gen3 settings will not be applied by the Driver as TC956X_PCIE_GEN3_SETTING is not defined.
2. TC956X_LOAD_FW_HEADER macro setting supported through makefile. By default, TC956X_LOAD_FW_HEADER macro is disabled. If FIRMWARE_NAME is not specified in Makefile, the default value shall be TC956X_Firmware_PCIeBridge.bin
3. Platform APIs supported.
4. Modified PHY C22/C45 debug message.

## TC956X_Host_Driver_20210902_V_01-00-11:

1. Configuration of Link state L0 and L1 transaction delay for PCIe switch ports & Endpoint. By default maximum values are set for L0s and L1 latencies.

## TC956X_Host_Driver_20210909_V_01-00-12:

1. Reverted changes related to usage of Port-0 pci_dev for all DMA allocation/mapping for IPA path

## TC956X_Host_Driver_20210914_V_01-00-13:

1. Synchronization between ethtool vlan features "rx-vlan-offload", "rx-vlan-filter", "tx-vlan-offload" output and register settings.
2. Added ethtool support to update "rx-vlan-offload", "rx-vlan-filter", and "tx-vlan-offload".
3. Removed IOCTL TC956XMAC_VLAN_STRIP_CONFIG.
4. Removed "Disable VLAN Filter" option in IOCTL TC956XMAC_VLAN_FILTERING.

## TC956X_Host_Driver_20210923_V_01-00-14:

1. Updated RX Queue Threshold limits for Activating and Deactivating Flow control 
2. Filtering All pause frames by default.
3. Capturing RBU status and updating to ethtool statistics for both S/W & IPA DMA channels

## TC956X_Host_Driver_20210929_V_01-00-15:

1. Added check for Device presence before changing PCIe ports speed.

## TC956X_Host_Driver_20211014_V_01-00-16:

1. Configuring pause frame control using kernel module parameter also forwarding only Link partner pause frames to Application and filtering PHY pause frames using FRP.
2. Returning error on disabling Receive Flow Control via ethtool for speed other than 10G in XFI mode.

## TC956X_Host_Driver_20211019_V_01-00-17:

1. Added M3 SRAM Debug counters to ethtool statistics.
2. Added MTL RX Overflow/packet miss count, TX underflow counts,Rx Watchdog value to ethtool statistics.

## TC956X_Host_Driver_20211021_V_01-00-18:

1. Added support for GPIO configuration API

## TC956X_Host_Driver_20211025_V_01-00-19:

1. Added PM support for suspend-resume.
2. Added WOL Interrupt Handler and ethtool Support.
3. Updated EEE support for PHY and MAC Control. (EEE macros are not enabled as EEE LPI interrupts disable are still under validation)

## TC956X_Host_Driver_20211104_V_01-00-20:

1. Added separate control functions for MAC TX and RX start/stop.
2. Stopped disabling/enabling of MAC TX during Link down/up.
3. Disabled link state latency configuration for all PCIe ports by default 

## TC956X_Host_Driver_20211108_V_01-00-21:

1. Skip queuing PHY Work during suspend and cancel any phy work if already queued.
2. Restore Gen 3 Speed after resume.

## TC956X_Host_Driver_20211124_V_01-00-22:

1. Single port Suspend/Resume supported

## TC956X_Host_Driver_20211124_V_01-00-23:

1. Restricted MDIO access when no PHY found or MDIO registration fails
2. Added mdio lock for making mii bus of private member to null to avoid parallel accessing to MDIO bus

## TC956X_Host_Driver_20211124_V_01-00-24:

1. Runtime configuration of EEE supported and LPI interrupts disabled by default.
2. Module param added to configure EEE and LPI timer.
3. Driver name corrected in ethtool display.

## TC956X_Host_Driver_20211130_V_01-00-25:

1. Print message correction for PCIe BAR size and Physical Address.

## TC956X_Host_Driver_20211130_V_01-00-26:

1. Added PHY Workqueue Cancel during suspend only if network interface available.

## TC956X_Host_Driver_20211201_V_01-00-27:

1. Free EMAC IRQ during suspend and request EMAC IRQ during resume.

## TC956X_Host_Driver_20211201_V_01-00-28:

1. Resetting SRAM Region before loading firmware.

## TC956X_Host_Driver_20211203_V_01-00-29:

1. Max C22/C45 PHY address changed to PHY_MAX_ADDR.
2. Added error check for phydev in tc956xmac_suspend().

## TC956X_Host_Driver_20211208_V_01-00-30:

1. Added module parameters for Rx Queue Size, Flow Control thresholds and Tx Queue Size configuration.
2. Renamed all module parameters for easy readability.

## TC956X_Host_Driver_20211210_V_01-00-31:

1. Support for link partner pause frame counting.
2. Module parameter support to enable/disable link partner pause frame counting.

## TC956X_Host_Driver_20211227_V_01-00-32:

1. Support for eMAC Reset and unused clock disable during Suspend and restoring it back during resume.
2. Resetting and disabling of unused clocks for eMAC Port, when no-found PHY for that particular port.
3. Valid phy-address and mii-pointer NULL check in tc956xmac_suspend().

## TC956X_Host_Driver_20220106_V_01-00-33:

1. Null check added while freeing skb buff data
2. Code comments corrected for flow control configuration

## TC956X_Host_Driver_20220107_V_01-00-34:

1. During emac resume, attach the net device after initializing the queues
