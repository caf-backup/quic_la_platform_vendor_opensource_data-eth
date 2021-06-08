/* SPDX-License-Identifier: GPL-2.0-only
 * Copyright (c) 2021, The Linux Foundation. All rights reserved.
 */

#include "ioss_i.h"

static void *default_mem_alloc(struct ioss_device *idev,
		size_t size, dma_addr_t *daddr,
		gfp_t gfp, struct ioss_mem_allocator *alctr)
{
	return dma_alloc_coherent(ioss_idev_to_real(idev), size, daddr, gfp);
}

static void default_mem_free(struct ioss_device *idev,
		size_t size, void *addr, dma_addr_t daddr,
		struct ioss_mem_allocator *alctr)
{
	dma_free_coherent(ioss_idev_to_real(idev), size, addr, daddr);
}

static phys_addr_t default_mem_pa(struct ioss_device *idev,
		void *addr, dma_addr_t daddr,
		struct ioss_mem_allocator *alctr)
{
	return page_to_phys(
		vmalloc_to_page(addr)) | ((phys_addr_t)addr & ~PAGE_MASK);
}

struct ioss_mem_allocator ioss_default_alctr = {
	.name = "dma_alloc_coherent",
	.alloc = default_mem_alloc,
	.free = default_mem_free,
	.pa = default_mem_pa,
};

/* LLCC Memory Allocator */

#include <linux/soc/qcom/llcc-qcom.h>
#include <linux/soc/qcom/llcc-tcm.h>

bool tcm_in_use;
static struct llcc_tcm_data *tcm_mem;

static void *llcc_mem_alloc(struct ioss_device *idev,
		size_t size, dma_addr_t *daddr,
		gfp_t gfp, struct ioss_mem_allocator *alctr)
{
	struct device *dev = ioss_idev_to_real(idev);

	if (!tcm_mem || tcm_in_use || size > tcm_mem->mem_size)
		return NULL;

	*daddr = dma_map_resource(dev, tcm_mem->phys_addr, tcm_mem->mem_size,
				DMA_BIDIRECTIONAL, 0);

	if (dma_mapping_error(dev, *daddr))
		return NULL;

	tcm_in_use = true;

	return tcm_mem->virt_addr;
}

static void llcc_mem_free(struct ioss_device *idev,
		size_t size, void *addr, dma_addr_t daddr,
		struct ioss_mem_allocator *alctr)
{
	dma_unmap_resource(ioss_idev_to_real(idev),
			daddr, size, DMA_BIDIRECTIONAL, 0);

	tcm_in_use = false;
}

static phys_addr_t llcc_mem_pa(struct ioss_device *idev,
		void *addr, dma_addr_t daddr,
		struct ioss_mem_allocator *alctr)
{
	return tcm_mem->phys_addr + (tcm_mem->virt_addr - addr);
}

static size_t llcc_mem_get(size_t size)
{
	struct llcc_tcm_data *tcm_data;

	if (tcm_mem) {
		ioss_log_msg(NULL, "TCM MEM already in use");
		return 0;
	}

	tcm_data = llcc_tcm_activate();
	if (IS_ERR_OR_NULL(tcm_data)) {
		ioss_log_err(NULL, "Failed to activate TCM");
		return 0;
	}

	tcm_mem = tcm_data;

	return tcm_mem->mem_size;
}

static void llcc_mem_put(size_t size)
{
	struct llcc_tcm_data *tcm_data = tcm_mem;

	if (!tcm_data)
		return;

	tcm_mem = NULL;

	llcc_tcm_deactivate(tcm_data);
}

struct ioss_mem_allocator ioss_llcc_alctr = {
	.name = "llcc_mem_allocator",
	.alloc = llcc_mem_alloc,
	.free = llcc_mem_free,
	.pa = llcc_mem_pa,
	.get = llcc_mem_get,
	.put = llcc_mem_put,
};
