/* SPDX-License-Identifier: GPL-2.0-only
 * Copyright (c) 2021, The Linux Foundation. All rights reserved.
 */

#include "ioss_i.h"

static void *default_mem_alloc(struct ioss_device *idev,
		size_t size, dma_addr_t *daddr,
		gfp_t gfp, struct ioss_mem_allocator *alctr)
{
	return dma_alloc_coherent(ioss_to_real_dev(idev), size, daddr, gfp);
}

static void default_mem_free(struct ioss_device *idev,
		size_t size, void *addr, dma_addr_t daddr,
		struct ioss_mem_allocator *alctr)
{
	dma_free_coherent(ioss_to_real_dev(idev), size, addr, daddr);
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
