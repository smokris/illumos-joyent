/*-
 * SPDX-License-Identifier: BSD-2-Clause-FreeBSD
 *
 * Copyright (c) 2011 NetApp, Inc.
 * All rights reserved.
 * Copyright (c) 2019 Joyent, Inc.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY NETAPP, INC ``AS IS'' AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED.  IN NO EVENT SHALL NETAPP, INC OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 *
 * $FreeBSD$
 */
/*
 * This file and its contents are supplied under the terms of the
 * Common Development and Distribution License ("CDDL"), version 1.0.
 * You may only use this file in accordance with the terms of version
 * 1.0 of the CDDL.
 *
 * A full copy of the text of the CDDL should have accompanied this
 * source.  A copy of the CDDL is also available via the Internet at
 * http://www.illumos.org/license/CDDL.
 *
 * Copyright 2014 Pluribus Networks Inc.
 * Copyright 2018 Joyent, Inc.
 * Copyright 2020 Oxide Computer Company
 */

#include <sys/cdefs.h>
__FBSDID("$FreeBSD$");

#include <sys/param.h>
#include <sys/lock.h>
#include <sys/kernel.h>
#include <sys/malloc.h>
#include <sys/mutex.h>
#include <sys/systm.h>
#include <sys/cpuset.h>

#include <x86/specialreg.h>
#include <x86/apicreg.h>

#include <machine/clock.h>

#include <machine/vmm.h>

#include "vmm_lapic.h"
#include "vmm_ktr.h"
#include "vmm_stat.h"

#include "vlapic.h"
#include "vlapic_priv.h"
#include "vioapic.h"


/*
 * The 4 high bits of a given interrupt vector represent its priority.  The same
 * is true for the contents of the TPR when it is used to calculate the ultimate
 * PPR of an APIC - the 4 high bits hold the priority.
 */
#define	PRIO(x)			((x) & 0xf0)

#define	VLAPIC_VERSION		(16)

#define	x2apic(vlapic)	(((vlapic)->msr_apicbase & APICBASE_X2APIC) ? 1 : 0)

/*
 * The 'vlapic->timer_mtx' is used to provide mutual exclusion between the
 * vlapic_callout_handler() and vcpu accesses to:
 * - timer_freq_bt, timer_period_bt, timer_fire_bt
 * - timer LVT register
 */
#define	VLAPIC_TIMER_LOCK(vlapic)	mtx_lock_spin(&((vlapic)->timer_mtx))
#define	VLAPIC_TIMER_UNLOCK(vlapic)	mtx_unlock_spin(&((vlapic)->timer_mtx))
#define	VLAPIC_TIMER_LOCKED(vlapic)	mtx_owned(&((vlapic)->timer_mtx))

/*
 * APIC timer frequency:
 * - arbitrary but chosen to be in the ballpark of contemporary hardware.
 * - power-of-two to avoid loss of precision when calculating times
 */
#define	VLAPIC_BUS_FREQ		(128 * 1024 * 1024)

static void vlapic_set_error(struct vlapic *, uint32_t, bool);
static void vlapic_callout_handler(void *arg);

#ifdef __ISRVEC_DEBUG
static void vlapic_isrstk_accept(struct vlapic *, int);
static void vlapic_isrstk_eoi(struct vlapic *, int);
static void vlapic_isrstk_verify(const struct vlapic *);
#endif /* __ISRVEC_DEBUG */

static __inline uint32_t
vlapic_get_id(struct vlapic *vlapic)
{

	if (x2apic(vlapic))
		return (vlapic->vcpuid);
	else
		return (vlapic->vcpuid << 24);
}

static uint32_t
x2apic_ldr(struct vlapic *vlapic)
{
	int apicid;
	uint32_t ldr;

	apicid = vlapic_get_id(vlapic);
	ldr = 1 << (apicid & 0xf);
	ldr |= (apicid & 0xffff0) << 12;
	return (ldr);
}

void
vlapic_dfr_write_handler(struct vlapic *vlapic)
{
	struct LAPIC *lapic;

	lapic = vlapic->apic_page;
	if (x2apic(vlapic)) {
		VM_CTR1(vlapic->vm, "ignoring write to DFR in x2apic mode: %#x",
		    lapic->dfr);
		lapic->dfr = 0;
		return;
	}

	lapic->dfr &= APIC_DFR_MODEL_MASK;
	lapic->dfr |= APIC_DFR_RESERVED;
}

void
vlapic_ldr_write_handler(struct vlapic *vlapic)
{
	struct LAPIC *lapic;

	lapic = vlapic->apic_page;

	/* LDR is read-only in x2apic mode */
	if (x2apic(vlapic)) {
		VLAPIC_CTR1(vlapic, "ignoring write to LDR in x2apic mode: %#x",
		    lapic->ldr);
		lapic->ldr = x2apic_ldr(vlapic);
	} else {
		lapic->ldr &= ~APIC_LDR_RESERVED;
		VLAPIC_CTR1(vlapic, "vlapic LDR set to %#x", lapic->ldr);
	}
}

void
vlapic_id_write_handler(struct vlapic *vlapic)
{
	struct LAPIC *lapic;

	/*
	 * We don't allow the ID register to be modified so reset it back to
	 * its default value.
	 */
	lapic = vlapic->apic_page;
	lapic->id = vlapic_get_id(vlapic);
}

static int
vlapic_timer_divisor(uint32_t dcr)
{
	switch (dcr & 0xB) {
	case APIC_TDCR_1:
		return (1);
	case APIC_TDCR_2:
		return (2);
	case APIC_TDCR_4:
		return (4);
	case APIC_TDCR_8:
		return (8);
	case APIC_TDCR_16:
		return (16);
	case APIC_TDCR_32:
		return (32);
	case APIC_TDCR_64:
		return (64);
	case APIC_TDCR_128:
		return (128);
	default:
		panic("vlapic_timer_divisor: invalid dcr 0x%08x", dcr);
	}
}

#if 0
static inline void
vlapic_dump_lvt(uint32_t offset, uint32_t *lvt)
{
	printf("Offset %x: lvt %08x (V:%02x DS:%x M:%x)\n", offset,
	    *lvt, *lvt & APIC_LVTT_VECTOR, *lvt & APIC_LVTT_DS,
	    *lvt & APIC_LVTT_M);
}
#endif

static uint32_t
vlapic_get_ccr(struct vlapic *vlapic)
{
	struct LAPIC *lapic;
	uint32_t ccr;

	ccr = 0;
	lapic = vlapic->apic_page;

	VLAPIC_TIMER_LOCK(vlapic);
	if (callout_active(&vlapic->callout)) {
		/*
		 * If the timer is scheduled to expire in the future then
		 * compute the value of 'ccr' based on the remaining time.
		 */

		const hrtime_t now = gethrtime();
		if (vlapic->timer_fire_when > now) {
			ccr += hrt_freq_count(vlapic->timer_fire_when - now,
			    vlapic->timer_cur_freq);
		}
	}
	KASSERT(ccr <= lapic->icr_timer, ("vlapic_get_ccr: invalid ccr %x, "
	    "icr_timer is %x", ccr, lapic->icr_timer));
	VLAPIC_CTR2(vlapic, "vlapic ccr_timer = %#x, icr_timer = %#x",
	    ccr, lapic->icr_timer);
	VLAPIC_TIMER_UNLOCK(vlapic);
	return (ccr);
}

void
vlapic_dcr_write_handler(struct vlapic *vlapic)
{
	struct LAPIC *lapic;
	int divisor;

	lapic = vlapic->apic_page;
	VLAPIC_TIMER_LOCK(vlapic);

	divisor = vlapic_timer_divisor(lapic->dcr_timer);
	VLAPIC_CTR2(vlapic, "vlapic dcr_timer=%#x, divisor=%d",
	    lapic->dcr_timer, divisor);

	/*
	 * Update the timer frequency and the timer period.
	 *
	 * XXX changes to the frequency divider will not take effect until
	 * the timer is reloaded.
	 */
	vlapic->timer_cur_freq = VLAPIC_BUS_FREQ / divisor;
	vlapic->timer_period = hrt_freq_interval(vlapic->timer_cur_freq,
	    lapic->icr_timer);

	VLAPIC_TIMER_UNLOCK(vlapic);
}

void
vlapic_esr_write_handler(struct vlapic *vlapic)
{
	struct LAPIC *lapic;

	lapic = vlapic->apic_page;
	lapic->esr = vlapic->esr_pending;
	vlapic->esr_pending = 0;
}

vcpu_notify_t
vlapic_set_intr_ready(struct vlapic *vlapic, int vector, bool level)
{
	struct LAPIC *lapic;
	uint32_t *irrptr, *tmrptr, mask, tmr;
	int idx;

	KASSERT(vector >= 0 && vector < 256, ("invalid vector %d", vector));

	lapic = vlapic->apic_page;
	if (!(lapic->svr & APIC_SVR_ENABLE)) {
		/* ignore interrupt on software-disabled APIC */
		return (VCPU_NOTIFY_NONE);
	}

	if (vector < 16) {
		vlapic_set_error(vlapic, APIC_ESR_RECEIVE_ILLEGAL_VECTOR,
		    false);

		/*
		 * If the error LVT is configured to interrupt the vCPU, it will
		 * have delivered a notification through that mechanism.
		 */
		return (VCPU_NOTIFY_NONE);
	}

	if (vlapic->ops.set_intr_ready) {
		return ((*vlapic->ops.set_intr_ready)(vlapic, vector, level));
	}

	idx = (vector / 32) * 4;
	mask = 1 << (vector % 32);
	tmrptr = &lapic->tmr0;
	irrptr = &lapic->irr0;

	/*
	 * Update TMR for requested vector, if necessary.
	 * This must be done prior to asserting the bit in IRR so that the
	 * proper TMR state is always visible before the to-be-queued interrupt
	 * can be injected.
	 */
	tmr = atomic_load_acq_32(&tmrptr[idx]);
	if ((tmr & mask) != (level ? mask : 0)) {
		if (level) {
			atomic_set_int(&tmrptr[idx], mask);
		} else {
			atomic_clear_int(&tmrptr[idx], mask);
		}
	}

	/* Now set the bit in IRR */
	atomic_set_int(&irrptr[idx], mask);

	return (VCPU_NOTIFY_EXIT);
}

static __inline uint32_t *
vlapic_get_lvtptr(struct vlapic *vlapic, uint32_t offset)
{
	struct LAPIC	*lapic = vlapic->apic_page;
	int		i;

	switch (offset) {
	case APIC_OFFSET_CMCI_LVT:
		return (&lapic->lvt_cmci);
	case APIC_OFFSET_TIMER_LVT ... APIC_OFFSET_ERROR_LVT:
		i = (offset - APIC_OFFSET_TIMER_LVT) >> 2;
		return ((&lapic->lvt_timer) + i);
	default:
		panic("vlapic_get_lvt: invalid LVT\n");
	}
}

static __inline int
lvt_off_to_idx(uint32_t offset)
{
	int index;

	switch (offset) {
	case APIC_OFFSET_CMCI_LVT:
		index = APIC_LVT_CMCI;
		break;
	case APIC_OFFSET_TIMER_LVT:
		index = APIC_LVT_TIMER;
		break;
	case APIC_OFFSET_THERM_LVT:
		index = APIC_LVT_THERMAL;
		break;
	case APIC_OFFSET_PERF_LVT:
		index = APIC_LVT_PMC;
		break;
	case APIC_OFFSET_LINT0_LVT:
		index = APIC_LVT_LINT0;
		break;
	case APIC_OFFSET_LINT1_LVT:
		index = APIC_LVT_LINT1;
		break;
	case APIC_OFFSET_ERROR_LVT:
		index = APIC_LVT_ERROR;
		break;
	default:
		index = -1;
		break;
	}
	KASSERT(index >= 0 && index <= VLAPIC_MAXLVT_INDEX, ("lvt_off_to_idx: "
	    "invalid lvt index %d for offset %x", index, offset));

	return (index);
}

static __inline uint32_t
vlapic_get_lvt(struct vlapic *vlapic, uint32_t offset)
{
	int idx;
	uint32_t val;

	idx = lvt_off_to_idx(offset);
	val = atomic_load_acq_32(&vlapic->lvt_last[idx]);
	return (val);
}

void
vlapic_lvt_write_handler(struct vlapic *vlapic, uint32_t offset)
{
	uint32_t *lvtptr, mask, val;
	struct LAPIC *lapic;
	int idx;

	lapic = vlapic->apic_page;
	lvtptr = vlapic_get_lvtptr(vlapic, offset);
	val = *lvtptr;
	idx = lvt_off_to_idx(offset);

	if (!(lapic->svr & APIC_SVR_ENABLE))
		val |= APIC_LVT_M;
	mask = APIC_LVT_M | APIC_LVT_DS | APIC_LVT_VECTOR;
	switch (offset) {
	case APIC_OFFSET_TIMER_LVT:
		mask |= APIC_LVTT_TM;
		break;
	case APIC_OFFSET_ERROR_LVT:
		break;
	case APIC_OFFSET_LINT0_LVT:
	case APIC_OFFSET_LINT1_LVT:
		mask |= APIC_LVT_TM | APIC_LVT_RIRR | APIC_LVT_IIPP;
		/* FALLTHROUGH */
	default:
		mask |= APIC_LVT_DM;
		break;
	}
	val &= mask;
	*lvtptr = val;
	atomic_store_rel_32(&vlapic->lvt_last[idx], val);
}

static void
vlapic_mask_lvts(struct vlapic *vlapic)
{
	struct LAPIC *lapic = vlapic->apic_page;

	lapic->lvt_cmci |= APIC_LVT_M;
	vlapic_lvt_write_handler(vlapic, APIC_OFFSET_CMCI_LVT);

	lapic->lvt_timer |= APIC_LVT_M;
	vlapic_lvt_write_handler(vlapic, APIC_OFFSET_TIMER_LVT);

	lapic->lvt_thermal |= APIC_LVT_M;
	vlapic_lvt_write_handler(vlapic, APIC_OFFSET_THERM_LVT);

	lapic->lvt_pcint |= APIC_LVT_M;
	vlapic_lvt_write_handler(vlapic, APIC_OFFSET_PERF_LVT);

	lapic->lvt_lint0 |= APIC_LVT_M;
	vlapic_lvt_write_handler(vlapic, APIC_OFFSET_LINT0_LVT);

	lapic->lvt_lint1 |= APIC_LVT_M;
	vlapic_lvt_write_handler(vlapic, APIC_OFFSET_LINT1_LVT);

	lapic->lvt_error |= APIC_LVT_M;
	vlapic_lvt_write_handler(vlapic, APIC_OFFSET_ERROR_LVT);
}

static int
vlapic_fire_lvt(struct vlapic *vlapic, uint_t lvt)
{
	uint32_t mode, reg, vec;
	vcpu_notify_t notify;

	reg = atomic_load_acq_32(&vlapic->lvt_last[lvt]);

	if (reg & APIC_LVT_M)
		return (0);
	vec = reg & APIC_LVT_VECTOR;
	mode = reg & APIC_LVT_DM;

	switch (mode) {
	case APIC_LVT_DM_FIXED:
		if (vec < 16) {
			vlapic_set_error(vlapic, APIC_ESR_SEND_ILLEGAL_VECTOR,
			    lvt == APIC_LVT_ERROR);
			return (0);
		}
		notify = vlapic_set_intr_ready(vlapic, vec, false);
		vcpu_notify_event_type(vlapic->vm, vlapic->vcpuid, notify);
		break;
	case APIC_LVT_DM_NMI:
		vm_inject_nmi(vlapic->vm, vlapic->vcpuid);
		break;
	case APIC_LVT_DM_EXTINT:
		vm_inject_extint(vlapic->vm, vlapic->vcpuid);
		break;
	default:
		// Other modes ignored
		return (0);
	}
	return (1);
}

static uint_t
vlapic_active_isr(struct vlapic *vlapic)
{
	int i;
	uint32_t *isrp;

	isrp = &vlapic->apic_page->isr7;

	for (i = 7; i >= 0; i--, isrp -= 4) {
		uint32_t reg = *isrp;

		if (reg != 0) {
			uint_t vec = (i * 32) + bsrl(reg);

			if (vec < 16) {
				/*
				 * Truncate the illegal low vectors to value of
				 * 0, indicating that no active ISR was found.
				 */
				return (0);
			}
			return (vec);
		}
	}

	return (0);
}

/*
 * After events which might arbitrarily change the value of PPR, such as a TPR
 * write or an EOI, calculate that new PPR value and store it in the APIC page.
 */
static void
vlapic_update_ppr(struct vlapic *vlapic)
{
	int isrvec, tpr, ppr;

	isrvec = vlapic_active_isr(vlapic);
	tpr = vlapic->apic_page->tpr;

	/*
	 * Algorithm adopted from section "Interrupt, Task and Processor
	 * Priority" in Intel Architecture Manual Vol 3a.
	 */
	if (PRIO(tpr) >= PRIO(isrvec)) {
		ppr = tpr;
	} else {
		ppr = PRIO(isrvec);
	}

	vlapic->apic_page->ppr = ppr;
	VLAPIC_CTR1(vlapic, "vlapic_update_ppr 0x%02x", ppr);
}

/*
 * When a vector is asserted in ISR as in-service, the PPR must be raised to the
 * priority of that vector, as the vCPU would have been at a lower priority in
 * order for the vector to be accepted.
 */
static void
vlapic_raise_ppr(struct vlapic *vlapic, int vec)
{
	struct LAPIC *lapic = vlapic->apic_page;
	int ppr;

	ppr = PRIO(vec);

#ifdef __ISRVEC_DEBUG
	KASSERT(vec >= 16 && vec < 256, ("invalid vector %d", vec));
	KASSERT(ppr > lapic->tpr, ("ppr %x <= tpr %x", ppr, lapic->tpr));
	KASSERT(ppr > lapic->ppr, ("ppr %x <= old ppr %x", ppr, lapic->ppr));
	KASSERT(vec == (int)vlapic_active_isr(vlapic), ("ISR missing for ppr"));
#endif /* __ISRVEC_DEBUG */

	lapic->ppr = ppr;
	VLAPIC_CTR1(vlapic, "vlapic_update_ppr 0x%02x", ppr);
}

void
vlapic_sync_tpr(struct vlapic *vlapic)
{
	vlapic_update_ppr(vlapic);
}

static VMM_STAT(VLAPIC_GRATUITOUS_EOI, "EOI without any in-service interrupt");

static void
vlapic_process_eoi(struct vlapic *vlapic)
{
	struct LAPIC	*lapic = vlapic->apic_page;
	uint32_t	*isrptr, *tmrptr;
	int		i;
	uint_t		idx, bitpos, vector;

	isrptr = &lapic->isr0;
	tmrptr = &lapic->tmr0;

	for (i = 7; i >= 0; i--) {
		idx = i * 4;
		if (isrptr[idx] != 0) {
			bitpos = bsrl(isrptr[idx]);
			vector = i * 32 + bitpos;

			isrptr[idx] &= ~(1 << bitpos);
			VCPU_CTR1(vlapic->vm, vlapic->vcpuid, "EOI vector %d",
			    vector);
			VLAPIC_CTR_ISR(vlapic, "vlapic_process_eoi");
#ifdef __ISRVEC_DEBUG
			vlapic_isrstk_eoi(vlapic, vector);
#endif
			vlapic_update_ppr(vlapic);
			if ((tmrptr[idx] & (1 << bitpos)) != 0) {
				vioapic_process_eoi(vlapic->vm, vlapic->vcpuid,
				    vector);
			}
			return;
		}
	}
	VCPU_CTR0(vlapic->vm, vlapic->vcpuid, "Gratuitous EOI");
	vmm_stat_incr(vlapic->vm, vlapic->vcpuid, VLAPIC_GRATUITOUS_EOI, 1);
}

static __inline int
vlapic_get_lvt_field(uint32_t lvt, uint32_t mask)
{

	return (lvt & mask);
}

static __inline int
vlapic_periodic_timer(struct vlapic *vlapic)
{
	uint32_t lvt;

	lvt = vlapic_get_lvt(vlapic, APIC_OFFSET_TIMER_LVT);

	return (vlapic_get_lvt_field(lvt, APIC_LVTT_TM_PERIODIC));
}

static VMM_STAT(VLAPIC_INTR_ERROR, "error interrupts generated by vlapic");

static void
vlapic_set_error(struct vlapic *vlapic, uint32_t mask, bool lvt_error)
{

	vlapic->esr_pending |= mask;

	/*
	 * Avoid infinite recursion if the error LVT itself is configured with
	 * an illegal vector.
	 */
	if (lvt_error)
		return;

	if (vlapic_fire_lvt(vlapic, APIC_LVT_ERROR)) {
		vmm_stat_incr(vlapic->vm, vlapic->vcpuid, VLAPIC_INTR_ERROR, 1);
	}
}

static VMM_STAT(VLAPIC_INTR_TIMER, "timer interrupts generated by vlapic");

static void
vlapic_fire_timer(struct vlapic *vlapic)
{

	KASSERT(VLAPIC_TIMER_LOCKED(vlapic), ("vlapic_fire_timer not locked"));

	if (vlapic_fire_lvt(vlapic, APIC_LVT_TIMER)) {
		VLAPIC_CTR0(vlapic, "vlapic timer fired");
		vmm_stat_incr(vlapic->vm, vlapic->vcpuid, VLAPIC_INTR_TIMER, 1);
	}
}

static VMM_STAT(VLAPIC_INTR_CMC,
	"corrected machine check interrupts generated by vlapic");

void
vlapic_fire_cmci(struct vlapic *vlapic)
{

	if (vlapic_fire_lvt(vlapic, APIC_LVT_CMCI)) {
		vmm_stat_incr(vlapic->vm, vlapic->vcpuid, VLAPIC_INTR_CMC, 1);
	}
}

static VMM_STAT_ARRAY(LVTS_TRIGGERRED, VLAPIC_MAXLVT_INDEX + 1,
	"lvts triggered");

int
vlapic_trigger_lvt(struct vlapic *vlapic, int vector)
{

	if (vlapic_enabled(vlapic) == false) {
		/*
		 * When the local APIC is global/hardware disabled,
		 * LINT[1:0] pins are configured as INTR and NMI pins,
		 * respectively.
		 */
		switch (vector) {
			case APIC_LVT_LINT0:
				vm_inject_extint(vlapic->vm, vlapic->vcpuid);
				break;
			case APIC_LVT_LINT1:
				vm_inject_nmi(vlapic->vm, vlapic->vcpuid);
				break;
			default:
				break;
		}
		return (0);
	}

	switch (vector) {
	case APIC_LVT_LINT0:
	case APIC_LVT_LINT1:
	case APIC_LVT_TIMER:
	case APIC_LVT_ERROR:
	case APIC_LVT_PMC:
	case APIC_LVT_THERMAL:
	case APIC_LVT_CMCI:
		if (vlapic_fire_lvt(vlapic, vector)) {
			vmm_stat_array_incr(vlapic->vm, vlapic->vcpuid,
			    LVTS_TRIGGERRED, vector, 1);
		}
		break;
	default:
		return (EINVAL);
	}
	return (0);
}

static void
vlapic_callout_reset(struct vlapic *vlapic)
{
	callout_reset_hrtime(&vlapic->callout, vlapic->timer_fire_when,
	    vlapic_callout_handler, vlapic, C_ABSOLUTE);
}

static void
vlapic_callout_handler(void *arg)
{
	struct vlapic *vlapic = arg;

	VLAPIC_TIMER_LOCK(vlapic);
	if (callout_pending(&vlapic->callout))	/* callout was reset */
		goto done;

	if (!callout_active(&vlapic->callout))	/* callout was stopped */
		goto done;

	callout_deactivate(&vlapic->callout);

	vlapic_fire_timer(vlapic);

	if (vlapic_periodic_timer(vlapic)) {
		/*
		 * Compute the delta between when the timer was supposed to
		 * fire and the present time.  We can depend on the fact that
		 * cyclics (which underly these callouts) will never be called
		 * early.
		 */
		const hrtime_t now = gethrtime();
		const hrtime_t delta = now - vlapic->timer_fire_when;
		if (delta >= vlapic->timer_period) {
			/*
			 * If we are so behind that we have missed an entire
			 * timer period, reset the time base rather than
			 * attempting to catch up.
			 */
			vlapic->timer_fire_when = now + vlapic->timer_period;
		} else {
			vlapic->timer_fire_when += vlapic->timer_period;
		}
		vlapic_callout_reset(vlapic);
	}
done:
	VLAPIC_TIMER_UNLOCK(vlapic);
}

void
vlapic_icrtmr_write_handler(struct vlapic *vlapic)
{
	struct LAPIC *lapic = vlapic->apic_page;

	VLAPIC_TIMER_LOCK(vlapic);
	vlapic->timer_period = hrt_freq_interval(vlapic->timer_cur_freq,
	    lapic->icr_timer);
	if (vlapic->timer_period != 0) {
		vlapic->timer_fire_when = gethrtime() + vlapic->timer_period;
		vlapic_callout_reset(vlapic);
	} else {
		vlapic->timer_fire_when = 0;
		callout_stop(&vlapic->callout);
	}
	VLAPIC_TIMER_UNLOCK(vlapic);
}

/*
 * This function populates 'dmask' with the set of vcpus that match the
 * addressing specified by the (dest, phys, lowprio) tuple.
 *
 * 'x2apic_dest' specifies whether 'dest' is interpreted as x2APIC (32-bit)
 * or xAPIC (8-bit) destination field.
 */
void
vlapic_calcdest(struct vm *vm, cpuset_t *dmask, uint32_t dest, bool phys,
    bool lowprio, bool x2apic_dest)
{
	struct vlapic *vlapic;
	uint32_t dfr, ldr, ldest, cluster;
	uint32_t mda_flat_ldest, mda_cluster_ldest, mda_ldest, mda_cluster_id;
	cpuset_t amask;
	int vcpuid;

	if ((x2apic_dest && dest == 0xffffffff) ||
	    (!x2apic_dest && dest == 0xff)) {
		/*
		 * Broadcast in both logical and physical modes.
		 */
		*dmask = vm_active_cpus(vm);
		return;
	}

	if (phys) {
		/*
		 * Physical mode: destination is APIC ID.
		 */
		CPU_ZERO(dmask);
		vcpuid = vm_apicid2vcpuid(vm, dest);
		amask = vm_active_cpus(vm);
		if (vcpuid < vm_get_maxcpus(vm) && CPU_ISSET(vcpuid, &amask))
			CPU_SET(vcpuid, dmask);
	} else {
		/*
		 * In the "Flat Model" the MDA is interpreted as an 8-bit wide
		 * bitmask. This model is only available in the xAPIC mode.
		 */
		mda_flat_ldest = dest & 0xff;

		/*
		 * In the "Cluster Model" the MDA is used to identify a
		 * specific cluster and a set of APICs in that cluster.
		 */
		if (x2apic_dest) {
			mda_cluster_id = dest >> 16;
			mda_cluster_ldest = dest & 0xffff;
		} else {
			mda_cluster_id = (dest >> 4) & 0xf;
			mda_cluster_ldest = dest & 0xf;
		}

		/*
		 * Logical mode: match each APIC that has a bit set
		 * in its LDR that matches a bit in the ldest.
		 */
		CPU_ZERO(dmask);
		amask = vm_active_cpus(vm);
		while ((vcpuid = CPU_FFS(&amask)) != 0) {
			vcpuid--;
			CPU_CLR(vcpuid, &amask);

			vlapic = vm_lapic(vm, vcpuid);
			dfr = vlapic->apic_page->dfr;
			ldr = vlapic->apic_page->ldr;

			if ((dfr & APIC_DFR_MODEL_MASK) ==
			    APIC_DFR_MODEL_FLAT) {
				ldest = ldr >> 24;
				mda_ldest = mda_flat_ldest;
			} else if ((dfr & APIC_DFR_MODEL_MASK) ==
			    APIC_DFR_MODEL_CLUSTER) {
				if (x2apic(vlapic)) {
					cluster = ldr >> 16;
					ldest = ldr & 0xffff;
				} else {
					cluster = ldr >> 28;
					ldest = (ldr >> 24) & 0xf;
				}
				if (cluster != mda_cluster_id)
					continue;
				mda_ldest = mda_cluster_ldest;
			} else {
				/*
				 * Guest has configured a bad logical
				 * model for this vcpu - skip it.
				 */
				VLAPIC_CTR1(vlapic, "vlapic has bad logical "
				    "model %x - cannot deliver interrupt", dfr);
				continue;
			}

			if ((mda_ldest & ldest) != 0) {
				CPU_SET(vcpuid, dmask);
				if (lowprio)
					break;
			}
		}
	}
}

static VMM_STAT(VLAPIC_IPI_SEND, "ipis sent from vcpu");
static VMM_STAT(VLAPIC_IPI_RECV, "ipis received by vcpu");

static void
vlapic_set_tpr(struct vlapic *vlapic, uint8_t val)
{
	struct LAPIC *lapic = vlapic->apic_page;

	if (lapic->tpr != val) {
		VCPU_CTR2(vlapic->vm, vlapic->vcpuid, "vlapic TPR changed "
		    "from %#x to %#x", lapic->tpr, val);
		lapic->tpr = val;
		vlapic_update_ppr(vlapic);
	}
}

static uint8_t
vlapic_get_tpr(struct vlapic *vlapic)
{
	struct LAPIC *lapic = vlapic->apic_page;

	return (lapic->tpr);
}

void
vlapic_set_cr8(struct vlapic *vlapic, uint64_t val)
{
	uint8_t tpr;

	if (val & ~0xf) {
		vm_inject_gp(vlapic->vm, vlapic->vcpuid);
		return;
	}

	tpr = val << 4;
	vlapic_set_tpr(vlapic, tpr);
}

uint64_t
vlapic_get_cr8(struct vlapic *vlapic)
{
	uint8_t tpr;

	tpr = vlapic_get_tpr(vlapic);
	return (tpr >> 4);
}

int
vlapic_icrlo_write_handler(struct vlapic *vlapic)
{
	int i;
	cpuset_t dmask;
	uint64_t icrval;
	uint32_t dest, vec, mode, dsh;
	struct LAPIC *lapic;

	lapic = vlapic->apic_page;
	lapic->icr_lo &= ~APIC_DELSTAT_PEND;
	icrval = ((uint64_t)lapic->icr_hi << 32) | lapic->icr_lo;

	if (x2apic(vlapic))
		dest = icrval >> 32;
	else
		dest = icrval >> (32 + 24);
	vec = icrval & APIC_VECTOR_MASK;
	mode = icrval & APIC_DELMODE_MASK;
	dsh = icrval & APIC_DEST_MASK;

	if (mode == APIC_DELMODE_FIXED && vec < 16) {
		vlapic_set_error(vlapic, APIC_ESR_SEND_ILLEGAL_VECTOR, false);
		return (0);
	}
	if (mode == APIC_DELMODE_INIT &&
	    (icrval & APIC_LEVEL_MASK) == APIC_LEVEL_DEASSERT) {
		/* No work required to deassert INIT */
		return (0);
	}
	if ((mode == APIC_DELMODE_STARTUP || mode == APIC_DELMODE_INIT) &&
	    !(dsh == APIC_DEST_DESTFLD || dsh == APIC_DEST_ALLESELF)) {
		/*
		 * While Intel makes no mention of restrictions for destination
		 * shorthand when sending INIT or SIPI, AMD requires either a
		 * specific destination or all-excluding self.  Common use seems
		 * to be restricted to those two cases.
		 */
		return (-1);
	}

	switch (dsh) {
	case APIC_DEST_DESTFLD:
		vlapic_calcdest(vlapic->vm, &dmask, dest,
		    (icrval & APIC_DESTMODE_LOG) == 0, false, x2apic(vlapic));
		break;
	case APIC_DEST_SELF:
		CPU_SETOF(vlapic->vcpuid, &dmask);
		break;
	case APIC_DEST_ALLISELF:
		dmask = vm_active_cpus(vlapic->vm);
		break;
	case APIC_DEST_ALLESELF:
		dmask = vm_active_cpus(vlapic->vm);
		CPU_CLR(vlapic->vcpuid, &dmask);
		break;
	default:
		/*
		 * All possible delivery notations are covered above.
		 * We should never end up here.
		 */
		panic("unknown delivery shorthand: %x", dsh);
	}

	while ((i = CPU_FFS(&dmask)) != 0) {
		i--;
		CPU_CLR(i, &dmask);
		switch (mode) {
		case APIC_DELMODE_FIXED:
			lapic_intr_edge(vlapic->vm, i, vec);
			vmm_stat_incr(vlapic->vm, vlapic->vcpuid,
			    VLAPIC_IPI_SEND, 1);
			vmm_stat_incr(vlapic->vm, i,
			    VLAPIC_IPI_RECV, 1);
			break;
		case APIC_DELMODE_NMI:
			vm_inject_nmi(vlapic->vm, i);
			break;
		case APIC_DELMODE_INIT:
			(void) vm_inject_init(vlapic->vm, i);
			break;
		case APIC_DELMODE_STARTUP:
			(void) vm_inject_sipi(vlapic->vm, i, vec);
			break;
		case APIC_DELMODE_LOWPRIO:
		case APIC_DELMODE_SMI:
		default:
			/* Unhandled IPI modes (for now) */
			break;
		}
	}
	return (0);
}

void
vlapic_self_ipi_handler(struct vlapic *vlapic, uint64_t val)
{
	int vec;

	KASSERT(x2apic(vlapic), ("SELF_IPI does not exist in xAPIC mode"));

	vec = val & 0xff;
	lapic_intr_edge(vlapic->vm, vlapic->vcpuid, vec);
	vmm_stat_incr(vlapic->vm, vlapic->vcpuid, VLAPIC_IPI_SEND, 1);
	vmm_stat_incr(vlapic->vm, vlapic->vcpuid, VLAPIC_IPI_RECV, 1);
	VLAPIC_CTR1(vlapic, "vlapic self-ipi %d", vec);
}

int
vlapic_pending_intr(struct vlapic *vlapic, int *vecptr)
{
	struct LAPIC	*lapic = vlapic->apic_page;
	int		 idx, i, bitpos, vector;
	uint32_t	*irrptr, val;

	if (vlapic->ops.sync_state) {
		(*vlapic->ops.sync_state)(vlapic);
	}

	irrptr = &lapic->irr0;

	for (i = 7; i >= 0; i--) {
		idx = i * 4;
		val = atomic_load_acq_int(&irrptr[idx]);
		bitpos = fls(val);
		if (bitpos != 0) {
			vector = i * 32 + (bitpos - 1);
			if (PRIO(vector) > PRIO(lapic->ppr)) {
				VLAPIC_CTR1(vlapic, "pending intr %d", vector);
				if (vecptr != NULL)
					*vecptr = vector;
				return (1);
			} else
				break;
		}
	}
	return (0);
}

void
vlapic_intr_accepted(struct vlapic *vlapic, int vector)
{
	struct LAPIC	*lapic = vlapic->apic_page;
	uint32_t	*irrptr, *isrptr;
	int		idx;

	KASSERT(vector >= 16 && vector < 256, ("invalid vector %d", vector));

	if (vlapic->ops.intr_accepted)
		return ((*vlapic->ops.intr_accepted)(vlapic, vector));

	/*
	 * clear the ready bit for vector being accepted in irr
	 * and set the vector as in service in isr.
	 */
	idx = (vector / 32) * 4;

	irrptr = &lapic->irr0;
	atomic_clear_int(&irrptr[idx], 1 << (vector % 32));
	VLAPIC_CTR_IRR(vlapic, "vlapic_intr_accepted");

	isrptr = &lapic->isr0;
	isrptr[idx] |= 1 << (vector % 32);
	VLAPIC_CTR_ISR(vlapic, "vlapic_intr_accepted");

	/*
	 * The only way a fresh vector could be accepted into ISR is if it was
	 * of a higher priority than the current PPR.  With that vector now
	 * in-service, the PPR must be raised.
	 */
	vlapic_raise_ppr(vlapic, vector);

#ifdef __ISRVEC_DEBUG
	vlapic_isrstk_accept(vlapic, vector);
#endif
}

void
vlapic_svr_write_handler(struct vlapic *vlapic)
{
	struct LAPIC *lapic;
	uint32_t old, new, changed;

	lapic = vlapic->apic_page;

	new = lapic->svr;
	old = vlapic->svr_last;
	vlapic->svr_last = new;

	changed = old ^ new;
	if ((changed & APIC_SVR_ENABLE) != 0) {
		if ((new & APIC_SVR_ENABLE) == 0) {
			/*
			 * The apic is now disabled so stop the apic timer
			 * and mask all the LVT entries.
			 */
			VLAPIC_CTR0(vlapic, "vlapic is software-disabled");
			VLAPIC_TIMER_LOCK(vlapic);
			callout_stop(&vlapic->callout);
			VLAPIC_TIMER_UNLOCK(vlapic);
			vlapic_mask_lvts(vlapic);
		} else {
			/*
			 * The apic is now enabled so restart the apic timer
			 * if it is configured in periodic mode.
			 */
			VLAPIC_CTR0(vlapic, "vlapic is software-enabled");
			if (vlapic_periodic_timer(vlapic))
				vlapic_icrtmr_write_handler(vlapic);
		}
	}
}

int
vlapic_read(struct vlapic *vlapic, int mmio_access, uint64_t offset,
    uint64_t *data)
{
	struct LAPIC	*lapic = vlapic->apic_page;
	uint32_t	*reg;
	int		 i;

	/* Ignore MMIO accesses in x2APIC mode */
	if (x2apic(vlapic) && mmio_access) {
		VLAPIC_CTR1(vlapic, "MMIO read from offset %#lx in x2APIC mode",
		    offset);
		*data = 0;
		goto done;
	}

	if (!x2apic(vlapic) && !mmio_access) {
		/*
		 * XXX Generate GP fault for MSR accesses in xAPIC mode
		 */
		VLAPIC_CTR1(vlapic, "x2APIC MSR read from offset %#lx in "
		    "xAPIC mode", offset);
		*data = 0;
		goto done;
	}

	if (offset > sizeof (*lapic)) {
		*data = 0;
		goto done;
	}

	offset &= ~3;
	switch (offset) {
		case APIC_OFFSET_ID:
			*data = lapic->id;
			break;
		case APIC_OFFSET_VER:
			*data = lapic->version;
			break;
		case APIC_OFFSET_TPR:
			*data = vlapic_get_tpr(vlapic);
			break;
		case APIC_OFFSET_APR:
			*data = lapic->apr;
			break;
		case APIC_OFFSET_PPR:
			*data = lapic->ppr;
			break;
		case APIC_OFFSET_EOI:
			*data = lapic->eoi;
			break;
		case APIC_OFFSET_LDR:
			*data = lapic->ldr;
			break;
		case APIC_OFFSET_DFR:
			*data = lapic->dfr;
			break;
		case APIC_OFFSET_SVR:
			*data = lapic->svr;
			break;
		case APIC_OFFSET_ISR0 ... APIC_OFFSET_ISR7:
			i = (offset - APIC_OFFSET_ISR0) >> 2;
			reg = &lapic->isr0;
			*data = *(reg + i);
			break;
		case APIC_OFFSET_TMR0 ... APIC_OFFSET_TMR7:
			i = (offset - APIC_OFFSET_TMR0) >> 2;
			reg = &lapic->tmr0;
			*data = *(reg + i);
			break;
		case APIC_OFFSET_IRR0 ... APIC_OFFSET_IRR7:
			i = (offset - APIC_OFFSET_IRR0) >> 2;
			reg = &lapic->irr0;
			*data = atomic_load_acq_int(reg + i);
			break;
		case APIC_OFFSET_ESR:
			*data = lapic->esr;
			break;
		case APIC_OFFSET_ICR_LOW:
			*data = lapic->icr_lo;
			if (x2apic(vlapic))
				*data |= (uint64_t)lapic->icr_hi << 32;
			break;
		case APIC_OFFSET_ICR_HI:
			*data = lapic->icr_hi;
			break;
		case APIC_OFFSET_CMCI_LVT:
		case APIC_OFFSET_TIMER_LVT ... APIC_OFFSET_ERROR_LVT:
			*data = vlapic_get_lvt(vlapic, offset);
#ifdef INVARIANTS
			reg = vlapic_get_lvtptr(vlapic, offset);
			KASSERT(*data == *reg, ("inconsistent lvt value at "
			    "offset %#lx: %#lx/%#x", offset, *data, *reg));
#endif
			break;
		case APIC_OFFSET_TIMER_ICR:
			*data = lapic->icr_timer;
			break;
		case APIC_OFFSET_TIMER_CCR:
			*data = vlapic_get_ccr(vlapic);
			break;
		case APIC_OFFSET_TIMER_DCR:
			*data = lapic->dcr_timer;
			break;
		case APIC_OFFSET_SELF_IPI:
			/*
			 * XXX generate a GP fault if vlapic is in x2apic mode
			 */
			*data = 0;
			break;
		case APIC_OFFSET_RRR:
		default:
			*data = 0;
			break;
	}
done:
	VLAPIC_CTR2(vlapic, "vlapic read offset %#x, data %#lx", offset, *data);
	return (0);
}

int
vlapic_write(struct vlapic *vlapic, int mmio_access, uint64_t offset,
    uint64_t data)
{
	struct LAPIC	*lapic = vlapic->apic_page;
	uint32_t	*regptr;
	int		retval;

	KASSERT((offset & 0xf) == 0 && offset < PAGE_SIZE,
	    ("vlapic_write: invalid offset %lx", offset));

	VLAPIC_CTR2(vlapic, "vlapic write offset %#lx, data %#lx",
	    offset, data);

	if (offset > sizeof (*lapic))
		return (0);

	/* Ignore MMIO accesses in x2APIC mode */
	if (x2apic(vlapic) && mmio_access) {
		VLAPIC_CTR2(vlapic, "MMIO write of %#lx to offset %#lx "
		    "in x2APIC mode", data, offset);
		return (0);
	}

	/*
	 * XXX Generate GP fault for MSR accesses in xAPIC mode
	 */
	if (!x2apic(vlapic) && !mmio_access) {
		VLAPIC_CTR2(vlapic, "x2APIC MSR write of %#lx to offset %#lx "
		    "in xAPIC mode", data, offset);
		return (0);
	}

	retval = 0;
	switch (offset) {
		case APIC_OFFSET_ID:
			lapic->id = data;
			vlapic_id_write_handler(vlapic);
			break;
		case APIC_OFFSET_TPR:
			vlapic_set_tpr(vlapic, data & 0xff);
			break;
		case APIC_OFFSET_EOI:
			vlapic_process_eoi(vlapic);
			break;
		case APIC_OFFSET_LDR:
			lapic->ldr = data;
			vlapic_ldr_write_handler(vlapic);
			break;
		case APIC_OFFSET_DFR:
			lapic->dfr = data;
			vlapic_dfr_write_handler(vlapic);
			break;
		case APIC_OFFSET_SVR:
			lapic->svr = data;
			vlapic_svr_write_handler(vlapic);
			break;
		case APIC_OFFSET_ICR_LOW:
			lapic->icr_lo = data;
			if (x2apic(vlapic))
				lapic->icr_hi = data >> 32;
			retval = vlapic_icrlo_write_handler(vlapic);
			break;
		case APIC_OFFSET_ICR_HI:
			lapic->icr_hi = data;
			break;
		case APIC_OFFSET_CMCI_LVT:
		case APIC_OFFSET_TIMER_LVT ... APIC_OFFSET_ERROR_LVT:
			regptr = vlapic_get_lvtptr(vlapic, offset);
			*regptr = data;
			vlapic_lvt_write_handler(vlapic, offset);
			break;
		case APIC_OFFSET_TIMER_ICR:
			lapic->icr_timer = data;
			vlapic_icrtmr_write_handler(vlapic);
			break;

		case APIC_OFFSET_TIMER_DCR:
			lapic->dcr_timer = data;
			vlapic_dcr_write_handler(vlapic);
			break;

		case APIC_OFFSET_ESR:
			vlapic_esr_write_handler(vlapic);
			break;

		case APIC_OFFSET_SELF_IPI:
			if (x2apic(vlapic))
				vlapic_self_ipi_handler(vlapic, data);
			break;

		case APIC_OFFSET_VER:
		case APIC_OFFSET_APR:
		case APIC_OFFSET_PPR:
		case APIC_OFFSET_RRR:
		case APIC_OFFSET_ISR0 ... APIC_OFFSET_ISR7:
		case APIC_OFFSET_TMR0 ... APIC_OFFSET_TMR7:
		case APIC_OFFSET_IRR0 ... APIC_OFFSET_IRR7:
		case APIC_OFFSET_TIMER_CCR:
		default:
			// Read only.
			break;
	}

	return (retval);
}

void
vlapic_reset(struct vlapic *vlapic)
{
	struct LAPIC *lapic = vlapic->apic_page;
	uint32_t *isrptr, *tmrptr, *irrptr;

	/* Reset any timer-related state first */
	VLAPIC_TIMER_LOCK(vlapic);
	callout_stop(&vlapic->callout);
	lapic->icr_timer = 0;
	lapic->ccr_timer = 0;
	VLAPIC_TIMER_UNLOCK(vlapic);
	lapic->dcr_timer = 0;
	vlapic_dcr_write_handler(vlapic);

	/*
	 * Sync any APIC acceleration (APICv/AVIC) state into the APIC page so
	 * it is not leftover after the reset.  This is performed after the APIC
	 * timer has been stopped, in case it happened to fire just prior to
	 * being deactivated.
	 */
	if (vlapic->ops.sync_state) {
		(*vlapic->ops.sync_state)(vlapic);
	}

	lapic->id = vlapic_get_id(vlapic);
	lapic->version = VLAPIC_VERSION;
	lapic->version |= (VLAPIC_MAXLVT_INDEX << MAXLVTSHIFT);

	lapic->tpr = 0;
	lapic->apr = 0;
	lapic->ppr = 0;

#ifdef __ISRVEC_DEBUG
	/* With the PPR cleared, the isrvec tracking should be reset too */
	vlapic->isrvec_stk_top = 0;
#endif

	lapic->eoi = 0;
	lapic->ldr = 0;
	lapic->dfr = 0xffffffff;
	lapic->svr = APIC_SVR_VECTOR;
	vlapic->svr_last = lapic->svr;

	isrptr = &lapic->isr0;
	tmrptr = &lapic->tmr0;
	irrptr = &lapic->irr0;
	for (uint_t i = 0; i < 8; i++) {
		atomic_store_rel_int(&isrptr[i * 4], 0);
		atomic_store_rel_int(&tmrptr[i * 4], 0);
		atomic_store_rel_int(&irrptr[i * 4], 0);
	}

	lapic->esr = 0;
	vlapic->esr_pending = 0;
	lapic->icr_lo = 0;
	lapic->icr_hi = 0;

	lapic->lvt_cmci = 0;
	lapic->lvt_timer = 0;
	lapic->lvt_thermal = 0;
	lapic->lvt_pcint = 0;
	lapic->lvt_lint0 = 0;
	lapic->lvt_lint1 = 0;
	lapic->lvt_error = 0;
	vlapic_mask_lvts(vlapic);
}

void
vlapic_init(struct vlapic *vlapic)
{
	KASSERT(vlapic->vm != NULL, ("vlapic_init: vm is not initialized"));
	KASSERT(vlapic->vcpuid >= 0 &&
	    vlapic->vcpuid < vm_get_maxcpus(vlapic->vm),
	    ("vlapic_init: vcpuid is not initialized"));
	KASSERT(vlapic->apic_page != NULL, ("vlapic_init: apic_page is not "
	    "initialized"));

	/*
	 * If the vlapic is configured in x2apic mode then it will be
	 * accessed in the critical section via the MSR emulation code.
	 *
	 * Therefore the timer mutex must be a spinlock because blockable
	 * mutexes cannot be acquired in a critical section.
	 */
	mtx_init(&vlapic->timer_mtx, "vlapic timer mtx", NULL, MTX_SPIN);
	callout_init(&vlapic->callout, 1);

	vlapic->msr_apicbase = DEFAULT_APIC_BASE | APICBASE_ENABLED;

	if (vlapic->vcpuid == 0)
		vlapic->msr_apicbase |= APICBASE_BSP;

	vlapic_reset(vlapic);
}

void
vlapic_cleanup(struct vlapic *vlapic)
{

	callout_drain(&vlapic->callout);
}

uint64_t
vlapic_get_apicbase(struct vlapic *vlapic)
{

	return (vlapic->msr_apicbase);
}

int
vlapic_set_apicbase(struct vlapic *vlapic, uint64_t new)
{

	if (vlapic->msr_apicbase != new) {
		VLAPIC_CTR2(vlapic, "Changing APIC_BASE MSR from %#lx to %#lx "
		    "not supported", vlapic->msr_apicbase, new);
		return (-1);
	}

	return (0);
}

void
vlapic_set_x2apic_state(struct vm *vm, int vcpuid, enum x2apic_state state)
{
	struct vlapic *vlapic;
	struct LAPIC *lapic;

	vlapic = vm_lapic(vm, vcpuid);

	if (state == X2APIC_DISABLED)
		vlapic->msr_apicbase &= ~APICBASE_X2APIC;
	else
		vlapic->msr_apicbase |= APICBASE_X2APIC;

	/*
	 * Reset the local APIC registers whose values are mode-dependent.
	 *
	 * XXX this works because the APIC mode can be changed only at vcpu
	 * initialization time.
	 */
	lapic = vlapic->apic_page;
	lapic->id = vlapic_get_id(vlapic);
	if (x2apic(vlapic)) {
		lapic->ldr = x2apic_ldr(vlapic);
		lapic->dfr = 0;
	} else {
		lapic->ldr = 0;
		lapic->dfr = 0xffffffff;
	}

	if (state == X2APIC_ENABLED) {
		if (vlapic->ops.enable_x2apic_mode)
			(*vlapic->ops.enable_x2apic_mode)(vlapic);
	}
}

void
vlapic_deliver_intr(struct vm *vm, bool level, uint32_t dest, bool phys,
    int delmode, int vec)
{
	bool lowprio;
	int vcpuid;
	cpuset_t dmask;

	if (delmode != IOART_DELFIXED &&
	    delmode != IOART_DELLOPRI &&
	    delmode != IOART_DELEXINT) {
		VM_CTR1(vm, "vlapic intr invalid delmode %#x", delmode);
		return;
	}
	lowprio = (delmode == IOART_DELLOPRI);

	/*
	 * We don't provide any virtual interrupt redirection hardware so
	 * all interrupts originating from the ioapic or MSI specify the
	 * 'dest' in the legacy xAPIC format.
	 */
	vlapic_calcdest(vm, &dmask, dest, phys, lowprio, false);

	while ((vcpuid = CPU_FFS(&dmask)) != 0) {
		vcpuid--;
		CPU_CLR(vcpuid, &dmask);
		if (delmode == IOART_DELEXINT) {
			vm_inject_extint(vm, vcpuid);
		} else {
			lapic_set_intr(vm, vcpuid, vec, level);
		}
	}
}

void
vlapic_post_intr(struct vlapic *vlapic, int hostcpu)
{
	/*
	 * Post an interrupt to the vcpu currently running on 'hostcpu'.
	 *
	 * This is done by leveraging features like Posted Interrupts (Intel)
	 * Doorbell MSR (AMD AVIC) that avoid a VM exit.
	 *
	 * If neither of these features are available then fallback to
	 * sending an IPI to 'hostcpu'.
	 */
	if (vlapic->ops.post_intr)
		(*vlapic->ops.post_intr)(vlapic, hostcpu);
	else
		poke_cpu(hostcpu);
}

bool
vlapic_enabled(struct vlapic *vlapic)
{
	struct LAPIC *lapic = vlapic->apic_page;

	if ((vlapic->msr_apicbase & APICBASE_ENABLED) != 0 &&
	    (lapic->svr & APIC_SVR_ENABLE) != 0)
		return (true);
	else
		return (false);
}

void
vlapic_localize_resources(struct vlapic *vlapic)
{
	vmm_glue_callout_localize(&vlapic->callout);
}

#ifdef __ISRVEC_DEBUG
static void
vlapic_isrstk_eoi(struct vlapic *vlapic, int vector)
{
	if (vlapic->isrvec_stk_top <= 0) {
		panic("invalid vlapic isrvec_stk_top %d",
		    vlapic->isrvec_stk_top);
	}
	vlapic->isrvec_stk_top--;
	vlapic_isrstk_verify(vlapic);
}

static void
vlapic_isrstk_accept(struct vlapic *vlapic, int vector)
{
	int stk_top;

	vlapic->isrvec_stk_top++;

	stk_top = vlapic->isrvec_stk_top;
	if (stk_top >= ISRVEC_STK_SIZE)
		panic("isrvec_stk_top overflow %d", stk_top);

	vlapic->isrvec_stk[stk_top] = vector;
	vlapic_isrstk_verify(vlapic);
}

static void
vlapic_isrstk_dump(const struct vlapic *vlapic)
{
	int i;
	uint32_t *isrptr;

	isrptr = &vlapic->apic_page->isr0;
	for (i = 0; i < 8; i++)
		printf("ISR%d 0x%08x\n", i, isrptr[i * 4]);

	for (i = 0; i <= vlapic->isrvec_stk_top; i++)
		printf("isrvec_stk[%d] = %d\n", i, vlapic->isrvec_stk[i]);
}

static void
vlapic_isrstk_verify(const struct vlapic *vlapic)
{
	int i, lastprio, curprio, vector, idx;
	uint32_t *isrptr;

	/*
	 * Note: The value at index 0 in isrvec_stk is always 0.
	 *
	 * It is a placeholder for the value of ISR vector when no bits are set
	 * in the ISRx registers.
	 */
	if (vlapic->isrvec_stk_top == 0 && vlapic->isrvec_stk[0] != 0) {
		panic("isrvec_stk is corrupted: %d", vlapic->isrvec_stk[0]);
	}

	/*
	 * Make sure that the priority of the nested interrupts is
	 * always increasing.
	 */
	lastprio = -1;
	for (i = 1; i <= vlapic->isrvec_stk_top; i++) {
		curprio = PRIO(vlapic->isrvec_stk[i]);
		if (curprio <= lastprio) {
			vlapic_isrstk_dump(vlapic);
			panic("isrvec_stk does not satisfy invariant");
		}
		lastprio = curprio;
	}

	/*
	 * Make sure that each bit set in the ISRx registers has a
	 * corresponding entry on the isrvec stack.
	 */
	i = 1;
	isrptr = &vlapic->apic_page->isr0;
	for (vector = 0; vector < 256; vector++) {
		idx = (vector / 32) * 4;
		if (isrptr[idx] & (1 << (vector % 32))) {
			if (i > vlapic->isrvec_stk_top ||
			    vlapic->isrvec_stk[i] != vector) {
				vlapic_isrstk_dump(vlapic);
				panic("ISR and isrvec_stk out of sync");
			}
			i++;
		}
	}
}
#endif
