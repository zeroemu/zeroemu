// zeroemu's vDSO for arm64 guests: clock_gettime, gettimeofday and clock_getres
// without leaving the VM, as Linux's arm64 vDSO answers them (arch/arm64/kernel/vdso,
// lib/vdso/gettimeofday.c). Built by scripts/build-vdso.sh into vdso.so, which
// src/kernel/vdso.rs maps into every arm64 process; see that file for the layout of
// the [vvar] page these read, which is mapped just below this image.
//
// Each function answers what it can from the guest's virtual counter, CNTVCT_EL0,
// and the [vvar] page, and makes the syscall for everything else (the CPU-time
// clocks, ids it doesn't know, a counter it can't use), returning what the syscall
// returns: 0 or -errno, as bionic's vdso_return expects.
//
// Only x0-x17 are used: they are the caller's to lose (AAPCS64). x18 is not, and
// Android keeps its shadow call stack there.

#define VVAR_SEQ	0
#define VVAR_SERVED	4
#define VVAR_BASE	8
#define VVAR_MULT	16
#define VVAR_OFFSETS	64

#define NR_gettimeofday		169
#define NR_clock_gettime	113
#define NR_clock_getres		114
#define CLOCK_REALTIME		0

	.text

// x2 = the [vvar] page. It is the page below this image, wherever that is mapped.
.macro	vvar_page
	adrp	x2, _vvar
	add	x2, x2, :lo12:_vvar
.endm

// x6 = nanoseconds on a clock: CLOCK_MONOTONIC from the counter, plus the clock's
// offset, read from x4. In: x2, the [vvar] page. Uses x5-x12.
//
// The host may change an offset at any time (CLOCK_REALTIME's follows the host's
// wall clock), so the reads go inside a sequence count as Linux's do
// (include/vdso/helpers.h): an odd count means a change is under way, and a count
// that moved means one happened while reading.
.macro	clock_ns
70:	ldar	w5, [x2, #VVAR_SEQ]
	tbnz	w5, #0, 70b
	// Without the isb the counter could be read early, before something this
	// thread has already seen happen (Linux's __arch_get_hw_counter).
	isb
	mrs	x6, cntvct_el0
	ldr	x7, [x2, #VVAR_BASE]
	ldp	w9, w10, [x2, #VVAR_MULT]
	ldr	x11, [x4]
	dmb	ishld
	// The count is read again only once the counter has been: the address depends
	// on the counter's value (arch_counter_enforce_ordering in Linux).
	eor	x12, x6, x6
	ldr	w12, [x2, x12]
	cmp	w12, w5
	b.ne	70b
	// ns = ticks * numer / denom, exactly and without overflow for centuries:
	// (t / denom) * numer + (t % denom) * numer / denom. zeroemu computes its own
	// clocks the same way (src/kernel/clock.rs), so both agree to the nanosecond.
	sub	x6, x6, x7
	udiv	x7, x6, x10
	msub	x6, x7, x10, x6
	mul	x7, x7, x9
	mul	x6, x6, x9
	udiv	x6, x6, x10
	add	x6, x6, x7
	add	x6, x6, x11
.endm

// x9 = x6 / 1e9, x10 = x6 % 1e9. Uses x7.
.macro	split_seconds
	mov	x7, #0xca00
	movk	x7, #0x3b9a, lsl #16
	udiv	x9, x6, x7
	msub	x10, x9, x7, x6
.endm

// int __kernel_clock_gettime(clockid_t id, struct timespec *ts)
	.globl	__kernel_clock_gettime
	.type	__kernel_clock_gettime, %function
	.p2align 4
__kernel_clock_gettime:
	.cfi_startproc
	// Negative ids (CPU-time clocks) and large ones compare above 31.
	cmp	w0, #31
	b.hi	9f
	vvar_page
	ldr	w3, [x2, #VVAR_SERVED]
	lsr	w3, w3, w0
	tbz	w3, #0, 9f
	add	x4, x2, #VVAR_OFFSETS
	add	x4, x4, w0, uxtw #3
	clock_ns
	split_seconds
	stp	x9, x10, [x1]
	mov	w0, #0
	ret
9:	mov	x8, #NR_clock_gettime
	svc	#0
	ret
	.cfi_endproc
	.size	__kernel_clock_gettime, . - __kernel_clock_gettime

// int __kernel_gettimeofday(struct timeval *tv, struct timezone *tz)
	.globl	__kernel_gettimeofday
	.type	__kernel_gettimeofday, %function
	.p2align 4
__kernel_gettimeofday:
	.cfi_startproc
	vvar_page
	cbz	x0, 1f
	ldr	w3, [x2, #VVAR_SERVED]
	tbz	w3, #CLOCK_REALTIME, 9f
	add	x4, x2, #VVAR_OFFSETS + CLOCK_REALTIME * 8
	clock_ns
	split_seconds
	mov	x7, #1000
	udiv	x10, x10, x7
	stp	x9, x10, [x0]
	// The time zone is Linux's sys_tz, which is zeros unless settimeofday set it
	// (kernel/time/time.c), and zeroemu's settimeofday sets nothing.
1:	cbz	x1, 2f
	str	xzr, [x1]
2:	mov	w0, #0
	ret
9:	mov	x8, #NR_gettimeofday
	svc	#0
	ret
	.cfi_endproc
	.size	__kernel_gettimeofday, . - __kernel_gettimeofday

// int __kernel_clock_getres(clockid_t id, struct timespec *res)
	.globl	__kernel_clock_getres
	.type	__kernel_clock_getres, %function
	.p2align 4
__kernel_clock_getres:
	.cfi_startproc
	cmp	w0, #31
	b.hi	9f
	vvar_page
	ldr	w3, [x2, #VVAR_SERVED]
	lsr	w3, w3, w0
	tbz	w3, #0, 9f
	// 1 ns, what the syscall says too: Linux's high-resolution clocks report
	// hrtimer_resolution, and these are exact to the nanosecond.
	cbz	x1, 1f
	mov	x3, #1
	stp	xzr, x3, [x1]
1:	mov	w0, #0
	ret
9:	mov	x8, #NR_clock_getres
	svc	#0
	ret
	.cfi_endproc
	.size	__kernel_clock_getres, . - __kernel_clock_getres
