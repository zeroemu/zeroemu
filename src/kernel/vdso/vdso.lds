/*
 * Layout of zeroemu's arm64 vDSO (vdso.S). One read-and-execute segment, linked at
 * 0, holds the headers, the dynamic symbol table and the code, so that the image
 * mapped as it is in the file is already "loaded": bionic's linker (add_vdso) and
 * libc (__libc_init_vdso) take it as found, with no relocations to apply. The
 * section headers follow it in the file and are mapped too, because libc counts
 * the symbols from the size of the SHT_DYNSYM section.
 */

SECTIONS
{
	/* The [vvar] page: the page below the image, wherever it is mapped. Code
	 * reaches it PC-relatively, so nothing needs relocating. */
	PROVIDE_HIDDEN(_vvar = . - 4096);

	. = SIZEOF_HEADERS;

	.hash		: { *(.hash) }			:text
	.gnu.hash	: { *(.gnu.hash) }
	.dynsym		: { *(.dynsym) }
	.dynstr		: { *(.dynstr) }
	.gnu.version	: { *(.gnu.version) }
	.gnu.version_d	: { *(.gnu.version_d) }
	.gnu.version_r	: { *(.gnu.version_r) }
	.dynamic	: { *(.dynamic) }		:text :dynamic
	.eh_frame_hdr	: { *(.eh_frame_hdr) }		:text :eh_frame_hdr
	.eh_frame	: { KEEP(*(.eh_frame)) }	:text
	.text		: { *(.text*) }			:text

	/DISCARD/	: { *(.data*) *(.bss*) *(.note*) *(.comment) *(.interp) }
}

PHDRS
{
	text		PT_LOAD		FLAGS(5) FILEHDR PHDRS;	/* read, execute */
	dynamic		PT_DYNAMIC	FLAGS(4);
	eh_frame_hdr	PT_GNU_EH_FRAME	FLAGS(4);
}

/* The version Linux's arm64 vDSO gives its symbols. bionic looks them up by name
 * alone; glibc, musl and Go ask for this version. */
VERSION
{
	LINUX_2.6.39 {
	global:
		__kernel_clock_gettime;
		__kernel_gettimeofday;
		__kernel_clock_getres;
		__kernel_rt_sigreturn;
	local: *;
	};
}
