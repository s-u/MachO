/* Mach-O header parser. Supports both fat and thin Mach-O files.
   However, it will only interpret Mach-O files of the same
   architecture as this binary.

   (c)2022 Simon Urbanek - https://urbanek.nz
   License: MIT
*/

#if __APPLE__
/* on macOS we can use native definitions */
#include <mach-o/loader.h>
#include <mach-o/fat.h>
#else
/* otherwise use a compatibility layer */
#include "mach-o.h"
#endif

#include <stdio.h>
#include <string.h>
#include <stdlib.h>

struct mach_common_part {
    uint32_t magic;
    cpu_type_t cputype;
    cpu_subtype_t cpusubtype;
    uint32_t filetype;
    uint32_t ncmds;
    uint32_t sizeofcmds;
    uint32_t flags;
};

typedef union mach_headers {
    struct mach_common_part h;
    struct mach_header h32;
    struct mach_header_64 h64;
} mach_headers_ty;

/* flip endianness of fat headers if the magic indicates so */
static void flip4(void *buf, unsigned int n, uint32_t magic) {
    if (magic != FAT_CIGAM) return;
    unsigned char *c = (unsigned char *)buf;
    while (n--) {
	unsigned char t = c[0]; c[0] = c[3]; c[3] = t;
	t = c[1]; c[1] = c[2]; c[2] = t;
	c += 4;
    }
}

#include <Rinternals.h>

static const char *cputype2str(cpu_type_t t) {
    const char *cpu = 0;
    switch(t) {
    case CPU_TYPE_VAX: cpu = "vax"; break;
    case CPU_TYPE_MC680x0: cpu = "mc680x0"; break;
    case CPU_TYPE_X86: cpu = "i386"; break;
    case CPU_TYPE_X86_64: cpu = "x86_64"; break;
    case CPU_TYPE_ARM: cpu = "arm"; break;
    case CPU_TYPE_ARM64: cpu = "arm64"; break;
    case CPU_TYPE_ARM64_32: cpu = "arm64/32"; break;
    case CPU_TYPE_SPARC: cpu = "sparc"; break;
    case CPU_TYPE_POWERPC: cpu = "ppc"; break;
    case CPU_TYPE_POWERPC64: cpu = "pp64"; break;
    case CPU_TYPE_HPPA: cpu = "hppa"; break;
    default: cpu = "<unknown>"; break;
    }
    return cpu;
}

SEXP macho(SEXP sFile, SEXP sArch) {
    if (TYPEOF(sFile) != STRSXP || LENGTH(sFile) != 1)
	Rf_error("Invalid file name");
    /* FIXME: translate ? */
    const char *fn = CHAR(STRING_ELT(sFile, 0));
    const char *target_arch = 0;

    SEXP archs = 0;
    
    if (TYPEOF(sArch) == STRSXP && LENGTH(sArch) == 1)
	target_arch = CHAR(STRING_ELT(sArch, 0));

    FILE *f = fopen(fn, "rb");
    if (!f)
	Rf_error("Cannot open '%s'!\n", fn);

    uint32_t magic;
    
    if (fread(&magic, sizeof(magic), 1, f) != 1)
	Rf_error("Cannot read magic number");

    if (magic == FAT_MAGIC || magic == FAT_CIGAM) {
	uint32_t nfat_arch, native_offset = 0, fallback_offset = 0, target_offset = 0, desired_offset = 0, i = 0;
	printf("Fat file\n");
	if (fread(&nfat_arch, sizeof(nfat_arch), 1, f) != 1) {
	    fclose(f);
	    Rf_error("Cannot read number of fat archs");
	}
	flip4(&nfat_arch, 1, magic);
	archs = PROTECT(Rf_allocVector(VECSXP, nfat_arch));
	SEXP sAN = PROTECT(Rf_allocVector(STRSXP, nfat_arch));
	Rf_setAttrib(archs, R_NamesSymbol, sAN);
	UNPROTECT(1);
	while (i < nfat_arch) {
	    struct fat_arch fa;
	    if (fread(&fa, sizeof(fa), 1, f) != 1)
		Rf_error("Cannot read fat architecture header");
	    flip4(&fa, 5, magic);
	    const char *cpu = cputype2str(fa.cputype);
	    /* find native and fall-back type */
	    switch (fa.cputype) {
	    case CPU_TYPE_X86:
#ifdef __i386__
		native_offset = fa.offset;
#endif
#ifdef __x86_64__
		fallback_offset = fa.offset;
#endif
		break;
	    case CPU_TYPE_X86_64:
#ifdef __x86_64__
		native_offset = fa.offset;
#endif
		break;
	    case CPU_TYPE_ARM64:
#ifdef __arm64__
		native_offset = fa.offset;
#endif
		break;
	    case CPU_TYPE_POWERPC:
#ifdef __ppc__
		native_offset = fa.offset;
#endif
#ifdef __ppc64__
		fallback_offset = fa.offset;
#endif
		break;
	    case CPU_TYPE_POWERPC64:
#ifdef __ppc64__
		native_offset = fa.offset;
#endif
		break;
	    }
	    if (target_arch && !strcmp(target_arch, cpu))
		target_offset = fa.offset;
	    const char *names[] = { "cpu.subtype", "offset", "size", "native", "fallback", "" };
	    SEXP ai = PROTECT(Rf_mkNamed(VECSXP, names));
	    SET_STRING_ELT(sAN, i, Rf_mkChar(cpu));
	    SET_VECTOR_ELT(archs, i++, ai);
	    UNPROTECT(1);
	    SET_VECTOR_ELT(ai, 0, Rf_ScalarReal((double) fa.cpusubtype));
	    SET_VECTOR_ELT(ai, 1, Rf_ScalarReal((double) fa.offset));
	    SET_VECTOR_ELT(ai, 2, Rf_ScalarReal((double) fa.size));
	    SET_VECTOR_ELT(ai, 3, Rf_ScalarLogical(native_offset == fa.offset));
	    SET_VECTOR_ELT(ai, 4, Rf_ScalarLogical(native_offset == fa.offset || fallback_offset == fa.offset));
	}
	if (target_arch && !target_offset) {
	    fclose(f);
	    UNPROTECT(1);
	    return archs;
	}
	desired_offset =  target_offset ? target_offset : (native_offset ? native_offset : fallback_offset);
	if (!desired_offset) {
	    fclose(f);
	    Rf_error("No valid architecture found");
	}
	/* seek here into desired offset */
	if (fseek(f, desired_offset, SEEK_SET) != 0) {
	    fclose(f);
	    Rf_error("Cannot seek to the beginning of the object in a fat file.");
	}
	/* read magic */
	if (fread(&magic, sizeof(magic), 1, f) != 1) {
	    fclose(f);
	    Rf_error("Cannot read Mach-O magic number!");
	}
    }
    /* magic has been read, so continue */
    mach_headers_ty h;
    if (fread(&h.h.cputype, sizeof(struct mach_common_part) - sizeof(magic), 1, f) != 1) {
	fclose(f);
	Rf_error("Cannot read Mach-O common header");
    }
    const char *names[] = { "filename", "archs", "cpu", "abi", "type", "id", "loads", "min.version", "sdk", "" };
    SEXP res = PROTECT(Rf_mkNamed(VECSXP, names));
    SET_VECTOR_ELT(res, 0, sFile);
    if (archs) SET_VECTOR_ELT(res, 1, archs);
    SET_VECTOR_ELT(res, 2, Rf_mkString(cputype2str(h.h.cputype)));
    h.h.magic = magic; /* copy the magic value */
    if (h.h32.magic == MH_MAGIC) {
	SET_VECTOR_ELT(res, 3, Rf_ScalarInteger(32));
    } else if (h.h32.magic == MH_CIGAM) {
	fclose(f);
	Rf_error("Mach-O 32-bit, reverse endianness, cannot parse");
    } else if (h.h64.magic == MH_MAGIC_64) {
	SET_VECTOR_ELT(res, 3, Rf_ScalarInteger(64));
	if (fread(&h.h64.reserved, sizeof(struct mach_header_64) - sizeof(struct mach_common_part), 1, f) != 1) {
	    fclose(f);
	    Rf_error("Cannot read 64-bit header");
	}
    } else if (h.h64.magic == MH_CIGAM_64) {
	fclose(f);
	Rf_error("Mach-O 64-bit, reverse endianness, cannot parse");
    } else{
	fclose(f);
	Rf_error("Not a valid Mach-O file");
    }
    const char *tyn = 0;
    switch (h.h.filetype) {
    case MH_OBJECT: tyn = "object"; break;
    case MH_EXECUTE: tyn = "executable"; break;
    case MH_BUNDLE: tyn = "bundle"; break;
    case MH_DYLIB: tyn = "dylib"; break;
    case MH_DYLIB_STUB: tyn = "dylib-stub"; break;
    case MH_PRELOAD: tyn = "preload"; break;
    case MH_CORE: tyn = "core dump"; break;
    case MH_DYLINKER: tyn ="dylinker"; break;
    case MH_DSYM: tyn = "DSYM"; break;
    }
    SET_VECTOR_ELT(res, 4, tyn ? Rf_mkString(tyn) : NA_STRING);
    /* printf("File type: %s, load size: %d bytes\n", tyn, (int) h.h.sizeofcmds); */

    char *ld = (char*) malloc(h.h.sizeofcmds), *ld0 = ld;
    if (!ld) {
	fclose(f);
	Rf_error("Cannot allocate %d bytes for load commands\n", (int) h.h.sizeofcmds);
    }
    if (fread(ld, h.h.sizeofcmds, 1, f) != 1) {
	free(ld);
	fclose(f);
	Rf_error("Cannot read load commands\n");
    }
    char *lde = ld + h.h.sizeofcmds;
    uint32_t n_load_dylib = 0;
    while (ld < lde) {
	struct load_command *lc = (struct load_command*) ld;
	ld += lc->cmdsize;
	switch (lc->cmd) {
	case LC_ID_DYLIB: 
	case LC_LOAD_DYLIB: { /* they both use dylib_command */
	    struct dylib_command *dyc = (struct dylib_command*) lc;
	    char *name = ((char*)dyc) + dyc->dylib.name.offset;
	    if (lc->cmd == LC_ID_DYLIB)
		SET_VECTOR_ELT(res, 5, Rf_mkString(name));
	    else
		n_load_dylib++;
	}
	    break;
	case LC_BUILD_VERSION:
	case LC_VERSION_MIN_MACOSX: /* also same as LC_VERSION_MIN_WATCHOS, LC_VERSION_MIN_IPHONEOS, LC_VERSION_MIN_TVOS */
	    {
		uint32_t minver = 0, sdk = 0;
		if (lc->cmd == LC_BUILD_VERSION) {
		    struct build_version_command *bvc = (struct build_version_command*) lc;
		    minver = bvc->minos;
		    sdk = bvc->sdk;
		    /* we're ignoring platform and ntools .. */
		} else {
		    struct version_min_command *vmc = (struct version_min_command*) lc;
		    minver = vmc->version;
		    sdk = vmc->sdk;
		}
		SEXP sVer = SET_VECTOR_ELT(res, 7, Rf_allocVector(INTSXP, 3));
		SEXP sSDK = SET_VECTOR_ELT(res, 8, Rf_allocVector(INTSXP, 3));
		INTEGER(sVer)[0] = (int) (minver >> 16);
		INTEGER(sVer)[1] = (int) ((minver >> 8) & 255);
		INTEGER(sVer)[2] = (int) (minver & 255);
		INTEGER(sSDK)[0] = (int) (sdk >> 16);
		INTEGER(sSDK)[1] = (int) ((sdk >> 8) & 255);
		INTEGER(sSDK)[2] = (int) (sdk & 255);
		break;
	    }
	}
    }
    if (n_load_dylib) { /* pass #2 extract the dylib loads */
	SEXP sLoads = PROTECT(Rf_allocVector(STRSXP, n_load_dylib));
	uint32_t i = 0;
	SET_VECTOR_ELT(res, 6, sLoads);
	UNPROTECT(1);
	ld = ld0;
	while (ld < lde) {
	    struct load_command *lc = (struct load_command*) ld;
	    ld += lc->cmdsize;
	    if (lc->cmd == LC_LOAD_DYLIB) {
		struct dylib_command *dyc = (struct dylib_command*) lc;
		char *name = ((char*)dyc) + dyc->dylib.name.offset;
		SET_STRING_ELT(sLoads, i++, Rf_mkChar(name));
	    }
	}
    }
    fclose(f);
    free(ld0);
    if (archs) UNPROTECT(1);
    UNPROTECT(1);
    return res;
}
