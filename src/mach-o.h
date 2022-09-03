/* Mach-O compatibility API from the specs.
   It is intended to be compatible with Apple's
   mach-o include files as far as struct layout
   and names, but it may not be necessarily identical
   (i.e. do not try to include both as they are likely 
   to clash due to slightly different definitions).
   Includes only piece we parse.

   (c)2022 Simon Urbanek - https://urbanek.nz
   License: MIT
*/

/* magic numbers */
#define MH_MAGIC    0xfeedface
#define MH_CIGAM    0xcefaedfe
#define MH_MAGIC_64 0xfeedfacf
#define MH_CIGAM_64 0xcffaedfe
#define FAT_MAGIC   0xcafebabe
#define FAT_CIGAM   0xbebafeca

/* need exact int types */
#include <stdint.h>

/* pretty much everything is uint32_t, but those
   two have dedicated types */
typedef uint32_t cpu_type_t;
typedef uint32_t cpu_subtype_t;

#define CPU_ARCH_ABI64     0x1000000
#define CPU_ARCH_ABI64_32  0x2000000

#define CPU_TYPE_VAX       1
#define CPU_TYPE_MC680x0   6
#define CPU_TYPE_X86       7
#define CPU_TYPE_X86_64    (CPU_TYPE_X86 | CPU_ARCH_ABI64)
#define CPU_TYPE_HPPA      11
#define CPU_TYPE_ARM       12
#define CPU_TYPE_ARM64     (CPU_TYPE_ARM | CPU_ARCH_ABI64)
#define CPU_TYPE_ARM64_32  (CPU_TYPE_ARM | CPU_ARCH_ABI64_32)
#define CPU_TYPE_SPARC     14
#define CPU_TYPE_POWERPC   18
#define CPU_TYPE_POWERPC64 (CPU_TYPE_POWERPC | CPU_ARCH_ABI64)

struct mach_header {
    uint32_t      magic;
    cpu_type_t    cputype;
    cpu_subtype_t cpusubtype;
    uint32_t      filetype;
    uint32_t      ncmds;
    uint32_t      sizeofcmds;
    uint32_t      flags;
};

struct mach_header_64 {
    uint32_t      magic;
    cpu_type_t    cputype;
    cpu_subtype_t cpusubtype;
    uint32_t      filetype;
    uint32_t      ncmds;
    uint32_t      sizeofcmds;
    uint32_t      flags;
    uint32_t      reserved;
};

/* filetype - for us only informational */
#define MH_OBJECT       1
#define MH_EXECUTE      2
#define MH_CORE         4
#define MH_PRELOAD      5
#define MH_DYLIB        6
#define MH_DYLINKER     7
#define MH_BUNDLE       8
#define MH_DYLIB_STUB   9
#define MH_DSYM         10

/* load commands (LC) - what we're most interested in */
struct load_command {
    uint32_t cmd;
    uint32_t cmdsize;
};

#define LC_LOAD_DYLIB         0x0c
#define LC_ID_DYLIB           0x0d
#define LC_VERSION_MIN_MACOSX 0x24
#define LC_BUILD_VERSION      0x32

struct lc_str {
    uint32_t offset;
};

struct dylib {
    struct lc_str name;
    uint32_t timestamp;
    uint32_t current_version;
    uint32_t compatibility_version;
};

struct dylib_command {
    uint32_t     cmd;
    uint32_t     cmdsize;
    struct dylib dylib;
};

struct version_min_command {
    uint32_t cmd;
    uint32_t cmdsize;
    uint32_t version;
    uint32_t sdk;
};

struct build_version_command {
    uint32_t cmd;
    uint32_t cmdsize;
    uint32_t platform;
    uint32_t minos;
    uint32_t sdk;
    uint32_t ntools;
};

/* fat file header - index into the contents by arch */
struct fat_header {
    uint32_t magic;
    uint32_t nfat_arch;
};

struct fat_arch {
    cpu_type_t    cputype;
    cpu_subtype_t cpusubtype;
    uint32_t      offset;
    uint32_t      size;
    uint32_t      align;
};
