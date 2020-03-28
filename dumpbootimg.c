#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <errno.h>
#include <limits.h>
#include <libgen.h>
#include <inttypes.h>
#include <sys/types.h>
#include <sys/stat.h>

#include "bootimg.h"

typedef unsigned char byte;

const char *detect_hash_type(boot_img_hdr_v2 *hdr)
{
    /*
     * This isn't a sophisticated or 100% reliable method to detect the hash
     * type but it's probably good enough.
     *
     * sha256 is expected to have no zeroes in the id array
     * sha1 is expected to have zeroes in id[5], id[6] and id[7]
     * Zeroes anywhere else probably indicates neither.
     */
    #define id (hdr->id)
    if (id[0] != 0 && id[1] != 0 && id[2] != 0 && id[3] != 0 &&
        id[4] != 0 && id[5] != 0 && id[6] != 0 && id[7] != 0) {
        return "sha256";
    } else if (id[0] != 0 && id[1] != 0 && id[2] != 0 && id[3] != 0 &&
               id[4] != 0 && id[5] == 0 && id[6] == 0 && id[7] == 0) {
        return "sha1";
    } else {
        return "unknown";
    }
    #undef id
}

int usage()
{
    printf("usage: dumpbootimg\n");
    printf("\t-i|--input boot.img\n");
    printf("\t[ -p|--pagesize <size-in-hexadecimal> ]\n");
    return 0;
}

int main(int argc, char** argv)
{
    char tmp[PATH_MAX];
    char* filename = NULL;
    int pagesize = 0;
    int base = 0;

    int seeklimit = 65536; /* arbitrary byte limit to search in input file for ANDROID! magic */
    int hdr_ver_max = 4; /* arbitrary maximum header version value; when greater assume the field is appended dtb size */

    argc--;
    argv++;
    while(argc > 0){
        char *arg = argv[0];
        char *val = argv[1];
        argc -= 2;
        argv += 2;
        if(!strcmp(arg, "--input") || !strcmp(arg, "-i")) {
            filename = val;
        } else if(!strcmp(arg, "--pagesize") || !strcmp(arg, "-p")) {
            pagesize = strtoul(val, 0, 16);
        } else {
            return usage();
        }
    }

    if (filename == NULL) {
        return usage();
    }

    int total_read = 0;
    FILE* f = fopen(filename, "rb");
    boot_img_hdr_v2 header;

    if (!f) {
        printf("Could not open input file: %s\n", strerror(errno));
        return (1);
    }

    //printf("Reading header...\n");
    int i;
    for (i = 0; i <= seeklimit; i++) {
        fseek(f, i, SEEK_SET);
        if(fread(tmp, BOOT_MAGIC_SIZE, 1, f)){};
        if (memcmp(tmp, BOOT_MAGIC, BOOT_MAGIC_SIZE) == 0) {
            break;
        }
    }
    total_read = i;
    if (i > seeklimit) {
        printf("Android boot magic not found.\n");
        return 1;
    }
    fseek(f, i, SEEK_SET);
    if (i > 0) {
        printf("Android magic found at: %d\n", i);
    }

    if(fread(&header, sizeof(header), 1, f)){};
    base = header.kernel_addr - 0x00008000;

    if (header.dt_size > hdr_ver_max) {
        printf("BOARD_DT_SIZE %d\n", header.dt_size);
    } else {
        printf("header_version=%d\n", header.header_version);
    }

    int a=0, b=0, c=0, y=0, m=0;
    if (header.os_version != 0) {
        int os_version,os_patch_level;
        os_version = header.os_version >> 11;
        os_patch_level = header.os_version&0x7ff;

        a = (os_version >> 14)&0x7f;
        b = (os_version >> 7)&0x7f;
        c = os_version&0x7f;

        y = (os_patch_level >> 4) + 2000;
        m = os_patch_level&0xf;

        if((a < 128) && (b < 128) && (c < 128) && (y >= 2000) && (y < 2128) && (m > 0) && (m <= 12)) {
            printf("os_version=%d.%d.%d\n", a, b, c);
            printf("os_patch_level=%d-%02d\n", y, m);
        } else {
            header.os_version = 0;
        }
    }

    printf("board=%s\n", header.name);
    printf("pagesize=%d\n", header.page_size);
    printf("cmdline=%.*s%.*s\n", BOOT_ARGS_SIZE, header.cmdline, BOOT_EXTRA_ARGS_SIZE, header.extra_cmdline);
    printf("base=0x%08x\n", base);
    printf("kernel_offset=0x%08x\n", header.kernel_addr - base);
    printf("ramdisk_offset=0x%08x\n", header.ramdisk_addr - base);
    printf("second_offset=0x%08x\n", header.second_addr - base);
    printf("tags_offset=0x%08x\n", header.tags_addr - base);
    printf("hash=%s\n", detect_hash_type(&header));

    if (header.header_version <= hdr_ver_max) {
        if (header.header_version > 0) {
            if (header.recovery_dtbo_size != 0) {
                printf("BOARD_RECOVERY_DTBO_SIZE %d\n", header.recovery_dtbo_size);
                printf("BOARD_RECOVERY_DTBO_OFFSET %"PRId64"\n", header.recovery_dtbo_offset);
            }
            //printf("BOARD_HEADER_SIZE %d\n", header.header_size);
        } else {
            header.recovery_dtbo_size = 0;
        }
        if (header.header_version > 1) {
            if (header.dtb_size != 0) {
                printf("BOARD_DTB_SIZE %d\n", header.dtb_size);
                printf("BOARD_DTB_OFFSET %08"PRIx64"\n", header.dtb_addr - base);
            }
        } else {
            header.dtb_size = 0;
        }
    }

    fclose(f);

    return 0;
}
