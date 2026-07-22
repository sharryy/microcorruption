# Microcorruption — Lagos

This is the level where the login input is **restricted to alphanumeric
characters** (`0-9`, `A-Z`, `a-z`), and the door only opens on `INT 0x7F`. The
password path fires `INT 0x7E` (HSM-2), which needs a password I don't have.

The actual solution is two inputs and eight bytes of shellcode. It's almost
insultingly simple.

I did not find it for three days.

What I found instead was a rabbit hole so deep I built a *tool* to help me dig it,
and the tool worked so well at digging that it kept me in the hole. This writeup is
the honest version: the clean solve is at the top, and the entire graveyard of
harder-than-necessary ideas is at the bottom, because on this level the dead ends
genuinely are the story.

---

## The target

`login` (`0x455e`) does roughly this:

1. `getsn(0x2400, 0x200)` — read up to 512 raw bytes into the global buffer at
   `0x2400`.
2. A filter loop (`0x45a0–0x45c6`) copies bytes from `0x2400` onto a **16-byte
   stack buffer**, one at a time, and **stops at the first non-alphanumeric byte**.
   There's no length check on the copy, so it's a clean stack overflow — but every
   byte that lands has to be alphanumeric.
3. `memset(0x2400, 0, 0x200)` — wipes the raw input buffer. (Remember this one. It
   killed an entire idea.)
4. `conditional_unlock_door` → `INT 0x7E` (HSM-2). Unlocks only for the correct
   password, which I don't have, and there's no verdict flag sitting in memory to
   corrupt (that was HSM-1's thing).
5. `ret`.

The door opens on `INT 0x7F`, delivered by the little trampoline at `0x45fc`. It
takes a number, folds it into the status register, and pokes the gate:

```
45fc: mov 0x2(sp), r14      ; N = number from the stack
4602: mov r14, r15
4604: swpb r15              ; N -> high byte
4606: mov r15, sr           ; sr = N << 8
4608: bis #0x8000, sr       ; sr = 0x8000 | (N << 8)
460c: call #0x10            ; PC = 0x10 with sr set -> emulator fires the interrupt
```

The interrupt number is `(sr >> 8) & 0x7f`, and bit 15 is the "please actually do
it" request flag. So `INT 0x7F` means **`sr = 0xff00`**. That's the whole target:
get `sr = 0xff00`, then hit the gate.

---

## The bug that actually matters

The overflow lets me overwrite `login`'s saved return address — but only with
**alphanumeric** bytes. And the instructions that unlock (`swpb`, `bis`, `call`,
anything with `0x7f`/`0xff`/`0x00` in it) are not alphanumeric-encodable. That
single fact is what ate three days.

The real weakness is dumber than any of that: **the filter only guards the copy to
the stack. `getsn` itself does not filter anything.** So if I can make the program
call `getsn` a *second* time, that read takes **arbitrary bytes** — including a
perfectly clean `mov #0xff00, sr ; call #0x10`.

`getsn` (`0x4650`) sets up its own arguments and fires:

```
4650: push r14        ; length
4652: push r15        ; buffer
4654: push #0x2       ; INT number 2 = read input
4656: call #0x45fc    ; go
465a: add #0x6, sp
465e: ret
```

If I return to **`0x4654`** instead of `0x4650`, I skip the two `push`es. That means
the buffer address and length the interrupt reads come from **my overflowed stack**,
which I control. I pick where the unfiltered second input lands, and I pick where
`getsn`'s trailing `ret` sends control afterward.

That's the entire level. The alphanumeric constraint was never a property of the
program — just of one code path.

---

## The exploit

### First input (all alphanumeric)

```
61  6161 6161 6161 6161 6161 6161 6161 6161  5446  3044 3044 3044 3044 3044
```

| bytes             | value    | role |
|-------------------|----------|------|
| `61` × 17 (`a`)   | padding  | fills the buffer up to the saved return address (the lone leading `61` is there to eat the filter's duplicate-first-byte quirk) |
| `54 46`           | `0x4654` | new return address → re-enter `getsn` past its pushes = the unfiltered second read |
| `30 44` × 5       | `0x4430` | sprayed 5× so it lands in **both** slots that matter — `getsn`'s **buffer** arg (second input writes to `0x4430`) **and** the word its `ret` pops → `PC = 0x4430` — without pinning exact offsets |

Flow: `login` returns to `0x4654` → `getsn` reads a second input straight to
`0x4430` → its tail `add #0x6, sp ; ret` pops `0x4430` → we jump into the bytes we
just wrote.

`0x4430` is just a spot in code I can name with alphanumeric bytes and that's safe
to clobber. Repeating it five times is deliberate **spray**: instead of computing
the exact offset of the buffer arg vs. the return slot and trying to land each one
precisely, I splatter `0x4430` across five words so it's already sitting in whichever
slot gets used. Spraying the value across the landing zone brute-forces the placement
in one shot — no per-offset arithmetic, no second attempt. (I didn't compute where
the second input lands either; I ran it, watched the debugger, and pointed the return
there. Observation beats prediction when you have a single-stepper.)

### Second input (unfiltered — anything goes)

```
32 40 00 ff   b0 12 10 00
```

| bytes         | instruction        | effect |
|---------------|--------------------|--------|
| `32 40 00 ff` | `mov #0xff00, sr`  | `sr = 0xff00`: bit 15 = request, bits 8–14 = `0x7f` |
| `b0 12 10 00` | `call #0x10`       | hit the gate with `sr` already set → **INT 0x7F → unlock** |

Every wall I spent three days hitting was a wall around *reusing the trampoline*.
The moment I could write raw bytes, I didn't need the trampoline at all.

---

## The three days I'm not proud of

Before the second-`getsn` idea, I was completely locked onto solving it with
**alphanumeric shellcode only** — never getting an unfiltered write, just building
the unlock out of typeable bytes in a single input. Every one of these was a real,
plausible-looking path. Every one hit a wall the reasoning could've predicted if
I'd stepped back.

**And here's the trap:** early on I realized alphanumeric shellcode is brutal to
hand-write, so I built a tool to enumerate which MSP430 instructions and immediates
are even encodable under an alphanumeric byte set, plus a searcher that finds
`add`-chains to construct target values (`0x7f`, `0xff00`, `0x10`) in a register
from legal constants.

The tool was great. That was the problem. It made the hard path *feel* tractable —
every day it'd hand me a fresh set of legal gadgets and I'd think "okay *this*
combination will do it," and I'd grind another attempt instead of questioning
whether the whole approach was necessary. A worse tool would've made me give up on
alphanumeric-only sooner and go looking for the easy door. Instead I had a
beautifully engineered shovel and used it to dig for three days.

> The tool (separate repo, appropriately named): **AGI** — it filters MSP430
> opcodes. [link](https://github.com/sharryy/agi)

### What's encodable, and what's dead

Everything below fights the same instruction-format fact. A double-operand MSP430
instruction is one 16-bit word:

```
 15    12 11    8  7    6    5   4  3    0
+--------+-------+----+----+------+------+
| opcode |  src  | Ad | BW |  As  | dst  |
+--------+-------+----+----+------+------+
```

For `op #imm, rD` (immediate source, register dest) the word splits into two
independent bytes:

- **high byte = `opcode << 4`** → which *operation* is legal
- **low byte = `0x30 | dst`** (As=3, Ad=0) → which *register* is legal

**Dead ops.** The high byte must be alphanumeric and almost none are: only `add`
(`0x50` = `'P'`) survives — `mov` (`0x40`), `sub` (`0x80`), `xor` (`0xE0`), `and`
(`0xF0`), `bis`/`bic` (`0xD0`/`0xC0`) are all out. Every single-operand op (`push`,
`call`, `swpb`, …) is Format II with a `0x10-0x13` high byte — dead too. So the only
arithmetic I get is `add #imm`.

**Dead registers.** `0x30 | dst` gives `0x31`–`0x39` for `r1`–`r9` (fine), but
`r10`–`r15` give `0x3a`–`0x3f` = `:;<=>?` — not alphanumeric. Only `r1`–`r9`.

**Writing to memory is dead.** A memory destination needs `Ad = 1`, and that bit is
bit 7 of the low byte — so the low byte goes `≥ 0x80`, past the alphanumeric ceiling
`0x7a`, every time. No store encodes. With `push` also dead, a value I compute in a
register can never reach memory. That one fact kills half the attempts below.

**`mov.b` works but is lossy.** Byte-mode register moves encode, but byte mode zeroes
the destination's high byte — I can move a low byte, never assemble a full 16-bit
value like `0xff00`.

**`sr` is writable but radioactive.** `sr` is `r2`, so `add #imm, sr` encodes (`0x32`
= `'2'`). But it's the status register, and bit 4 is **CPUOFF** — set it and the
emulator halts instantly. Since `add` can't reach `0xff00` in one legal step, I have
to build it across several `add`s with *every intermediate value* keeping CPUOFF
clear. So one approach builds the value in a scratch register (`r4`/`r5`) step by
step — keeping each intermediate's low byte `0x00`, or at least CPUOFF off — and only
then tries to move it into `sr` (where the `mov.b` and no-store walls finish it off).

Here's the graveyard, each attempt tied to the wall it hit.

### Attempt A — build the number in a register, then pivot SP toward `0x2400`

Idea: build `0x7f` in a register, move the stack pointer down to the raw input
buffer at `0x2400`, and run unrestricted shellcode I'd parked there.

```
61 6161 ... 4644 6162 6666 ... 3450 3130 3450 5a50 3450 7a4f 3450 7a30 6666 ... 3150 304a 3150 564a 3150 7a4b
```

- `add #0x3031,r4; add #0x505a,r4; add #0x4f7a,r4; add #0x307a,r4` → `r4 = 0x7f`
- `mov.b r4, r14` / `mov.b r4, r11` → number in a register
- `add #0x4a30,sp; add #0x4a56,sp; add #0x4b7a,sp` → `sp -= 0x2000` (`0x4400 → 0x2400`)

**Wall:** `0x2400` is exactly the buffer `memset` zeroes at step 3, before I ever
get control. My parked shellcode was gone before execution reached it. (This is the
"remember this one" from way up top.)

### Attempt B — build SR with add-chains, jump through a *found* trampoline pointer

Idea: build `0xff00` in `sr` by hand with three `add`s, then transfer control to
the trampoline.

The interesting sub-problem here is the control transfer. I can't `mov #0x45fc, pc`
— `mov`-into-`pc` (dst = r0) in register mode forces the low byte to `0x00`, illegal,
and `mov #imm, pc` embeds the address `0x45fc` whose byte `0xfc` is illegal too. So
I can't *name* the address I want to jump to at all.

The way around it: **I don't type the address, I point at a copy of it that already
exists in memory.** This is where the tool actually earned its keep — I had it
enumerate legal instructions and it surfaced that `mov @r5+, pc` (indirect jump
through a register) *is* alphanumeric-encodable. So the plan became: find some word
in the image that already equals the address I want, get *that word's address* into
a register (legal, because I picked a pointer whose address is typeable), and jump
through it with `mov @rX+, pc`. The illegal target address never appears in my
input — it's read out of memory at runtime.

I scanned memory, found a word holding `0x45fc` at an alphanumeric-addressable
location, and:

```
61 6161 ... 4644 6162 6666 ... 3750 5846 3250 4155 3250 4155 3250 4155 3047 3041
```

- `add #0x4658, r7` → `r7` = address of a word that contains `0x45fc`
- `add #0x5541, sr` × 3 → `sr` high byte climbs `0x55 → 0xaa → 0xff`
- `mov @r7+, pc` → reads `0x45fc` out of memory and jumps there — no illegal byte
  ever typed

(Caveat I learned the hard way: this only works because a word holding `0x45fc`
*happened* to sit at a typeable address. I got lucky. You can't manufacture such a
pointer — you're at the mercy of what's already in the image, so this is a scan,
not a construction.)

**Wall:** entering the trampoline at `0x45fc` re-runs `mov 0x2(sp), r14 ; ... ; mov
r15, sr` — which **overwrites the `sr` I just carefully built** with whatever
`2(sp)` swpb's to. I built the answer and then the trampoline erased it on the way
in. To skip the overwrite I'd need to enter at `0x4608`/`0x460c` (past the `mov
r15, sr`), and those addresses have illegal bytes (`0x08`, `0x0c`) — and unlike
`0x45fc`, no word in memory happened to hold *those* values at a typeable address,
so the found-pointer trick couldn't rescue it either.

### Attempt C — flip the pushed `0x7e` to `0x7f` in place

Idea: I'm overwriting code anyway, so overwrite `conditional_unlock_door`'s `push
#0x7e` (`0x445c`) so it pushes `0x7f` instead, then let the existing trampoline
fire it.

**Wall:** `0x7f` is not an alphanumeric byte, so I can't type it into the operand.
And the operand isn't reachable by arithmetic-at-runtime either without a
memory-write instruction — which brings us to:

### Attempt D — just write `0x7f` to the stack slot the trampoline reads

Idea: forget building `sr`; the trampoline reads `2(sp)`, so put `0x007f` there.

**Wall:** there is **no legal way to write memory at all.** `push` is Format II →
opcode byte `0x12` → illegal. A two-operand `mov`/`add`/`xor` with an *indexed
destination* sets the Ad bit (bit 7 of the low byte) → pushes the byte to `0x80`+
→ illegal, for *every* opcode. So no store, no push, nothing puts a computed value
into memory. `0x7f` can be built in a register and can never leave it.

This one is the cleanest proof of why the whole single-input approach is doomed:
the number has to reach either the stack (can't write memory) or `sr` via the
trampoline (which overwrites it) or `sr` directly (can't jump to the gate). Every
road out is blocked. The constraint isn't "hard," it's closed.

### Attempt E — point `2(sp)` at an existing `0x7f`/`0xff` byte

Idea: if I can't *write* `0x7f`, maybe one already exists in the image and I can
slide `sp` so `2(sp)` lands on it.

**Wall:** the emulator enforces word-aligned reads, and every `0xff` in the binary
is the high byte of some `0xffXX` immediate → it sits at an **odd** address. There
is no even-aligned `0x7f` or `0xff` byte to point at. Also I couldn't move `sp` to
an arbitrary spot precisely anyway (the `add`-to-`sp` gadgets are coarse).

---

## What actually unstuck it

All five of those die for the same underlying reason: I was trying to **defeat the
alphanumeric filter** — smuggle an illegal value past it, or reconstruct the unlock
out of legal pieces. And the filter is genuinely, provably airtight against that on
a single input.

The fix wasn't to beat the filter. It was to notice the filter only runs **once**,
on the first read, and then go get a **second** read through a path (`getsn`) that
never filtered anything. Write real shellcode into the second input, let an
existing `ret` deliver control to it, done.

The tool would never have found that, because the tool was built to answer "what
can I do within the constraint" — and the answer was "stop being inside the
constraint."

---

## Lessons (the transferable bits)

- **A good tool can keep you in a bad approach** just by always having another option to try — mine handed me a fresh set of legal gadgets every day, so I never stopped to question whether the whole approach was the problem.

Most writeups for this level dance with the stack, `r14`, `push` chains, and
re-deriving the trampoline's argument. You don't need any of it: `mov #0xff00, sr ;
call #0x10` bakes the entire interrupt into two instructions and you move on — no
push, no stack arithmetic, no trampoline.