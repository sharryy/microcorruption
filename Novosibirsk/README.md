# Microcorruption — Novosibirsk

`main()` reads a username into `0x2400` via `getsn` (up to `0x1f4` = 500 bytes),
then `strcpy`s it onto the stack, then passes it to `printf` as the **format
string** — the classic format-string vulnerability:

```
printf(username);   // not printf("%s", username)
```

Confirming the bug: sending `ZZ%x%x%x%x` echoes back my own input bytes
(`5a5a`, `2578` = the literal `%x`) as leaked stack "arguments", which proves
(a) the format string is attacker-controlled and (b) my input buffer sits in the
argument-read region at a low offset.

Unlock path: there is **no `unlock_door()` function** to jump to. The check +
unlock is handled by **HSM-2** (`INT 0x7E`), which is sealed — no verdict flag in
my memory to corrupt. The unconditional unlock is `INT 0x7F` (no password), so
the goal becomes: get execution to trigger `INT 0x7F` myself.

## The constraints (this is what made it hard)

I dumped the `printf` implementation and confirmed, at the source level, a brutal
stack of restrictions on the `%n` write primitive:

- **`%n` writes a full 2-byte word**, and the value written is the running
  character count.
- **No width padding.** `%16x` prints `6x` literally — the width field isn't
  parsed. So I can't inflate the count with `%<N>x`.
- **No `%hhn` / `%hn`** (no length modifiers parsed). So no byte-granular writes.
- **Word writes must be even-aligned** — writing to an odd address traps
  ("insn address unaligned").
- **Count is capped by input length (~500).** With no width padding, the count
  comes almost entirely from *literal characters printed*, bounded by the
  500-byte buffer.

Consequence: to redirect execution into my shellcode at `0x2400`, I'd need to
write the value `0x2400` (= 9216) somewhere — but the count can only reach ~500.
Writing 9216 in one word write is impossible, and I can't byte-split it (no
`%hhn`), and I can't stagger word-writes onto odd addresses (unaligned). Dead end
via the obvious routes.

## The key realization

The count can't reach `0x2400`, **but it *can* reach a small address.** So
instead of writing the address I want, I looked for a small, reachable address
that would **forward** execution to where my payload already lives.

At `0x0010` there's `__trap_interrupt`, which is just a bare `ret`:

```
0010:  3041   ret
```

That's a **ret gadget / trampoline**. If I make the return address `0x0010`, the
`ret` there fires immediately and pops the *next* value off the stack into `pc` —
so it forwards execution one slot further down. And my `strcpy`'d payload sits at
`0x420c`, right where that second `ret` lands.

The `printf` return-address slot is at `0x4208`, which is why my first planted
bytes are `0x4208` (little-endian `0842`) — that's the `%n` target.

## The exploit

**Payload:**

```
0842 7e40 7fff 0e12 b012 3645 5a5a 5a5a 256e
```

Breakdown:

- `0842` → `0x4208`, the `%n` write target (the `printf` return slot). Also — by
  luck — these bytes double as my first executed instruction (see note below).
- `7e40 7fff 0e12 b012 3645` → the unlock shellcode: set up `r14 = 0x7f`, push it,
  `call INT` → fires `INT 0x7F` → deadbolt opens.
- `5a5a 5a5a` → filler, to make the character count come out to `0x0010` (16)
  before `%n`.
- `256e` → `%n`, writes the count (`0x0010`) to `0x4208`.

**Chain:**

1. `%n` writes `0x0010` into the `printf` return slot at `0x4208`.
2. `printf`/caller returns → `pc = 0x0010` (`__trap_interrupt`).
3. `__trap_interrupt` is a bare `ret` → pops the next stack value → `0x420c`.
4. `0x420c` is where my `strcpy`'d payload lives → execution runs my bytes as
   code → shellcode fires `INT 0x7F` → **unlocked.**

So it's a **two-hop ret chain** (`printf` ret → `__trap_interrupt` ret → my
buffer), i.e. a ret-trampoline into `strcpy`'d shellcode. I never needed to write
`0x2400` — the `strcpy` destination `0x420c` *was* the landing zone, handed to me
by the stack layout for free.

**The lucky part (worth being honest about):** my first planted bytes `0842`
(the `%n` target address) are *forced* — but when executed as an instruction they
happen to be inert (`mov sr, r8`-ish), so execution flows harmlessly past them
into the real shellcode. If those bytes had decoded to something that crashed or
diverted, I'd have needed to restructure the payload (e.g. jump over the address
bytes, or place shellcode elsewhere) and probably fall back to a null-free
deadbolt-trigger payload.

---

## Other approaches (there are many ways in)

The interesting thing about Novosibirsk is how *many* distinct solutions exist —
each attacking a different surface. Reading these after solving it myself was the
most valuable part. Categorized by *what they attack*:

**Rewrite an instruction operand.** Use `%n` to write `0x7f` over the pushed
`push #0x7e` (HSM-2, conditional) at `0x44c8`, turning it into `push #0x7f`
(unconditional unlock). Needs count = 127, padded with 127 literal chars. The
canonical / simplest solution.
- jiva: https://jiva.io/blog/microcorruption-ctf-writeup-novosibirsk
- jaimelightfoot (as the 131-byte version): https://jaimelightfoot.com/blog/microcorruption-embedded-security-ctf-novosibirsk/

**`%s` count-inflation.** Same target, but instead of 127 literal chars, point
`%s` at a ~127-byte nonzero region already in memory. `%s` prints those bytes for
free, inflating the count without supplying them. The elegant answer to "no width
padding." (8-byte solution in jaimelightfoot's writeup.)
- https://jaimelightfoot.com/blog/microcorruption-embedded-security-ctf-novosibirsk/

**Cancel an instruction + stack-shift.** Overwrite one `push` in `putchar` with a
tiny count so it becomes a nop; the missing push shifts the stack so a trailing
`7f` byte lands exactly where the next interrupt reads its type → `INT 0x7F`.
Needs almost no count at all (5-byte solution).
- jaimelightfoot (5-byte): https://jaimelightfoot.com/blog/microcorruption-embedded-security-ctf-novosibirsk/

**Stack-desync via corrupting `decd sp`.** Nop out `decd sp` in
`conditional_unlock_door` so its stack bookkeeping breaks; the function re-loops
and its own `ret`s drift onto the attacker's shellcode. Cousin of my approach
(both are ret + stack manipulation), but he desyncs the frame where I used a
trampoline gadget.
- Ilyar (int3rsys): https://int3rsys.medium.com/microcorruption-novosibirsk-an-elegant-solution-123fce4361b2

**Borrow existing binary code for null-free shellcode.** Because `strcpy` zeroes
bytes, the payload can't contain `0x00`, so `mov #0x7f00, r15` (has a null) is out.
Instead, reuse instruction bytes already present in the binary and build `0x7f`
via arithmetic (`add r4, r15` from null-free pieces) — a bridge toward ROP.
- ciz: https://github.com/ciz/microcorruption

**Corrupt control flow so execution drifts into the input buffer** (12-byte),
which is close in spirit to my approach but lands semi-luckily rather than via a
deliberate trampoline.
- jaimelightfoot (12-byte): https://jaimelightfoot.com/blog/microcorruption-embedded-security-ctf-novosibirsk/

Other solution repos:
- SimchaTeich: https://github.com/SimchaTeich/Microcorruption/tree/main/12%20-%20Novosibirsk
- dagnir: https://github.com/dagnir/microcorruption/tree/master/novosibirsk

---
