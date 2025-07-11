# crypti

Copyright (C) 2025 Jacob Farnsworth

This is a command-line tool which is specially designed to defeat compile-time xor string encryption (xorstr) in Windows binaries. crypti defeats most implementations of xorstr which end up being inlined and loop-unrolled by the MSVC optimizer.

## Usage

crypti accepts a binary to analyze as the first command-line argument. The behavior can be customized with optional command-line arguments:

```
  -l, --log-level <VERBOSITY>     Verbosity (0=errors, 1=errors+warnings, 2=debug) [default: 1]
  -f, --function-block <ADDRESS>  Analyze a function at this address (absolute virtual)
  -b, --basic-block <ADDRESS>     Analyze a basic block at this address (absolute virtual)
  -h, --help                      Print help
```

## Analysis

crypti works by first performing a control-flow analysis according to the following steps:

- First instruction decoding pass. All instructions are decoded, starting linearly from the beginning of the first code segment.
- Potential functions are identified by looking at targets of call instructions.
- "Bad functions", aka functions where decoding failed (in most cases due to misalignment), are identified.
- Second instruction decoding pass. Decodings of bad functions are corrected.
- Basic block analysis. For each function block, basic blocks are identified and used to determine starting and ending points of the function.

For each basic block, a rough emulation is performed using a temporary memory. Whenever a nontrivial xor or SSE xor (xorps, xorpd) instruction is encountered, the result is recorded.

crypti attempts to interpret each xor result first as UTF-8, then as UTF-16. Results without any sensible decoding are discarded. The rest are assumed to be decrypted strings.
