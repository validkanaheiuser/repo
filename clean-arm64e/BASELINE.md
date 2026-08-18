# Clean ARM64E rebuild baseline

This branch starts from the untouched upstream package. No patch from PoC versions
1 through 41 is inherited implicitly.

## Immutable inputs

- Source package: `com.fn.rh.iOSAutomate-1.5.3-3-roothide-iphoneos-arm64e.deb`
- Source package SHA-256: `B8CE7C3F1D32A7C460ECCC78D088874A05CE027989504BCE00DAFD551C341777`
- Extracted FAT dylib SHA-256: `E7CB5A6A3D078E689A3FFF82EAC4C2D294BB748E61E7E9F46E14B2907B90E1AD`
- ARM64E slice offset in FAT: `0x2A8000`
- ARM64E slice size: `2780576` bytes (`0x2A6DA0`)
- ARM64E slice SHA-256: `D16FF9D552FFB0FAC771E201D64D33E1C7825FE9618CECC6C5CD4EB67A696A4A`
- Mach-O magic: `CF FA ED FE` (`MH_MAGIC_64`, little-endian)

The standalone `rh_main_arm64e.dylib` was byte-compared against
`rh_main.dylib[0x2A8000:]`; the result was an exact match.

## Original-byte anchors

| ARM64E vmaddr | Original bytes | Purpose |
|---:|---|---|
| `0xF1F8` | `7F2303D5 FF0302D1` | `_ws_show_toast` prologue |
| `0x166B78` | `7F2303D5 FF4301D1` | Lua C-function precall path |
| `0x166CB4` | `1F093FD6` | authenticated indirect C callback |
| `0x17CBE4` | `7F2303D5 FF8300D1` | `luaE_checkcstack` prologue |
| `0x2E4B8` | `BFC31FB8 70000014` | first Lua sleep stop branch |
| `0x2E578` | `BFC31FB8 40000014` | loop Lua sleep stop branch |

## Clean-room rules

1. ARM64 is comparison/reference only. Shipping patches target ARM64E for the A12 device.
2. Every patch requires original bytes, IDA control-flow evidence, and one observed failure.
3. One independently testable behavior change per package version.
4. Do not reuse old offsets without re-deriving them from this clean database.
5. Do not globally disable toast, alter Lua GC, change stack thresholds, or serialize queues
   unless a new trace from this baseline proves that exact intervention is required.
6. Preserve the source package and extracted baseline files unchanged.

## First experiment

Build an observation-only baseline package from the original payload. The initial package
must preserve the original ARM64E code bytes. Any minimum compatibility/license changes
must be separately enumerated and justified before they are introduced.
