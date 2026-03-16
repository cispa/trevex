# Trevex - The Transient Execution Vulnerability Explorer

More coming soon.

## Found / Reproduced Vulnerabilities

### PoCs
In `./pocs`, you can find PoCs for some of the discovered issues.

#### FP-DSS
The folder `./pocs/amd-fpdss` contains our PoC for Floating-Point Divider State Sampling (FP-DSS).
FP-DSS is a transient execution attack leaking state from SSE and AVX floating point division units.
It is tracked as CVE-2025-54505 and discussed by AMD as a [Security Notice](TODO).
It affects AMD Zen 1 and Zen+ CPUs.

