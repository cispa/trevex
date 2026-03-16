# Floating Point Divider-State Sampling

## General
The code contains an attacker implementation (`attacker.c`), a userspace victim application in `victim.c`, and a kernelspace victim application in `victim-kmod/dss-victim.c`.
The code was tested on:
- AMD Ryzen 5 2500U (microcode 0x810100b) running Ubuntu 24.04.1 LTS with kernel 6.1.0
- AMD Ryzen 5 3550H (microcode 0x8108102) running Ubuntu 22.04.1 LTS with kernel 5.15.0

We assume the existance of two hardware threads on the same CPU core called HT1 and HT2.

## Experiment 1 - SSE Cross-Process Leakage
- make sure that in `attacker.c` the macro `EXPLOIT_SSE_DIVIDER` is set while the macros `EXPLOIT_AVX_DIVIDER` and `VICTIM_KERNEL` are commented out.
- Compile the code: `make`
- start the attacker on HT1: `taskset -c <HT1> ./attacker>`
- in a second terminal: start the victim on HT2 and give it a secret to encode: `taskset -c <HT2> ./victim A`
- the attacker code should now print the leakage.

## Experiment 2 - AVX Cross-Process Leakage
- make sure that in `attacker.c` the macro `EXPLOIT_AVX_DIVIDER` is set while the macros `EXPLOIT_SSE_DIVIDER` and `VICTIM_KERNEL` are commented out.
- Compile the code: `make`
- start the attacker on HT1: `taskset -c <HT1> ./attacker>`
- in a second terminal: start the victim on HT2 and give it a secret to encode: `taskset -c <HT2> ./victim A`
- the attacker code should now print the leakage.

## Experiment 3 - SSE Kernel Leakage
- make sure that in `attacker.c` the macro `EXPLOIT_SSE_DIVIDER` and `VICTIM_KERNEL` are set while the macro `EXPLOIT_SSE_DIVIDER` is commented out.
- Compile the code: `make`
- Compile the victim kernel module: `cd ./victim-kmod; make`
- Load the victim kernel module: `sudo insmod ./victim-kmod/dss-victim.ko`
- start the attacker on HT1: `taskset -c <HT1> ./attacker>`
- the attacker code should now print the leakage from the divisions inside the kernel module.
- Note that after the `ioctl` call to the kernel module, the attacker calls `amd_clear_divider()`, the function implementing the Linux kernel's mitigation for DSS (CVE-2023-20588).