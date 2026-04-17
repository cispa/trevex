# LVI-NULL on Unaffected

## Tested Machine
- Intel Core i3-1005G1
- microcode: 0xca

## Setup
The PoC requires [PTEditor](https://github.com/misc0110/PTEditor).
Thus, follow these steps:
- Clone PTeditor: `git clone https://github.com/misc0110/PTEditor`
- Switch into repo: `cd ./PTEditor/module`
- Build the module: `make`
- Load the module: `insmod pteditor.ko`


## The PoC
### General
The PoC is a slightly modified version of the [PoC by Giner et. al.](https://github.com/isec-tugraz/LVI-NULLify).
3
The PoC works as follows:
- The host app maps the nullpage and writes a function pointer to `oraculate` to it.
- The host ecalls into the enclave.
- The enclave calls `b->bar(oracle,LEAKAGE_CHAR)`.
- The address of `b` is transiently zeroed.
- Thus, the enclave transiently calls into the function pointer previously written to the nullpage.
- The `oraculate` function accesses an array at position `LEAKAGE_CHAR`.
- The the enclave ocalls the host.
- The host checks whether the index `LEAKAGE_CHAR` of said array is cached.

### Execution
- Switch into PoC: `cd giner_null_redirect_enclave`
- Compile it: `make -B`
- Run it: `sudo setarch x86_64 -Z ./app`

### Expected Result
You should see a result looking similar to this:
```
total: 100000
transient t: 99966 (99.97%)
other: 0 (0.00%)
```
The line starting with "transient t:" shows how often the PoC succeded, i.e., managed to redirect the enclaves control flow.
