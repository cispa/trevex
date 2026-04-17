# Proof of Concepts
The PoCs are developed for Linux and tested on an Intel Xeon Gold 6346 (microcode version: 0xd0003f5) running Ubuntu 24.04.4 LTS (kernel version: 5.15.0-134).


## Running The PoCs
### Dependencies
Some of the PoCs require the [PTEditor kernel module](https://github.com/misc0110/PTEditor) to be loaded.
To download, build, and load the module execute the following commands:
```bash
git clone https://github.com/misc0110/PTEditor.git
cd PTEditor
make
sudo insmod module/pteditor.ko
```
**NOTE**: If the system is running a Linux >= 6.2.0, you need to boot the kernel with `ibt=off` as IBT support for PTEditor is work-in-progress at the time of writing.

### Build
Just run `make`.

### Execute
Execute the binary belonging to the corresponding PoC while ensuring that the victim and attacker execute on sibling hyperthreads. For example:
```bash
terminal1> taskset -c CORE1_HT1 ./dataidx-float
terminal2> taskset -c CORE1_HT2 stress -c 1 -m 1
```

A simple fence-based mitigation to the vulnerability/-ies can be applied to every PoC by uncommenting the line `#define FIX`.

## PoC: dataidx-accessbit
This PoC zeroes out an index into a structure containing both public and private data.
Due to the zeroed index, the victim transiently encodes the private string instead of the public string.
The attacker triggers this behavior by clearing the Access bit of the PTE pointing to the index of the victim data structure.

This PoC works way more stable when the hyperthread executes `stress -c 1 -m 1`

## PoC: dataidx-float
This PoC transiently computes with a wrong index into a structure containing both public and private data.
Due to the miscomputed index, the victim transiently encodes the private string instead of the public string.
The attacker triggers this behavior by executing `stress -c 1 -m 1` on the hyperthread.


## PoC: vtable
This PoC zeroes out an index to a vtable, hence transiently calling the wrong member function.
The attacker triggers this behavior by clearing the Access bit in the vtable pointer's PTE.
