# Trevex - The Transient Execution Vulnerability Explorer


## Supported Platforms
We support the following environments: 

### OS / Distros
Trevex is developed and tested on Ubuntu 22.04 LTS and 24.04 LTS.
While other distros may work, some parts of the framework, e.g., the dependency checking and installation, assumes `apt` as package manager.

### Architectures
Trevex currently only targets x86.
Support for further architectures will come in the near future.

## Installation
We recommend adding the following shell alias in your dotfiles:
```bash
function tvx() {<repo-root>/tvx.py $@}
```

Next, install the framework's dependencies:
```bash
pip install -r ./requirements.txt
sudo apt-get update
sudo apt-get install build-essential cmake tmux cpuid linux-tools-common
```

## Usage
Trevex is controlled via the `tvx` command-line utility.
`tvx` follows this syntax:
```bash
tvx <command> <subcommand>
```
and supports the following commands:

### The `run` Command
The `run` is used to control local fuzzing runs:
```bash
# start the fuzzer
tvx run start

# clear the progress made and all results
tvx run cleanup
```

### The `setup` Command (will be published in the near future)
The `setup` command is used to install and load dependencies.
```bash
# install/check Trevex system dependencies (apt and python packages)
tvx setup install

# load the tvx Python environment (planned)
tvx setup load
```

Current status:
- `setup install` currently installs Trevex system dependencies.
- Python environment setup is not finished yet.

### The `result` Command
The `result` command is used to inspect and process fuzzing results:
```bash
# classify the results 
# (typically the first thing you want to do after fuzzing)
tvx result classify

# view the content of a testfile
tvx result view <result-file.json>

# export a given test file into a standalone 'reproducer'
# allows you to inspect the result further
tvx result export <result-file.json>

# rerun the testcase inside the fuzzer
tvx result rerun
```

### The `ctrl` Command (will be published in the near future)
The `ctrl` command is used to orchestrate Trevex fuzzing campaigns consistins of multiple machines.
It allows you to spawn Trevex on multiple machines and pull the results to your machine.
The set of machines is defined via a machine config file. 

#### Machine File
The machine file consist of 1 SSH config name per line.
Additionally, the format supports comment starting with `#`.
Trevex assumes that you have passwordless SSH access to these machines.
Typically, this is done by using key-based authentication and storing the keys in your local SSH agent, e.g., using `ssh-add`.

A valid config looks like this
```bash
uarch-lab01  # my server
uarch-lab03  # my dev machine 
uarch-lab07  # my other dev machine
```

#### Usage
The `ctrl` command requires you to speficy the machine file *before* the subcommand:
```bash
tvx ctrl -m <machine_file.cfg> <subcommand>
```

A typical fuzzing campaign looks as follows:
```bash

# prepare the machines for the fuzzing campaign
# ATTENTION: this might change the running kernel and reboot the machine
#   This is not always needed, you can just try skipping the step.
tvx ctrl -m ./my-servers.cfg setup

# Start Trevex on the remote machines and attach to their tmux sessions
# Note: If Trevex fails to start, the skipped setup step might be the reason.
tvx ctrl -m ./my-servers.cfg spawn

# Detach from all tmux sessions and let it run for a while
tvx ctrl -m ./my-servers.cfg detach

# Attach again to the tmux sessions
tvx ctrl -m ./my-servers.cfg attach

# Stop all Trevex instances once you're done
tvx ctrl -m ./my-servers.cfg stop

# Retrieve the results and store them on your local machine
# Note: While this is often useful for organization, actual 
#   reproduction steps should executed on the *exact same* 
#   CPU that was fuzzed.
tvx ctrl -m ./my-servers.cfg pull-results

# Reset the state on all machines. This cleans all progress
# made and deletes all results.
tvx ctrl -m ./my-servers.cfg cleanup
```

### The `dev` Command
This command is purely used for development purposes.
Hence, it also stays undocumented for now.

## Found / Reproduced Vulnerabilities

"Novel" refers to findings that are entirely new or where TREVEX uncovered additional aspects, such as new variants or instances on microarchitectures not previously known to be affected.

| Vulnerability | Status | Notes |
|----------|-----------|---------------------------------------------------------|
| FP-DSS   | **Novel** | Leaks stale data from the floating-point execution unit |
| LVI-NULL | **Novel** | Discovered on microarchs not known to be vulnerable |
| FPVI     | **Novel** | Discovered new variant and FPVI on Zhaoxin  |
| GDS (Downfall) | Reproduced | First fuzzer to detect it |
| MDS (ZombieLoad, RIDL, VRS, ...) | Reproduced | - |
| Meltdown-US | Reproduced | The "original" Meltdown vulnerability |
| Meltdown-CPL-REG | Reproduced | Requires a system with `nofsgsbase` |

### PoCs
Go to the directory `./pocs.`

#### FP-DSS
The folder `./pocs/amd-fpdss` contains our PoC for Floating-Point Divider State Sampling (FP-DSS).
FP-DSS is a transient execution attack leaking state from SSE and AVX floating point division units.
It is tracked as CVE-2025-54505 and discussed by AMD in a [Security Advisory](https://www.amd.com/en/resources/product-security/bulletin/amd-sb-7053.html).
It affects AMD Zen 1 and Zen+ CPUs.

#### FPVI Variant
The folder `./pocs/amd-fpvi-variant` contains our PoC for a variant of FPVI that does not require denormal input values.
AMD discusses the finding a [Security Advisory](https://www.amd.com/en/resources/product-security/bulletin/amd-sb-7050.html).
It affects AMD CPUs.

#### Zero-At-Ret
The folder `./pocs/intel-zero-at-ret` contains our PoC for the Zero-at-Ret variant of LVI NULL.

#### FPVI Zhaoxin
The folder `./pocs/zhaoxin-fpvi` contains our a PoC triggering FPVI behavior on Zhaoxin's LuJiaZui microarchitecture.


## Research Paper
The paper is available [here](https://d-we.me/papers/trevex_sp26.pdf). 
You can cite our work with the following BibTeX entry:
```latex
@inproceedings{Weber2026Trevex,
 author = {Weber, Daniel and Thomas, Fabian and Trampert, Leon and Zhang, Ruiyi and Schwarz, Michael},
 booktitle = {{IEEE S\&P}},
 title = {{Trevex: A Black-Box Detection Framework For Data-Flow Transient Execution Vulnerabilities}},
 year = {2026}
}
```

## Disclaimer
We are providing this code as-is.
You are responsible for protecting yourself, your property and data, and others from any risks caused by this code.
This code may cause unexpected and undesirable behavior to occur on your machine.
