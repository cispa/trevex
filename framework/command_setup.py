import platform
import re

from framework.common import *

TIMEOUT_UPDATE = 30

def install_trevex_dependencies():
    # install the fuzzer dependencies
    trevex_apt_dependencies = [
        "build-essential",
        "cmake",
        "tmux",
        "cpuid",
        "linux-tools-common",
    ]
    err, _, _ = run_cmd("sudo apt-get update", timeout=TIMEOUT_UPDATE)
    if err != 0:
        log_warning("Failed to update package lists")

    err, _, _ = run_cmd("sudo apt-get install -y " + " ".join(trevex_apt_dependencies))
    if err != 0:
        raise RuntimeError("Failed to check/install dependencies")


def install_tvx_dependencies():
    # TODO: install dependencies for the Python framework into the venv
    raise NotImplementedError()


def is_kernel_atleast(major, minor, patch):
    release = platform.release()
    m = re.match(r"^(\d+)\.(\d+)\.(\d+)", release)
    if not m:
        raise ValueError(f"Could not parse kernel release: {release}")

    curr_major, curr_minor, curr_patch = map(int, m.groups())
    return (curr_major, curr_minor, curr_patch) >= (major, minor, patch)

    
def is_kernel_ibt_disabled():
    with open("/proc/cmdline", "r") as fd:
        cmdline = fd.read()
    return "ibt=off" in cmdline


def build_and_load_pteditor():
    if is_kernel_atleast(6, 2, 0):
        if not is_kernel_ibt_disabled():
            log_error("Kernel >= 6.2.0 requires 'ibt=off' to enable PTEditor.")
            log_error("Please add 'ibt=off' to your kernel cmdline and reboot.")
            exit(1)

    build_dir = TREVEX_ROOT / "src" / "external" / "PTEditor" / "module"
    log_verbose(f"Building PTEditor in {build_dir}")
    if not build_dir.exists():
        raise RuntimeError(f"PTEditor build directory does not exist: {build_dir}")
    err, _, _ = run_cmd("make -j", working_dir=build_dir)
    if err != 0:
        raise RuntimeError("Failed to build PTEditor")

    # unload the module in case it's already loaded
    run_cmd("sudo rmmod pteditor", working_dir=build_dir)

    err, _, _ = run_cmd("sudo insmod pteditor.ko", working_dir=build_dir)
    if err != 0:
        raise RuntimeError("Failed to load PTEditor module")


def get_trevex_cmake_arch():
    vendor = get_cpu_vendor()
    if vendor == CPUVendor.Intel:
        return "INTEL"
    elif vendor == CPUVendor.Amd:
        if is_zen_1_cpu():
            # we do this as they don't support RDPRU
            log_info("Zen and Zen+ CPUs are threated as Intel CPUs")
            return "INTEL"
        return "AMD"
    elif vendor == CPUVendor.Zhaoxin:
        return "ZHAOXIN"
    else:
        raise RuntimeError(f"CMake arch unknown: {vendor}")

    
def build_trevex():
    build_dir = TREVEX_BUILD_DIR
    if not build_dir.exists():
        build_dir.mkdir(parents=True)
    arch = get_trevex_cmake_arch()
    log_info(f"Choosing architecture '{arch}'")
    log_verbose(f"Building trevex in {build_dir}")
    p_err, p_stdout, p_stderr = run_cmd(f"cmake -DARCH={arch} ..", working_dir=build_dir)
    if p_err != 0:
        raise RuntimeError(f"Trevex CMake failed: {p_stdout}\n{p_stderr}")
    p_err, p_stdout, p_stderr = run_cmd("make -j", working_dir=build_dir)
    if p_err != 0:
        raise RuntimeError(f"Trevex Make failed: {p_stdout}\n{p_stderr}")
    if in_verbose_mode():
        print(f"Trevex build output:\n{p_stdout}\n{p_stderr}")

    
def disable_hardware_prefetchers_intel():
    p_err, _, _ = run_cmd("sudo wrmsr -a 0x1a4 15")
    if p_err != 0:
        # not all Intel CPUs support 15, fallback is 5
        p_err, _, _ = run_cmd("sudo wrmsr -a 0x1a4 5")
        return p_err == 0
    return True


def set_bitmask_in_msr(msr_addr, bitmask_to_set):    
    p_err, p_stdout, _ = run_cmd(f"sudo rdmsr {msr_addr}")
    if p_err != 0:
        return False
    old_val = int(p_stdout.strip(), 16)
    new_val = old_val | bitmask_to_set
    p_err, _, _ = run_cmd(f"sudo wrmsr {msr_addr} {new_val:x}")
    return p_err == 0


def disable_hardware_prefetchers_amd():
    ret = set_bitmask_in_msr(0xc0011022, 0xa000)
    if ret is False:
        return False
    ret = set_bitmask_in_msr(0xc001102b, 0x70008)
    if ret is False:
        return False

    # Zen 4 prefetchers; we don't care if they fail
    run_cmd("sudo wrmsr -a 0xc0000108 0x2f")

    return True


def drop_runlevel():
    p_err, p_stdout, p_stderr = run_cmd("runlevel")
    if p_err != 0:
        return False
    try:
        current_runlevel = p_stdout.strip().split()[1]
    except (IndexError, ValueError):
        return False

    if current_runlevel == "3":
        log_verbose("Already in runlevel 3")
        return True
    p_err, _, _ = run_cmd("timeout 10 sudo init 3")
    return p_err == 0


def fix_cpu_frequency():
    p_err, _, _ = run_cmd("echo performance | " \
        "sudo tee /sys/devices/system/cpu/cpu*/cpufreq/scaling_governor")
    if p_err != 0:
        log_verbose("Failed to use scaling_governor interface. " \
            "Falling back to cpupower interface.") 
        p_err, _, _ = run_cmd("sudo cpupower frequency-set -g performance")
        return p_err == 0 
    return True


def enable_hugepages():
    p_err, _, _ = run_cmd("sudo sysctl -w vm.nr_hugepages=1000")
    return p_err == 0


def disable_aslr():
    p_err, _, _ = run_cmd("echo 0 | sudo tee /proc/sys/kernel/randomize_va_space")
    return p_err == 0

    
def prepare_system_for_fuzzing():
    cpu_vendor = get_cpu_vendor()
    if cpu_vendor == CPUVendor.Intel:
        success = disable_hardware_prefetchers_intel()
    elif cpu_vendor == CPUVendor.Amd:
        success = disable_hardware_prefetchers_amd()
    elif cpu_vendor == CPUVendor.Zhaoxin:
        success = False
        log_warning("Hardware prefetcher disabling not implemented " \
            "for Zhaoxin CPUs. skipping.")
    else:
        success = False
        log_warning("Unknown CPU vendor. Skipping hardware prefetcher disabling.")
    
    if not success:
        log_warning("Failed to disable hardware prefetchers")
        
    # minimize noise for more efficient measurements
    success = drop_runlevel()
    if not success:
        log_warning("Failed to drop runlevel to 3")

    # minimize noise for more efficient measurements
    success = fix_cpu_frequency()
    if not success:
        log_warning("Failed to fix CPU frequency")

    success = enable_hugepages()
    if not success:
        # while trevex requires huge pages, we let it take care of raising
        # the error
        log_warning("Failed to enable huge pages")
    
    success = disable_aslr()
    if not success:
        log_warning("Failed to disable ASLR")
    

def tvx_setup_load(args):
    # TODO: load the tvx Python venv
    raise NotImplementedError()

    
def tvx_setup_install(args):
    install_trevex_dependencies()
    # TODO: create python venv and install dependencies into it
    raise NotImplementedError()
