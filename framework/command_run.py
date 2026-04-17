import shutil
import sys
import time

from framework.common import *
import framework.command_setup as command_setup


def check_for_other_users_and_confirm():
    current_user = os.environ.get("USER")

    p_ret, p_stdout, p_stderr = run_cmd(["w", "-h"])
    if p_ret != 0:
        raise RuntimeError("User check failed")

    other_users = list()
    for line in p_stdout.splitlines():
        user = line.split()[0]
        if user != current_user:
            other_users.append(user)
    if other_users:
        log_warning("[!] Other users are logged in:")
        log_warning("\n".join(other_users))
        answer = input("[?] Do you want to continue? (y/n) ").strip()
        if answer != "y" and answer != "Y":
            sys.exit(1)
    

def duplicate_trevex_tmux_session_exists():
    p_err, p_stdout, p_stderr = run_cmd("tmux ls")
    if p_err != 0:
        # happens when there are no tmux sessions
        return False
    for line in p_stdout.splitlines():
        if line.startswith(TREVEX_TMUX_SESSION_NAME + ":"):
            return True
    return False


def countdown(seconds):
    for i in range(seconds, 0, -1):
        log_info(f"...{i}")
        time.sleep(1)


def start_trevex():
    if duplicate_trevex_tmux_session_exists():
        log_error(f"Tmux session '{TREVEX_TMUX_SESSION_NAME}' already exists.")
        log_error("Is Trevex already running? If not, please kill the tmux session and try again.")
        exit(1)

    # display a countdown to give the user chance to read previous log messages
    log_info("Starting Trevex in...")
    countdown(3)
    
    # start trevex in a tmux session, with a trap to drop into a shell 
    # if trevex crashes or is interrupted
    verbose_str = "-v" if in_verbose_mode() else ""
    payload = f"(trap 'zsh' INT; cd {TREVEX_BUILD_DIR};sudo ./trevex {verbose_str}; zsh)"
    argv = ["tmux", "new-session", "-s", TREVEX_TMUX_SESSION_NAME, payload]
    log_verbose(f"Starting trevex: {argv}")
    os.execvp("tmux", argv)


def tvx_run_start(args):
    check_for_other_users_and_confirm()

    # install fuzzer dependencies
    log_info("Checking and installing dependencies...")
    command_setup.install_trevex_dependencies()

    log_info("Building and installing PTEditor...")
    command_setup.build_and_load_pteditor()

    log_info("Preparing system for fuzzing...")
    command_setup.prepare_system_for_fuzzing()

    log_info("Building trevex...")
    command_setup.build_trevex()

    log_info("Starting trevex...")
    start_trevex()
    

def tvx_run_cleanup(args):
    log_info("Clearing trevex stored progress")
    try:
        os.unlink(TREVEX_BUILD_DIR / TREVEX_PROGRESS_FNAME)
    except FileNotFoundError:
        pass
    log_info("Clearing trevex results")
    # the results folder is root-owned, hence we use sudo to delete it
    p_err, p_stdout, p_stderr = run_cmd(f"sudo rm -rf {RESULT_FOLDER}")
    if p_err != 0:
        log_error(f"Failed to clear results: {p_stdout}\n{p_stderr}")
