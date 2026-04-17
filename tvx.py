#!/usr/bin/env python3

import argparse

import framework.common as common
import framework.command_ctrl as command_ctrl
import framework.command_run as command_run
import framework.command_dev as command_dev
import framework.command_setup as command_setup
import framework.command_result as command_result


def parse_args():
    parser = argparse.ArgumentParser(description="Trevex main control script")
    parser.add_argument("-v", "--verbose", action="store_true", help="Verbose")

    commands = parser.add_subparsers(dest="command", required=True)

    # we do not need subcommands for "run" atm
    run_parser = commands.add_parser("run", help="Run commands")
    run_subcommands = run_parser.add_subparsers(
        dest="subcommand",
        required=True,
    )
    run_subcommands.add_parser("start", help="Start fuzzing")
    run_subcommands.add_parser(
        "cleanup", 
        help="Cleanup fuzzing artifacts (incl. results)"
    )

    setup_parser = commands.add_parser("setup", help="Setup commands")
    setup_subcommands = setup_parser.add_subparsers(
        dest="subcommand",
        required=True,
    )
    setup_subcommands.add_parser("load", help="Load setup")
    setup_subcommands.add_parser("install", help="Install setup")

    result_parser = commands.add_parser("result", help="Result commands")
    result_subcommands = result_parser.add_subparsers(
        dest="subcommand",
        required=True,
    )
    result_subcommands.add_parser("rerun", help="Rerun testcase with fuzzer")

    result_export_parser = result_subcommands.add_parser(
        "export", help="Export testcase to standalone files")
    
    result_export_parser.add_argument(
                        dest="filename",
                        action="store",
                        help="Testcase JSON to export",
    )

    result_export_parser.add_argument(
                        "-o",
                        "--output-dir",
                        action="store",
                        help="Output directory for exported files",
    )
    

    result_view_parser = result_subcommands.add_parser(
        "view",
        help="View results"
    )
    result_view_parser.add_argument(
                        dest="filename",
                        action="store",
                        help="Testcase JSON to view",
    )
    result_view_parser.add_argument(
        "-t",
        "--taint-dependency-infos",
        action="store_true",
        help="Display verbose taint dependency information",
    )


    result_classify_parser = result_subcommands.add_parser(
        "classify", 
        help="Run the classification stage"
    )
    result_classify_parser.add_argument('-t', '--threshold',
                        dest="min_threshold",
                        action="store",
                        help="Minimum number of occurences for leakage to be considered valid",
                        required=False)
    result_classify_parser.add_argument('-s', '--src',
                        dest="source_dir",
                        action="store",
                        help="Directory to load results from",
                        required=False)
    result_classify_parser.add_argument('-d', '--dst',
                        dest="destination_dir",
                        action="store",
                        help="Directory to store the classification results to",
                        required=False)
    result_classify_parser.add_argument('-f', '--filename',
                        dest="filename",
                        action="store",
                        help="Run classification on a single file",
                        required=False)
    result_classify_parser.add_argument('-c', '--confirm',
                        dest="confirm",
                        action="store_true",
                        help="Confirm that you know what you're doing. Only required when you're prompted for it.",
                        required=False)


    ctrl_parser = commands.add_parser("ctrl", help="Remote machine orchestration commands")
    ctrl_parser.add_argument(
        "-m",
        "--machine-file",
        required=True,
        metavar="machine_file.cfg",
        help="Machine configuration file",
    )
    ctrl_subcommands = ctrl_parser.add_subparsers(dest="subcommand", required=True)
    ctrl_subcommands.add_parser("setup", help="Setup remote machines. Includes installing different kernel and rebooting if necessary.")
    ctrl_subcommands.add_parser("spawn", help="Spawn trevex on remote machines")
    ctrl_subcommands.add_parser("stop", help="Stop trevex on remote machines")
    ctrl_subcommands.add_parser("attach", help="Attach to running trevex instance on remote machines")
    ctrl_subcommands.add_parser("detach", help="Detach from running trevex instance on remote machines")
    ctrl_subcommands.add_parser("pull-results", help="Pull results from remote machines")
    ctrl_subcommands.add_parser("cleanup", help="Cleanup remote machines and deletes results.")

    dev_parser = commands.add_parser("dev", help="Development commands")
    dev_subcommands = dev_parser.add_subparsers(
        dest="subcommand",
        required=True,
    )
    dev_subcommands.add_parser("build", help="Build trevex")

    return parser.parse_args()


def main():
    args = parse_args()

    try:
        if args.verbose:
            common.set_verbose_mode(True)

        if args.command == "run":
            if args.subcommand == "start":
                command_run.tvx_run_start(args)
            elif args.subcommand == "cleanup":
                command_run.tvx_run_cleanup(args)

        elif args.command == "setup":
            if args.subcommand == "load":
                command_setup.tvx_setup_load(args)
            elif args.subcommand == "install":
                command_setup.tvx_setup_install(args)

        elif args.command == "result":
            if args.subcommand == "classify":
                command_result.tvx_result_classify(args)
            elif args.subcommand == "view":
                command_result.tvx_result_view(args)
            elif args.subcommand == "rerun":
                command_result.tvx_result_rerun(args)
            elif args.subcommand == "export":
                command_result.tvx_result_export(args)

        elif args.command in ("ctrl"):
            if args.subcommand == "setup":
                command_ctrl.tvx_ctrl_setup(args)
            elif args.subcommand == "spawn":
                command_ctrl.tvx_ctrl_spawn(args)
            elif args.subcommand == "stop":
                command_ctrl.tvx_ctrl_stop(args)
            elif args.subcommand == "attach":
                command_ctrl.tvx_ctrl_attach(args)
            elif args.subcommand == "detach":
                command_ctrl.tvx_ctrl_detach(args)
            elif args.subcommand == "pull-results":
                command_ctrl.tvx_ctrl_pull_results(args)
            elif args.subcommand == "cleanup":
                command_ctrl.tvx_ctrl_cleanup(args)

        elif args.command == "dev":
            if args.subcommand == "build":
                command_dev.tvx_dev_build(args)

        else:
            # should not happen as argparse should catch unknown commands
            raise ValueError(f"Unknown command: {args.command}")
    except NotImplementedError:
        common.log_warning(f"Command not implemented yet!")
        exit(1)


if __name__ == "__main__":
    main()
