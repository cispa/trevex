from framework.common import *
import framework.result_classification as result_classification
import framework.result_view as result_view
import framework.result_export as result_export


def tvx_result_classify(args):
    result_classification.classify_results(
        verbose=in_verbose_mode(),
        min_threshold=args.min_threshold,
        source_dir=args.source_dir,
        destination_dir=args.destination_dir,
        confirm=args.confirm,
        filename=args.filename
    )


def tvx_result_view(args):
    result_view.view_testcase(
        testcase_fname=args.filename,
        display_taint_dependency_infos=args.taint_dependency_infos
    )


def tvx_result_export(args):
    result_export.export_result_testcase(
        testcase_fname=args.filename,
        output_dir=args.output_dir
    )
