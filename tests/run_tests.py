from argparse import ArgumentParser
import logging
from test_runner.consts import Arches
from test_runner.tests import TEST_CASES, TESTS, get_test_with_features
from test_runner.test_run_utils import run_test, test_banner, arch_banner, display_output
import traceback
import sys

parser = ArgumentParser("testRunner")
all_arches = [arch.value for arch in Arches]
parser.add_argument("--arch", choices=all_arches, required=False, default=all_arches, nargs="+")
parser.add_argument("--test", choices=TEST_CASES, required=False, default=TEST_CASES, nargs="+")
parser.add_argument("--debug", default=False, action="store_true", required=False, help="Run qemu on local port 1234")
parser.add_argument("--verbose", default=False, action="store_true", required=False)
parser.add_argument("--test-verbose", default=False, action="store_true", help="Test runner verbose logging")
parser.add_argument("--strace", default=False, action="store_true", required=False)
parser.add_argument("--verbose-on-failed", default=False, action="store_true", required=False)
args = parser.parse_args()
sys.modules['__global_args'] = args
if args.test_verbose:
    logging.basicConfig(level=logging.INFO)


def main():
    summary_failed = []
    failed = 0
    success = 0
    for arch in args.arch:
        arch_banner(arch)
        for case in args.test:
            logging.info("Finding key for: {}".format(case))
            test_description, test_features = get_test_with_features(case)
            logging.info("Key found: {}".format(test_description))
            test_parameters = TESTS[test_description]
            if arch not in test_parameters['supported_arches']:
                continue
            if test_features in test_parameters.get("disabled_features", []):
                continue
            try:

                test_output = run_test(
                    key=test_description,
                    test_parameters=test_parameters,
                    arch=arch,
                    description=case,
                    test_features=test_features,
                    is_debug=args.debug,
                    is_strace=args.strace,
                    is_verbose=args.verbose,
                    verbose_on_failed=args.verbose_on_failed
                )

                display_output(test_output, is_verbose=args.verbose,
                               verbose_on_failed=args.verbose_on_failed)
                if test_output.success:
                    success += 1
                else:
                    failed += 1
                test_banner()
            except Exception as e:
                if args.test_verbose:
                    traceback.print_exc()
                summary_failed.append(e)
                failed += 1

    print("Success: {} Failed: {}".format(
        success,
        failed
    ))
    if args.verbose:
        for failed in summary_failed:
            print(failed)


if __name__ == "__main__":
    main()
