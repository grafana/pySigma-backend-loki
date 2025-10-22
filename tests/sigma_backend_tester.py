import argparse
import collections
import operator
import os
import subprocess
from typing import Any, Dict

from sigma.exceptions import SigmaError

from sigma.backends.loki import LogQLBackend
from sigma.collection import SigmaCollection
from sigma.pipelines.loki import loki_grafana_logfmt
from sigma.rule import SigmaDetection

parser = argparse.ArgumentParser(
    description="A script to help test pySigma backends using Sigma signature files",
    epilog="For any issues or requests for support, see the GitHub page",
)
parser.add_argument(
    "signature_path",
    help="A path to either a single Sigma signature YAML file or a directory containing "
    "one or more signatures (incl. sub-folders)",
)
parser.add_argument(
    "-a",
    "--add-line-filters",
    action="store_true",
    help="Attempt to add a single line filter to queries that otherwise lack any, to help improve "
    "the overall performance of the query when being run on Loki.",
)
parser.add_argument(
    "-c",
    "--counts",
    action="store_true",
    help="Produce counts of the numbers of signatures processed and counts of successes/fails, "
    "along with error counts",
)
parser.add_argument(
    "-p",
    "--print",
    action="store_true",
    help="Print the query(s) that were generated for the backend, and validation stdout if "
    "applicable",
)
parser.add_argument(
    "-s",
    "--summarize",
    action="store_true",
    help="Produce a summary of the processed signature's log source information",
)
parser.add_argument(
    "-t",
    "--tests",
    type=str,
    help="A path to either a single test log file or a directory containing one or more test log "
    "files, used during the validation of the generated rule(s). If a path to a directory is "
    "provided, this script will look for .log files with the same directory structure of the "
    "signature_path (i.e., if there is a rules/bad.yml file within signature_path, the script "
    "will look for a rules/bad.log file within the path specified in tests)",
)
parser.add_argument(
    "-u",
    "--unique",
    action="store_true",
    help="Print the unique types and messages of errors that occur during the process",
)
parser.add_argument(
    "-v",
    "--validate",
    action="store_true",
    help="Validate the generated rule(s) through the backend engine, where one or more lines of "
    "stdout denotes a successful validation",
)


args = parser.parse_args()

rule_path = args.signature_path

pipeline = loki_grafana_logfmt()

backend = LogQLBackend(
    processing_pipeline=pipeline,
    add_line_filters=args.add_line_filters,
)

counters: Dict[str, Any] = {
    "parse_error": 0,
    "convert_error": 0,
    "validate_error": 0,
    "total_sigs": 0,
    "total_queries": 0,
    "total_files": 0,
    "total_test_logs": 0,
    "convert_success": 0,
    "validate_success": 0,
    "fields": {},
    "error_types": {},
    "error_messages": {},
    "validate_stdout": {},
    "validate_stderr": {},
    "categories": {},
    "products": {},
    "services": {},
}


def validate_with_backend(query, test_file=subprocess.DEVNULL):
    if test_file is None:
        test_file = subprocess.DEVNULL
    result = subprocess.run(
        ["logcli", "--stdin", "query", query], stdin=test_file, capture_output=True
    )
    stdout = result.stdout.decode()
    stderr = result.stderr.decode()
    valid = False
    # If we have an input file, the query is valid if logcli produces one or more lines
    # of output. Otherwise, check logcli's return code to ensure the query is
    # syntactically valid
    if test_file is not subprocess.DEVNULL:
        valid = stdout.count(os.linesep) > 0
    else:
        valid = result.returncode == 0
    return (result.returncode, stdout, stderr, valid)


def find_all_detection_items(detection, acc):
    for value in detection.detection_items:
        if isinstance(value, SigmaDetection):
            return find_all_detection_items(value, acc)
        else:
            return acc + [value]


def process_file(file_path, test_file, args, counters):
    with open(file_path) as rule_file:
        sigma_rules = None
        yaml = rule_file.read()
        counters["total_files"] += 1
        try:
            sigma_rules = SigmaCollection.from_yaml(yaml)
            counters["total_sigs"] += len(sigma_rules)
            if args.summarize:
                for rule in sigma_rules:
                    fields = (
                        list(
                            item.field
                            for detection in rule.detection.detections.values()
                            for item in find_all_detection_items(detection, [])
                            if item.field is not None
                        )
                        + rule.fields
                    )
                    for field in fields:
                        counters["fields"][field] = counters["fields"].get(field, 0) + 1
                    cat = rule.logsource.category
                    prod = rule.logsource.product
                    serv = rule.logsource.service
                    if prod:
                        counters["products"][prod] = counters["products"].get(prod, 0) + 1
                    if serv:
                        counters["services"][serv] = counters["services"].get(serv, 0) + 1
                    if cat:
                        counters["categories"][cat] = counters["categories"].get(cat, 0) + 1
        except SigmaError as err:
            counters["parse_error"] += 1
            if args.unique:
                error_type = type(err).__name__
                counters["error_types"][error_type] = counters["error_types"].get(error_type, 0) + 1
                counters["error_messages"][str(err).strip()] = (
                    counters["error_messages"].get(str(err).strip(), 0) + 1
                )
            return
        try:
            loki_rules = backend.convert(sigma_rules)
            counters["convert_success"] += len(sigma_rules)
            counters["total_queries"] += len(loki_rules)
            if args.validate or args.print:
                for loki_query in loki_rules:
                    if args.print:
                        print(loki_query)
                    if args.validate:
                        (returncode, stdout, stderr, valid) = validate_with_backend(
                            loki_query, test_file
                        )
                        if returncode != 0:
                            counters["validate_error"] += 1
                        elif valid:
                            counters["validate_success"] += 1
                        if args.print and len(stdout) > 0:
                            print(stdout.strip())
                        if args.unique and len(stderr) > 0:
                            counters["validate_stderr"][stderr.strip()] = (
                                counters["validate_stderr"].get(stderr.strip(), 0) + 1
                            )
        except SigmaError as err:
            counters["convert_error"] += 1
            if args.unique:
                error_type = type(err).__name__
                counters["error_types"][error_type] = counters["error_types"].get(error_type, 0) + 1
                counters["error_messages"][str(err)] = (
                    counters["error_messages"].get(str(err), 0) + 1
                )


def print_counts(dct):
    if len(dct) == 0:
        print("\tNo results")
        return
    for k, v in collections.OrderedDict(
        sorted(dct.items(), key=operator.itemgetter(1), reverse=True)
    ).items():
        print(f"\t{k}: {v}")


def get_log_file(rule_file_path):
    (root, _) = os.path.splitext(os.path.basename(rule_file_path))
    return root + ".log"


test_file = None
test_dir = None
if args.tests:
    if os.path.isfile(args.tests):
        test_file = open(args.tests)
        counters["total_test_logs"] += 1
    elif os.path.isdir(args.tests):
        test_dir = args.tests
    else:
        print(f"Could not find test file/directory: {args.tests}")
        exit(1)

if os.path.isfile(rule_path):
    if test_dir:
        test_file_path = os.path.join(test_dir, get_log_file(rule_path))
        if os.path.isfile(test_file_path):
            test_file = open(test_file_path)
            counters["total_test_logs"] += 1
    process_file(rule_path, test_file, args, counters)
elif os.path.isdir(rule_path):
    for dirpath, dirnames, filenames in os.walk(rule_path):
        for filename in filenames:
            rule_file_path = os.path.join(dirpath, filename)
            if test_dir:
                if test_file:
                    test_file.close()
                test_file_path = os.path.join(
                    test_dir,
                    os.path.relpath(dirpath, start=rule_path),
                    get_log_file(filename),
                )
                if os.path.isfile(test_file_path):
                    test_file = open(test_file_path)
                    counters["total_test_logs"] += 1
                else:
                    test_file = None
            elif test_file:
                test_file.seek(0)  # reset the stream position each time
            process_file(rule_file_path, test_file, args, counters)
else:
    print(f"Could not find rule file/directory: {rule_path}")
    exit(1)

if args.counts:
    percent_conv = counters["convert_success"] / counters["total_sigs"] * 100
    print(
        f"Successfully converted {counters['convert_success']} out of "
        f"{counters['total_sigs']} ({percent_conv:.2f}%) signatures"
    )
    if args.validate:
        percent_valid = counters["validate_success"] / counters["total_queries"] * 100
        print(
            f"Successfully validated {counters['validate_success']} out of "
            f"{counters['total_queries']} ({percent_valid:.2f}%) queries"
        )
    print(f"YAML parse errors: {counters['parse_error']}")
    print(f"Conversion errors: {counters['convert_error']}")
    if args.validate:
        print(f"Validation errors: {counters['validate_error']}")
        if args.tests:
            print(f"Test log files used: {counters['total_test_logs']}")

if args.unique:
    print("Error counts:")
    print_counts(counters["error_types"])
    print("Error messages:")
    print_counts(counters["error_messages"])
    if args.validate:
        print("Validation stderr:")
        print_counts(counters["validate_stderr"])

if args.summarize:
    print("Fields:")
    print_counts(counters["fields"])
    print("Products:")
    print_counts(counters["products"])
    print("Services:")
    print_counts(counters["services"])
    print("Categories:")
    print_counts(counters["categories"])

if test_file:
    test_file.close()
