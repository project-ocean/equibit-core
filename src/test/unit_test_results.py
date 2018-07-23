#!/usr/bin/env python3
# Copyright (c) 2018 Equibit-group

import sys
import re
import datetime

with open(sys.argv[1], 'r', newline='\n') as f:
    contents = f.read().splitlines()

tests_result = {}
tSuite = {}
tCase = {}
tError = []
log_header = ""
log_file = ""
tests_n = 0

# Parse log file into the hierarchical structure
for ln in contents:
    tests_number = re.match(r'.*Running (\d+) test.*', ln)
    module = re.match(r'.*(Entering test module)\s\"(.+)\"', ln)
    suite = re.match(r'.*(Entering test suite)\s\"(.+)\"', ln)
    testcase = re.match(r'.*(Entering test case)\s\"(.+)\"', ln)
    testerror = re.match(r'.*(error: in)\s\"(.+)\":\s(.*)', ln)

    if tests_number is not None:
        log_header += ln + "\n"
        tests_n = int(tests_number.group(1))
    if suite is not None:
        tCase = {}
        tests_result[suite.group(2)] = tCase
    if testcase is not None:
        tError = []
        tCase[testcase.group(2)] = tError
    if testerror is not None:
        tError.append(testerror.group(3))

suites_with_errors = 0
tCases_with_errors = 0
total_errors = 0

now = datetime.datetime.now()
log_header += str(now.strftime("%Y-%m-%d %H:%M:%S")) + "\n"
print(log_header)

# Traverse tests_result{} and print summary to the screen and complete log to the file
for sui in sorted(tests_result.keys()):
    total_errors_suite = 0
    log_file += "Test Suite: %s\n\n" % sui

    for cs in sorted(tests_result[sui].keys()):
        numErrors = len(tests_result[sui][cs])
        if numErrors > -1:  # -1 prints all test cases, 0 prints only those with errors
            log_file += "Test Case: {0:50} Errors: {1:5}\n".format(cs, numErrors)
            total_errors_suite += numErrors
            total_errors += numErrors
        if numErrors > 0:
            tCases_with_errors += 1

    if total_errors_suite > 0:
        suites_with_errors += 1

    log_file += " " * 63 + "TOTAL: {:5}\n".format(total_errors_suite)
    log_file += "-----------------------------------------------------------------------------\n"
    print("Test Suite: {0:40} TOTAL ERRORS: {1:5}".format(sui, total_errors_suite))

print("-----------------------------------------------------------------------------")
print("Suites with errors:     {:5}".format(suites_with_errors))
print("Test Cases with errors: {:5}".format(tCases_with_errors))
print("Errors total:           {:5}".format(total_errors))
print("Executed test cases:    {:5}".format(tests_n))

with open("unit_test_results.log", "w") as file_log:
    print(log_header, file=file_log)
    print("Suites with errors:     {:5}".format(suites_with_errors), file=file_log)
    print("Test Cases with errors: {:5}".format(tCases_with_errors), file=file_log)
    print("Errors total:           {:5}".format(total_errors), file=file_log)
    print("-----------------------------------------------------------------------------", file=file_log)
    print(log_file, file=file_log)
