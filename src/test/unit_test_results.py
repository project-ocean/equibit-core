#!/usr/bin/env python3
# Copyright (c) 2018 Equibit-group

import sys
import re

with open(sys.argv[1], 'r', newline='\n') as f:
    contents = f.read().splitlines()

tests_result = {}
tSuite = {}
tCase = {}
tError = []
log_header = ""

for ln in contents:
    tests_number = re.match(r'.*Running \d+ test.*', ln)
    module = re.match(r'.*(Entering test module)\s\"(.+)\"', ln)    # Entering test module "Bitcoin Test Suite"
    suite = re.match(r'.*(Entering test suite)\s\"(.+)\"', ln)      # test/mempool_tests.cpp(15): Entering test suite "mempool_tests"
    testcase = re.match(r'.*(Entering test case)\s\"(.+)\"', ln)    # test/mempool_tests.cpp(433): Entering test case "MempoolSizeLimitTest"
    testerror = re.match(r'.*(error: in)\s\"(.+)\":\s(.*)', ln)     # test/mempool_tests.cpp(577): error: in "mempool_tests/MempoolSizeLimitTest": check pool.GetMinFee(1).GetFeePerK() == 1000 has failed

    if tests_number is not None:
        log_header += ln + "\n"
    if suite is not None:
        tCase = {}
        tests_result[suite.group(2)] = tCase
    if testcase is not None:
        tError = []
        tCase[testcase.group(2)] = tError
    if testerror is not None:
        tError.append(testerror.group(3))

#print(tests_result)
with open("unit_test_results.log", "w") as file_log:
    print(log_header, file=file_log)
    print(log_header)
    for sui in sorted(tests_result.keys()):
        total_errors_suite = 0
        print("Test Suite: %s\n" %sui, file=file_log)
        for cs in sorted(tests_result[sui].keys()):
            numErrors = len(tests_result[sui][cs])
            if numErrors > -1:  # print all test cases, including with no errors
                print("Test Case: {0:50} Errors: {1:5}".format(cs, numErrors), file=file_log)
                total_errors_suite += numErrors
        print("TOTAL ERRORS: {:6}".format(total_errors_suite), file=file_log)
        print("-----------------------------------------------------------------------------", file=file_log)

        print("Test Suite: {0:40} TOTAL ERRORS: {1:5}".format(sui, total_errors_suite))

