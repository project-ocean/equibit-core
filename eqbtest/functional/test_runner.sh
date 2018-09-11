# This script runs the python test_runner.py calling all the functional tests
# in two OS threads

python3 test_runner.py --extended --exclude feature_pruning,feature_dbcrash --jobs=4
