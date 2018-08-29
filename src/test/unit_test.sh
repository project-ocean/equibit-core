# The purpose of this shell script is to run the unit test suite and parse the
# log to produce a short result table

clear
echo "Starting unit test suite..."
echo "Writing brief results overview -> unit_test_results.log"
echo "Detailed test suite logs       -> unit_test.log"

# Starting unit test suite
./test_bitcoin --show_progress --build_info --log_level=test_suite --log_sink=unit_test.log

# Parsing unit test suite results into a brief table
python3 unit_test_results.py unit_test.log

