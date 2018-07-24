clear
echo "Starting unit test suite..."
echo "Overall results -> unit_test_results.log"
echo "Test suite logs -> unit_test.log"
./test_bitcoin --show_progress --build_info --log_level=test_suite --log_sink=unit_test.log
python3 unit_test_results.py unit_test.log

