// Example test suite, includes two test cases 
// with checks

#include "test/test_bitcoin.h"
#include <boost/test/unit_test.hpp>
#include <string>

BOOST_FIXTURE_TEST_SUITE(zzz_example_tests, BasicTestingSetup)

// test case 1
BOOST_AUTO_TEST_CASE(zzz_example_one)
{
    // a set of checks in test case 1
    BOOST_CHECK(std::stoi("3333") == 3333);
    BOOST_CHECK(true == false);
}

// test case 2
BOOST_AUTO_TEST_CASE(zzz_example_two)
{
    // checks
    BOOST_CHECK(true == true);
}

BOOST_AUTO_TEST_SUITE_END()
