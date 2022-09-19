    @dir ah_unit @brief Unit testing library.

Whatever the purpose of your software, you are likely going to have to test it
at some point. There are many ways to appropriately test software, depending on
what kind of software it is and how you intend it to be used. This particular
library can aid you with the testing process by helping you write so-called unit
tests.

The library itself does not actually provide units nor does it organize them
into suites, which is common for unit testing tools. Rather, the library
provides a simple data structure for counting executed and/or failed test
assertions, as well as functions that execute test assertions and print messages
if they fail. How you organize suites and individual tests is up to you. If you
want examples of test suites and test units, you may, for example, refer to the
source code of the ah_base library, which contains tests in its test/ folder.
