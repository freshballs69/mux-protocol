# CMake generated Testfile for 
# Source directory: /Users/vitalii/Documents/mux-protocol/tests
# Build directory: /Users/vitalii/Documents/mux-protocol/build-rel/tests
# 
# This file includes the relevant testing commands required for 
# testing this directory and lists subdirectories to be tested as well.
add_test([=[frame]=] "/Users/vitalii/Documents/mux-protocol/build-rel/tests/test_frame")
set_tests_properties([=[frame]=] PROPERTIES  _BACKTRACE_TRIPLES "/Users/vitalii/Documents/mux-protocol/tests/CMakeLists.txt;5;add_test;/Users/vitalii/Documents/mux-protocol/tests/CMakeLists.txt;0;")
add_test([=[session]=] "/Users/vitalii/Documents/mux-protocol/build-rel/tests/test_session")
set_tests_properties([=[session]=] PROPERTIES  _BACKTRACE_TRIPLES "/Users/vitalii/Documents/mux-protocol/tests/CMakeLists.txt;9;add_test;/Users/vitalii/Documents/mux-protocol/tests/CMakeLists.txt;0;")
add_test([=[auth]=] "/Users/vitalii/Documents/mux-protocol/build-rel/tests/test_auth")
set_tests_properties([=[auth]=] PROPERTIES  _BACKTRACE_TRIPLES "/Users/vitalii/Documents/mux-protocol/tests/CMakeLists.txt;13;add_test;/Users/vitalii/Documents/mux-protocol/tests/CMakeLists.txt;0;")
add_test([=[libpeer]=] "/Users/vitalii/Documents/mux-protocol/build-rel/tests/test_libpeer")
set_tests_properties([=[libpeer]=] PROPERTIES  TIMEOUT "30" _BACKTRACE_TRIPLES "/Users/vitalii/Documents/mux-protocol/tests/CMakeLists.txt;17;add_test;/Users/vitalii/Documents/mux-protocol/tests/CMakeLists.txt;0;")
add_test([=[fuzz_frame]=] "/Users/vitalii/Documents/mux-protocol/build-rel/tests/fuzz_frame")
set_tests_properties([=[fuzz_frame]=] PROPERTIES  _BACKTRACE_TRIPLES "/Users/vitalii/Documents/mux-protocol/tests/CMakeLists.txt;42;add_test;/Users/vitalii/Documents/mux-protocol/tests/CMakeLists.txt;0;")
