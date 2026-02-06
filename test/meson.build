# Test configuration for provisioningd

gtest_dep = dependency('gtest', main: true, required: true)
gmock_dep = dependency('gmock', required: true)

# Common test dependencies
test_deps = [
    provisioning_dep,
    gtest_dep,
    gmock_dep,
]

# Test for make_awaitable.hpp
test_make_awaitable = executable(
    'test_make_awaitable',
    'test_make_awaitable.cpp',
    dependencies: test_deps,
    cpp_args: ['-DBOOST_ASIO_DISABLE_THREADS', '-Wno-maybe-uninitialized'],
    include_directories: include_directories('../include'),
)

test('make_awaitable_tests', test_make_awaitable)

# Test for sdbus_calls.hpp
test_sdbus_calls = executable(
    'test_sdbus_calls',
    'test_sdbus_calls.cpp',
    dependencies: test_deps,
    cpp_args: ['-DBOOST_ASIO_DISABLE_THREADS'],
    include_directories: include_directories('../include'),
)

test('sdbus_calls_tests', test_sdbus_calls)