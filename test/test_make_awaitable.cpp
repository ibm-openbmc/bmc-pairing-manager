/**
 * @file test_make_awaitable.cpp
 * @brief Unit tests for make_awaitable.hpp
 *
 * Tests the awaitable handler wrapper functionality including:
 * - Type aliases (PrependEC, ReturnTuple, AwaitableResult)
 * - PromiseType functionality
 * - make_awaitable_handler with various return types
 * - Error code handling (with and without error_code in signature)
 */

#include <gmock/gmock.h>
#include <gtest/gtest.h>

// Define LOG_ERROR stub for testing - must be before including headers
#ifndef LOG_ERROR
#define LOG_ERROR(...)                                                         \
    do                                                                         \
    {                                                                          \
    } while (0)
#endif

// Suppress false positive warnings about uninitialized variables in coroutines
#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wmaybe-uninitialized"

#define NSNAME TestNamespace
#include "../include/make_awaitable.hpp"

#pragma GCC diagnostic pop

#include <boost/asio.hpp>
#include <boost/asio/co_spawn.hpp>
#include <boost/asio/detached.hpp>
#include <boost/asio/io_context.hpp>

#include <string>
#include <tuple>

using namespace TestNamespace;
namespace net = boost::asio;

/**
 * @brief Test fixture for make_awaitable tests
 */
class MakeAwaitableTest : public ::testing::Test
{
  protected:
    net::io_context io;
};

/**
 * @brief Test PrependEC type alias
 * Verifies that PrependEC correctly prepends error_code to a tuple of types
 */
TEST_F(MakeAwaitableTest, PrependECTypeAlias)
{
    // Test with single type
    using SingleType = PrependEC<int>;
    static_assert(
        std::is_same_v<SingleType, std::tuple<boost::system::error_code, int>>);

    // Test with multiple types
    using MultipleTypes = PrependEC<int, std::string, bool>;
    static_assert(
        std::is_same_v<MultipleTypes, std::tuple<boost::system::error_code, int,
                                                 std::string, bool>>);

    // Test with no types
    using NoTypes = PrependEC<>;
    static_assert(
        std::is_same_v<NoTypes, std::tuple<boost::system::error_code>>);
}

/**
 * @brief Test ReturnTuple type alias with error_code already present
 * Verifies that ReturnTuple doesn't duplicate error_code when it's already
 * first
 */
TEST_F(MakeAwaitableTest, ReturnTupleWithErrorCode)
{
    // When error_code is already first, should not prepend
    using WithEC = ReturnTuple<boost::system::error_code, int>;
    static_assert(
        std::is_same_v<WithEC, std::tuple<boost::system::error_code, int>>);

    // Multiple types with error_code first
    using WithECMultiple =
        ReturnTuple<boost::system::error_code, int, std::string>;
    static_assert(
        std::is_same_v<WithECMultiple, std::tuple<boost::system::error_code,
                                                  int, std::string>>);
}

/**
 * @brief Test ReturnTuple type alias without error_code
 * Verifies that ReturnTuple prepends error_code when not present
 */
TEST_F(MakeAwaitableTest, ReturnTupleWithoutErrorCode)
{
    // When error_code is not first, should prepend
    using WithoutEC = ReturnTuple<int>;
    static_assert(
        std::is_same_v<WithoutEC, std::tuple<boost::system::error_code, int>>);

    // Multiple types without error_code
    using WithoutECMultiple = ReturnTuple<int, std::string, bool>;
    static_assert(
        std::is_same_v<WithoutECMultiple, std::tuple<boost::system::error_code,
                                                     int, std::string, bool>>);
}

/**
 * @brief Test AwaitableResult type alias
 * Verifies that AwaitableResult wraps ReturnTuple in an awaitable
 */
TEST_F(MakeAwaitableTest, AwaitableResultTypeAlias)
{
    // Test with single type
    using SingleAwaitable = AwaitableResult<int>;
    static_assert(std::is_same_v<
                  SingleAwaitable,
                  net::awaitable<std::tuple<boost::system::error_code, int>>>);

    // Test with error_code already present
    using WithECAwaitable = AwaitableResult<boost::system::error_code, int>;
    static_assert(std::is_same_v<
                  WithECAwaitable,
                  net::awaitable<std::tuple<boost::system::error_code, int>>>);
}

/**
 * @brief Test PromiseType setValues method
 * Verifies that PromiseType correctly stores and invokes the promise
 */
TEST_F(MakeAwaitableTest, PromiseTypeSetValues)
{
    bool called = false;
    int receivedValue = 0;
    boost::system::error_code receivedEc;

    auto handler = [&](std::tuple<boost::system::error_code, int> result) {
        called = true;
        receivedEc = std::get<0>(result);
        receivedValue = std::get<1>(result);
    };

    PromiseType<decltype(handler), boost::system::error_code, int> promise{
        handler};
    promise.setValues(boost::system::error_code{}, 42);

    EXPECT_TRUE(called);
    EXPECT_FALSE(receivedEc);
    EXPECT_EQ(receivedValue, 42);
}

/**
 * @brief Test make_awaitable_handler with single return value
 * Verifies basic functionality with one return type
 */
TEST_F(MakeAwaitableTest, MakeAwaitableHandlerSingleValue)
{
    bool testComplete = false;
    int expectedValue = 123;

    net::co_spawn(
        io,
        [&]() -> net::awaitable<void> {
            auto handler = make_awaitable_handler<int>([&](auto promise) {
                promise.setValues(boost::system::error_code{}, expectedValue);
            });

            auto [ec, value] = co_await handler();

            EXPECT_FALSE(ec);
            EXPECT_EQ(value, expectedValue);
            testComplete = true;
        },
        net::detached);

    io.run();
    EXPECT_TRUE(testComplete);
}

/**
 * @brief Test make_awaitable_handler with multiple return values
 * Verifies functionality with multiple return types
 */
TEST_F(MakeAwaitableTest, MakeAwaitableHandlerMultipleValues)
{
    bool testComplete = false;

    net::co_spawn(
        io,
        [&]() -> net::awaitable<void> {
            auto handler = make_awaitable_handler<int, std::string, bool>(
                [](auto promise) {
                    promise.setValues(boost::system::error_code{}, 42, "test",
                                      true);
                });

            auto [ec, num, str, flag] = co_await handler();

            EXPECT_FALSE(ec);
            EXPECT_EQ(num, 42);
            EXPECT_EQ(str, "test");
            EXPECT_TRUE(flag);
            testComplete = true;
        },
        net::detached);

    io.run();
    EXPECT_TRUE(testComplete);
}

/**
 * @brief Test make_awaitable_handler with error_code in signature
 * Verifies that error_code is not duplicated when already in return types
 */
TEST_F(MakeAwaitableTest, MakeAwaitableHandlerWithErrorCodeInSignature)
{
    bool testComplete = false;

    net::co_spawn(
        io,
        [&]() -> net::awaitable<void> {
            auto handler =
                make_awaitable_handler<boost::system::error_code, int>(
                    [](auto promise) {
                        promise.setValues(boost::system::error_code{}, 99);
                    });

            auto [ec, value] = co_await handler();

            EXPECT_FALSE(ec);
            EXPECT_EQ(value, 99);
            testComplete = true;
        },
        net::detached);

    io.run();
    EXPECT_TRUE(testComplete);
}

/**
 * @brief Test make_awaitable_handler with error condition
 * Verifies error handling when operation fails
 */
TEST_F(MakeAwaitableTest, MakeAwaitableHandlerWithError)
{
    bool testComplete = false;

    net::co_spawn(
        io,
        [&]() -> net::awaitable<void> {
            auto handler =
                make_awaitable_handler<std::string>([](auto promise) {
                    promise.setValues(
                        boost::asio::error::make_error_code(
                            boost::asio::error::operation_aborted),
                        "");
                });

            auto [ec, value] = co_await handler();

            EXPECT_TRUE(ec);
            EXPECT_EQ(ec, boost::asio::error::operation_aborted);
            EXPECT_EQ(value, "");
            testComplete = true;
        },
        net::detached);

    io.run();
    EXPECT_TRUE(testComplete);
}

/**
 * @brief Test invoke_handler_with_promise with error_code present
 * Verifies the helper function correctly handles error_code in signature
 */
TEST_F(MakeAwaitableTest, InvokeHandlerWithPromiseErrorCodePresent)
{
    bool handlerCalled = false;
    bool promiseCalled = false;

    auto handler = [&](std::tuple<boost::system::error_code, int> result) {
        promiseCalled = true;
        EXPECT_FALSE(std::get<0>(result));
        EXPECT_EQ(std::get<1>(result), 55);
    };

    auto userHandler = [&](auto promise) {
        handlerCalled = true;
        promise.setValues(boost::system::error_code{}, 55);
    };

    invoke_handler_with_promise<boost::system::error_code, int>(
        handler, userHandler);

    EXPECT_TRUE(handlerCalled);
    EXPECT_TRUE(promiseCalled);
}

/**
 * @brief Test invoke_handler_with_promise without error_code
 * Verifies the helper function correctly prepends error_code when not present
 */
TEST_F(MakeAwaitableTest, InvokeHandlerWithPromiseErrorCodeNotPresent)
{
    bool handlerCalled = false;
    bool promiseCalled = false;

    auto handler =
        [&](std::tuple<boost::system::error_code, std::string> result) {
            promiseCalled = true;
            EXPECT_FALSE(std::get<0>(result));
            EXPECT_EQ(std::get<1>(result), "hello");
        };

    auto userHandler = [&](auto promise) {
        handlerCalled = true;
        promise.setValues(boost::system::error_code{}, "hello");
    };

    invoke_handler_with_promise<std::string>(handler, userHandler);

    EXPECT_TRUE(handlerCalled);
    EXPECT_TRUE(promiseCalled);
}

/**
 * @brief Test make_awaitable_handler with complex types
 * Verifies functionality with custom structs and complex types
 */
TEST_F(MakeAwaitableTest, MakeAwaitableHandlerComplexTypes)
{
    struct TestData
    {
        int id;
        std::string name;
        bool operator==(const TestData& other) const
        {
            return id == other.id && name == other.name;
        }
    };

    bool testComplete = false;
    TestData expected{42, "test_data"};

    net::co_spawn(
        io,
        [&]() -> net::awaitable<void> {
            auto handler = make_awaitable_handler<TestData>([&](auto promise) {
                promise.setValues(boost::system::error_code{}, expected);
            });

            auto [ec, data] = co_await handler();

            EXPECT_FALSE(ec);
            EXPECT_EQ(data, expected);
            testComplete = true;
        },
        net::detached);

    io.run();
    EXPECT_TRUE(testComplete);
}

/**
 * @brief Test make_awaitable_handler with move-only types
 * Verifies functionality with types that can only be moved
 */
TEST_F(MakeAwaitableTest, MakeAwaitableHandlerMoveOnlyTypes)
{
    bool testComplete = false;

    net::co_spawn(
        io,
        [&]() -> net::awaitable<void> {
            auto handler =
                make_awaitable_handler<std::unique_ptr<int>>([](auto promise) {
                    promise.setValues(boost::system::error_code{},
                                      std::make_unique<int>(777));
                });

            auto [ec, ptr] = co_await handler();

            EXPECT_FALSE(ec);
            EXPECT_NE(ptr, nullptr);
            if (ptr)
            {
                EXPECT_EQ(*ptr, 777);
            }
            testComplete = true;
        },
        net::detached);

    io.run();
    EXPECT_TRUE(testComplete);
}

/**
 * @brief Test make_awaitable_handler with no return value (void-like)
 * Verifies functionality when only error_code is returned
 */
TEST_F(MakeAwaitableTest, MakeAwaitableHandlerVoidLike)
{
    bool testComplete = false;

    net::co_spawn(
        io,
        [&]() -> net::awaitable<void> {
            auto handler = make_awaitable_handler<boost::system::error_code>(
                [](auto promise) {
                    promise.setValues(boost::system::error_code{});
                });

            auto [ec] = co_await handler();

            EXPECT_FALSE(ec);
            testComplete = true;
        },
        net::detached);

    io.run();
    EXPECT_TRUE(testComplete);
}

/**
 * @brief Test PromiseType with multiple values
 * Verifies PromiseType correctly handles multiple return values
 */
TEST_F(MakeAwaitableTest, PromiseTypeMultipleValues)
{
    bool called = false;
    int receivedInt = 0;
    std::string receivedStr;
    bool receivedBool = false;
    boost::system::error_code receivedEc;

    auto handler =
        [&](std::tuple<boost::system::error_code, int, std::string, bool>
                result) {
            called = true;
            receivedEc = std::get<0>(result);
            receivedInt = std::get<1>(result);
            receivedStr = std::get<2>(result);
            receivedBool = std::get<3>(result);
        };

    PromiseType<decltype(handler), boost::system::error_code, int, std::string,
                bool>
        promise{handler};
    promise.setValues(boost::system::error_code{}, 100, "data", true);

    EXPECT_TRUE(called);
    EXPECT_FALSE(receivedEc);
    EXPECT_EQ(receivedInt, 100);
    EXPECT_EQ(receivedStr, "data");
    EXPECT_TRUE(receivedBool);
}

/**
 * @brief Test make_awaitable_handler with different error codes
 * Verifies various error conditions are properly propagated
 */
TEST_F(MakeAwaitableTest, MakeAwaitableHandlerDifferentErrors)
{
    bool testComplete = false;

    net::co_spawn(
        io,
        [&]() -> net::awaitable<void> {
            // Test with connection_refused error
            auto handler1 = make_awaitable_handler<int>([](auto promise) {
                promise.setValues(boost::asio::error::make_error_code(
                                      boost::asio::error::connection_refused),
                                  0);
            });

            auto [ec1, val1] = co_await handler1();
            EXPECT_TRUE(ec1);
            EXPECT_EQ(ec1, boost::asio::error::connection_refused);

            // Test with timed_out error
            auto handler2 =
                make_awaitable_handler<std::string>([](auto promise) {
                    promise.setValues(boost::asio::error::make_error_code(
                                          boost::asio::error::timed_out),
                                      "");
                });

            auto [ec2, val2] = co_await handler2();
            EXPECT_TRUE(ec2);
            EXPECT_EQ(ec2, boost::asio::error::timed_out);

            testComplete = true;
        },
        net::detached);

    io.run();
    EXPECT_TRUE(testComplete);
}

/**
 * @brief Main function to run all tests
 */
int main(int argc, char** argv)
{
    ::testing::InitGoogleTest(&argc, argv);
    return RUN_ALL_TESTS();
}
