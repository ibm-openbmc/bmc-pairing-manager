#pragma once
#include <boost/asio.hpp>
#include <boost/asio/coroutine.hpp>

#include <concepts>
#include <tuple>
#include <type_traits>

namespace NSNAME
{
namespace net = boost::asio;

/**
 * @brief Concept to check if a type is boost::system::error_code
 */
template <typename T>
concept IsErrorCode =
    std::same_as<std::remove_cvref_t<T>, boost::system::error_code>;

/**
 * @brief Concept to check if the first type in a parameter pack is error_code
 */
template <typename... Types>
concept StartsWithErrorCode =
    (sizeof...(Types) > 0) &&
    IsErrorCode<std::tuple_element_t<0, std::tuple<Types...>>>;

/**
 * @brief Type alias that prepends boost::system::error_code to a tuple of
 * types.
 *
 * This is used to ensure async operations always have an error_code as the
 * first element in their result tuple, following Boost.Asio conventions.
 *
 * Example: PrependEC<int, std::string> -> std::tuple<error_code, int,
 * std::string>
 */
template <typename... Types>
using PrependEC = std::tuple<boost::system::error_code, Types...>;

/**
 * @brief Conditionally prepends error_code to return types if not already
 * present.
 *
 * Uses concepts to check if the first type in RetTypes is already an
 * error_code.
 * - If error_code is already first: Returns tuple as-is
 * (std::tuple<RetTypes...>)
 * - If error_code is NOT first: Prepends it using PrependEC<RetTypes...>
 *
 * This conditional behavior allows handlers to work with both:
 * 1. Functions that already include error_code in their signature
 * 2. Functions that need error_code added automatically
 *
 * Example : ReturnTuple<int, std::string> -> std::tuple<error_code, int,
 * std::string>
 */
template <typename... RetTypes>
using ReturnTuple =
    std::conditional_t<StartsWithErrorCode<RetTypes...>,
                       std::tuple<RetTypes...>, PrependEC<RetTypes...>>;

/**
 * @brief Wraps the return tuple in a Boost.Asio awaitable for coroutine
 * support.
 *
 * This creates an awaitable type that can be co_await'ed in coroutines,
 * with the result being a tuple containing error_code and return values.
 */
template <typename... Types>
using AwaitableResult = net::awaitable<ReturnTuple<Types...>>;

/**
 * @brief Promise type wrapper for async operations
 *
 * Wraps a handler and provides a setValues method to complete the promise
 * with the result values. Uses concepts to ensure type safety.
 */
template <typename Handler, typename... Types>
    requires std::invocable<Handler, ReturnTuple<Types...>>
struct PromiseType
{
    mutable std::decay_t<Handler> promise;

    void setValues(Types... values) const
    {
        promise(ReturnTuple<Types...>{std::move(values)...});
    }
};

/**
 * @brief Creates an awaitable handler wrapper for async operations in
 * coroutines.
 *
 * This function wraps a handler function to make it compatible with C++20
 * coroutines and Boost.Asio's awaitable pattern. It automatically manages
 * error_code handling based on the return type signature using concepts.
 *
 * @tparam Ret... The return types expected from the async operation
 * @tparam HandlerFunc The type of the handler function to wrap
 * @param h The handler function that will be called with a promise object
 *
 * @return A lambda that returns an AwaitableResult which can be co_await'ed
 *
 * The function uses concepts at compile-time to determine if error_code is
 * already part of the return signature:
 * - If Ret... already starts with error_code: Uses the types as-is
 * - If Ret... does NOT start with error_code: Automatically prepends it
 *
 * Usage Examples:
 *
 * Example 1: Handler with error_code already in signature
 * @code
 * auto handler = make_awaitable_handler<boost::system::error_code, int>(
 *     [](auto promise) {
 *         // Async operation that calls promise.setValues(error_code, result)
 *         promise.setValues(boost::system::error_code{}, 42);
 *     }
 * );
 * auto [ec, value] = co_await handler();
 * @endcode
 *
 * Example 2: Handler without error_code (automatically prepended)
 * @code
 * auto handler = make_awaitable_handler<std::string>(
 *     [](auto promise) {
 *         // error_code is automatically added as first parameter
 *         promise.setValues(boost::system::error_code{}, "result");
 *     }
 * );
 * auto [ec, str] = co_await handler();
 * @endcode
 *
 * Example 3: Multiple return values
 * @code
 * auto handler = make_awaitable_handler<int, std::string, bool>(
 *     [](auto promise) {
 *         promise.setValues(boost::system::error_code{}, 42, "hello", true);
 *     }
 * );
 * auto [ec, num, str, flag] = co_await handler();
 * @endcode
 */

/**
 * @brief Helper function to invoke handler with appropriate promise type.
 *
 * Uses concepts and if constexpr to determine at compile-time whether
 * error_code is already present in the return types and creates the
 * appropriate PromiseType:
 * - If error_code is first in Ret...: Creates PromiseType<Handler, Ret...>
 * - Otherwise: Creates PromiseType<Handler, error_code, Ret...>
 *
 * @tparam Ret... The return types for the async operation
 * @tparam Handler The handler type from async_initiate
 * @tparam HandlerFunc The user's handler function type
 */
template <typename... Ret, typename Handler, typename HandlerFunc>
void invoke_handler_with_promise(Handler&& handler, HandlerFunc&& h)
{
    if constexpr (StartsWithErrorCode<Ret...>)
    {
        // error_code already present - use Ret... as-is
        PromiseType<decltype(handler), Ret...> promise{std::move(handler)};
        h(std::move(promise));
    }
    else
    {
        // error_code not present - prepend it to Ret...
        PromiseType<decltype(handler), boost::system::error_code, Ret...>
            promise{std::move(handler)};
        h(std::move(promise));
    }
}
template <typename... Ret, typename HandlerFunc>
auto make_awaitable_handler(HandlerFunc&& h)
{
    return [h = std::move(h)]() -> AwaitableResult<Ret...> {
        co_return co_await net::async_initiate<
            const net::use_awaitable_t<>,
            ReturnTuple<Ret...>(ReturnTuple<Ret...>)>(
            [h = std::move(h)](auto handler) {
                invoke_handler_with_promise<Ret...>(std::move(handler),
                                                    std::move(h));
            },
            net::use_awaitable);
    };
}
} // namespace NSNAME
