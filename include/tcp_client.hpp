#pragma once
#include "make_awaitable.hpp"
#include "socket_streams.hpp"

#include <boost/asio.hpp>
#include <boost/asio/ssl.hpp>
#include <boost/asio/steady_timer.hpp>
#include <boost/beast.hpp>
#include <boost/system/error_code.hpp>

#include <iostream>
#include <string>
#include <utility>

namespace NSNAME
{
namespace net = boost::asio;
namespace ssl = boost::asio::ssl;
using tcp = boost::asio::ip::tcp;

inline AwaitableResult<net::ip::tcp::resolver::results_type> awaitable_resolve(
    typename net::ip::tcp::resolver& resolver, const std::string& host,
    const std::string& port)
{
    auto h = make_awaitable_handler<net::ip::tcp::resolver::results_type>(
        [&](auto promise) {
            // resolver.async_resolve(
            //     host, port,
            //     [handler = std::move(handler)](
            //         boost::system::error_code ec,
            //         net::ip::tcp::resolver::results_type results) mutable {
            //         handler(ec, std::move(results));
            //     });
            boost::system::error_code ec;
            auto results = resolver.resolve(host, port, ec);
            promise.setValues(ec, results);
        });
    co_return co_await h();
}
class TcpClient
{
  public:
    TcpClient(net::any_io_executor io_context, ssl::context& ssl_context) :
        resolver_(io_context),
        stream_(std::make_shared<ssl::stream<tcp::socket>>(io_context,
                                                           ssl_context)),
        timer_(std::make_shared<net::steady_timer>(io_context))
    {}
    ~TcpClient()
    {
        timer_->cancel();
    }

    net::awaitable<boost::system::error_code> connect(const std::string& host,
                                                      const std::string& port)
    {
        auto [ec, results] = co_await awaitable_resolve(resolver_, host, port);
        if (ec)
        {
            LOG_ERROR("Error resolving {}:{}. Error: {}", host, port,
                      ec.message());
            co_return ec;
        }

        TimedStreamer streamer(stream_, timer_);
        streamer.setTimeout(30s);
        co_await net::async_connect(
            stream_->next_layer(), results,
            net::redirect_error(net::use_awaitable, ec));
        if (ec)
        {
            LOG_ERROR("Error connecting to {}:{}. Error: {}", host, port,
                      ec.message());
            co_return ec;
        }

        // Configure TCP keepalive to detect dead connections quickly
        configureSocketKeepalive(stream_->lowest_layer());
        streamer.setTimeout(30s);
        co_await stream_->async_handshake(
            ssl::stream_base::client,
            net::redirect_error(net::use_awaitable, ec));
        if (ec)
        {
            LOG_ERROR("Error during SSL handshake with {}:{}. Error: {}", host,
                      port, ec.message());
        }
        co_return ec;
    }

    AwaitableResult<std::size_t> write(net::const_buffer data)
    {
        TimedStreamer streamer(stream_, timer_);
        co_return co_await streamer.write(data, true);
    }

    AwaitableResult<std::size_t> read(net::mutable_buffer buffer)
    {
        TimedStreamer streamer(stream_, timer_);
        co_return co_await streamer.read(buffer, true);
    }
    ssl::stream<tcp::socket>& stream()
    {
        return *stream_;
    }
    TimedStreamer<ssl::stream<tcp::socket>> streamer()
    {
        return TimedStreamer(stream_, timer_);
    }
    void close()
    {
        boost::system::error_code ec;
        stream_->next_layer().close(ec);
        if (ec)
        {
            LOG_ERROR("Error closing socket: {}", ec.message());
        }
    }
    bool isOpen() const
    {
        return stream_->lowest_layer().is_open();
    }

  private:
    tcp::resolver resolver_;
    std::shared_ptr<ssl::stream<tcp::socket>> stream_;
    std::shared_ptr<net::steady_timer> timer_;
};
} // namespace NSNAME
