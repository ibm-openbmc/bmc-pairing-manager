#pragma once
#include "make_awaitable.hpp"
#include "socket_streams.hpp"

#include <concepts>
#include <string>
#include <string_view>
namespace NSNAME
{
template <typename Accepter, typename Router>
class TcpServer
{
  public:
    using Streamer = TimedStreamer<typename Accepter::stream_type>;
    TcpServer(net::any_io_executor io_context, Accepter& accepter,
              Router& router) :
        context(io_context), acceptor(accepter), router(router)
    {
        start_accept();
    }
    ~TcpServer()
    {
        acceptor.cancel();
    }
    auto getLocalEndpoint() const
    {
        return acceptor.getLocalEndpoint();
    }

  private:
    void start_accept()
    {
        acceptor.accept([this](auto&& socket) {
            boost::asio::co_spawn(context, handle_client(socket),
                                  boost::asio::detached);
            start_accept();
        });
    }
    template <typename Socket>
    boost::asio::awaitable<void> handle_client(
        std::shared_ptr<boost::asio::ssl::stream<Socket>> socket)
    {
        // Perform SSL handshake with error handling
        boost::system::error_code ec;
        co_await socket->async_handshake(
            boost::asio::ssl::stream_base::server,
            boost::asio::redirect_error(boost::asio::use_awaitable, ec));
        if (ec)
        {
            // SSL handshake failed, log and return gracefully
            co_return;
        }
        if constexpr (requires { router(socket); })
        {
            co_await router(socket);
        }
        else
        {
            auto timer = std::make_shared<net::steady_timer>(context);
            co_await router(Streamer(socket, timer));
            timer->cancel(); // cancel any pending timer
        }
        co_await socket->async_shutdown(boost::asio::use_awaitable);
    }

    net::any_io_executor context;
    Accepter& acceptor;
    Router& router;
};
} // namespace NSNAME
