#pragma once
#include "name_space.hpp"

#include <boost/asio.hpp>
#include <boost/asio/coroutine.hpp>
#include <boost/asio/ssl.hpp>
#include <boost/beast/core.hpp>
#include <boost/beast/http.hpp>
namespace NSNAME
{
namespace beast = boost::beast;
namespace http = beast::http;
namespace net = boost::asio;
namespace ssl = boost::asio::ssl;
using tcp = net::ip::tcp;
using unix_domain = net::local::stream_protocol;
using Response = http::response<http::string_body>;
using Request = http::request<http::string_body>;
} // namespace NSNAME
