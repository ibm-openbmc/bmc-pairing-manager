#pragma once
#include "logger.hpp"
#include "sdbus_calls.hpp"
#include "utilities.hpp"

#include <chrono>
#include <ranges>
namespace NSNAME
{
template <typename Handler, typename PropType>
concept WatchHandler =
    requires(Handler handler, const boost::system::error_code& ec,
             std::optional<PropType> result) {
        { handler(ec, result) } -> std::same_as<boost::asio::awaitable<void>>;
    };

template <typename Derived, typename PropType>
struct DbusWatcher : std::enable_shared_from_this<Derived>
{
    using PROPERTY_HANDLER =
        std::function<void(boost::system::error_code, PropType)>;
    PROPERTY_HANDLER propHandler;
    std::shared_ptr<sdbusplus::asio::connection> conn;
    std::optional<sdbuscompat::match_t> match;

    DbusWatcher() = delete;
    DbusWatcher(const DbusWatcher&) = delete;
    DbusWatcher& operator=(const DbusWatcher&) = delete;
    DbusWatcher(DbusWatcher&&) = delete;
    DbusWatcher& operator=(DbusWatcher&&) = delete;
    DbusWatcher(std::shared_ptr<sdbusplus::asio::connection> conn) : conn(conn)
    {}
    ~DbusWatcher()
    {
        LOG_DEBUG(
            "DbusWatcher destructor called - cleaning up match and handler");
        match.reset();
        propHandler = nullptr;
    }

    Derived& derived()
    {
        return static_cast<Derived&>(*this);
    }
    net::io_context& getIoContext()
    {
        return conn->get_io_context();
    }
    void startTimeout(net::steady_timer& timer, std::chrono::seconds timeout)
    {
        timer.expires_after(timeout);
        // Use weak_ptr to avoid use-after-free if watcher is destroyed
        // while timer callback is queued or executing
        std::weak_ptr<Derived> weak = derived().shared_from_this();
        timer.async_wait([weak](const boost::system::error_code& ec) {
            if (!ec)
            {
                if (auto self = weak.lock())
                {
                    self->cancelWatch();
                    LOG_ERROR(
                        "Timeout occurred while waiting for SPDM property change");
                }
            }
        });
    }
    net::awaitable<void> watch(auto callback)
    {
        boost::system::error_code ec{};
        auto h = makeWatchHandler();
        while (true)
        {
            LOG_DEBUG("Waiting for Dbus property change...");
            PropType res{};
            std::tie(ec, res) = co_await h();
            if (!ec)
            {
                LOG_DEBUG("Dbus property changed, notifying callback");
                co_await callback(ec, std::optional(std::move(res)));
                continue;
            }
            if (ec != boost::asio::error::no_such_device)
            {
                LOG_DEBUG(
                    "Unsupported type or some other error occurred: {} stopping watch",
                    ec.message());
                co_await callback(ec, std::nullopt);
                break;
            }
        }
        co_return;
    }
    net::awaitable<std::optional<PropType>> watchOnce(
        std::chrono::seconds timeout = std::chrono::seconds(1))
    {
        auto h = makeWatchHandler();
        net::steady_timer timer(conn->get_io_context());
        startTimeout(timer, timeout);
        auto [ec, res] = co_await h();
        timer.cancel(); // Cancel the timer if we got a response
        if (ec)
        {
            LOG_ERROR("Error in watching Dbus: {}", ec.message());
            co_return std::nullopt;
        }
        co_return std::optional(res);
    }
    template <typename... Args>
    static void watch(net::io_context& ctx,
                      std::shared_ptr<sdbusplus::asio::connection> conn,
                      WatchHandler<PropType> auto callback, Args... args)
    {
        auto watcher = Derived::create(conn, args...);
        net::co_spawn(
            ctx,
            [&ctx, watcher,
             callback = std::move(callback)]() -> net::awaitable<void> {
                co_await watcher->watch([&ctx, callback = std::move(callback)](
                                            const boost::system::error_code& ec,
                                            std::optional<PropType> val)
                                            -> net::awaitable<void> {
                    net::co_spawn(
                        ctx,
                        [ec, callback,
                         val = std::move(val)]() -> net::awaitable<void> {
                            LOG_DEBUG(
                                "Invoking user async callback for Dbus property change");
                            co_await callback(ec, std::move(val));
                        },
                        net::detached);
                    co_return;
                });
            },
            net::detached);
    }
    auto makeWatchHandler()
    {
        return make_awaitable_handler<PropType>([this](auto promise) {
            auto promise_ptr =
                std::make_shared<decltype(promise)>(std::move(promise));

            propHandler = [promise_ptr](const boost::system::error_code& ec,
                                        PropType value) {
                promise_ptr->setValues(ec, std::move(value));
            };
        });
    }
    void notifyChange(const boost::system::error_code& ec, PropType value)
    {
        if (propHandler)
        {
            propHandler(ec, std::move(value));
        }
    }
    void cancelWatch()
    {
        propHandler(boost::asio::error::operation_aborted, PropType{});
    }
    void removeMatch()
    {
        match.reset();
    }
};
template <typename TYPE>
struct DbusPropertyWatcher : public DbusWatcher<DbusPropertyWatcher<TYPE>, TYPE>
{
    using BASE = DbusWatcher<DbusPropertyWatcher<TYPE>, TYPE>;
    using PropType = TYPE;
    std::string propMatchRule;
    std::string propName;

  private:
    struct PrivateTag
    {};

  public:
    static std::shared_ptr<DbusPropertyWatcher<TYPE>> create(
        std::shared_ptr<sdbusplus::asio::connection> conn,
        const std::string& path, const std::string& intf,
        const std::string& prop)
    {
        auto watcher = std::make_shared<DbusPropertyWatcher<TYPE>>(
            PrivateTag{}, conn, path, intf, prop);
        watcher->addMatch();
        return watcher;
    }

    DbusPropertyWatcher(PrivateTag,
                        std::shared_ptr<sdbusplus::asio::connection> conn,
                        const std::string& path, const std::string& intf,
                        const std::string& prop) : BASE(conn), propName(prop)
    {
        propMatchRule =
            sdbusplus::bus::match::rules::propertiesChanged(path, intf);
    }

  private:
    void addMatch()
    {
        // Use weak_ptr to avoid use-after-free if watcher is destroyed
        // while D-Bus callback is queued or executing
        std::weak_ptr<DbusPropertyWatcher<TYPE>> weak =
            BASE::derived().shared_from_this();
        BASE::match.emplace(*BASE::conn, propMatchRule,
                            [weak](sdbusplus::message_t& msg) {
                                if (auto self = weak.lock())
                                {
                                    self->handlePropertyChange(msg);
                                }
                            });
    }
    void printChangedProperties(
        const std::map<std::string, std::variant<PropType>>& changedProperties)
    {
        for (const auto& [key, value] : changedProperties)
        {
            if (std::holds_alternative<PropType>(value))
            {
                auto val = std::get<PropType>(value);
                LOG_DEBUG("Changed Property: {} Value: {}", key, val);
            }
            else
            {
                LOG_DEBUG("Changed Property: {} Value: <non-string type>", key);
            }
        }
    }
    void handlePropertyChange(sdbusplus::message_t& msg)
    {
        std::string interfaceName;
        PropertyMap changedProperties;
        std::vector<std::string> invalidatedProperties;

        msg.read(interfaceName, changedProperties, invalidatedProperties);

        LOG_INFO("Properties changed on interface: {}", interfaceName);
        // printChangedProperties(changedProperties);
        auto [ec, ipaddress] =
            getPropertiesFromMap<PropType>(changedProperties, propName);

        if (ec && ec != boost::asio::error::not_found)
        {
            LOG_ERROR("Error getting property {}: {}", propName, ec.message());
            BASE::notifyChange(ec, PropType{});
            return;
        }
        LOG_DEBUG("Property {} changed: {}", propName, ipaddress);
        BASE::notifyChange(boost::system::error_code{}, ipaddress);
    }
};
template <typename TYPE>
struct DbusSignalWatcher : public DbusWatcher<DbusSignalWatcher<TYPE>, TYPE>
{
    using BASE = DbusWatcher<DbusSignalWatcher<TYPE>, TYPE>;
    using PropType = TYPE;

    std::string signalMatchRule;

  private:
    struct PrivateTag
    {};

  public:
    DbusSignalWatcher& nameOwnerChanged() noexcept
    {
        signalMatchRule = sdbusplus::bus::match::rules::nameOwnerChanged();
        addMatch();
        return *this;
    }

    constexpr auto interfacesAdded() noexcept
    {
        signalMatchRule = sdbusplus::bus::match::rules::interfacesAdded();
        addMatch();
        return *this;
    }

    constexpr auto interfacesRemoved() noexcept
    {
        signalMatchRule = sdbusplus::bus::match::rules::interfacesRemoved();
        addMatch();
        return *this;
    }

    constexpr auto interfacesAdded(std::string_view p) noexcept
    {
        signalMatchRule = sdbusplus::bus::match::rules::interfacesAdded(p);
        addMatch();
        return *this;
    }

    constexpr auto interfacesAddedAtPath(std::string_view p) noexcept
    {
        signalMatchRule =
            sdbusplus::bus::match::rules::interfacesAddedAtPath(p);
        addMatch();
        return *this;
    }

    constexpr auto interfacesRemoved(std::string_view p) noexcept
    {
        signalMatchRule = sdbusplus::bus::match::rules::interfacesRemoved(p);
        addMatch();
        return *this;
    }

    constexpr auto interfacesRemovedAtPath(std::string_view p) noexcept
    {
        signalMatchRule =
            sdbusplus::bus::match::rules::interfacesRemovedAtPath(p);
        addMatch();
        return *this;
    }
    template <typename... Args>
    static std::shared_ptr<DbusSignalWatcher<TYPE>> create(
        std::shared_ptr<sdbusplus::asio::connection> conn, Args&&... args)
    {
        auto watcher = std::make_shared<DbusSignalWatcher<TYPE>>(
            PrivateTag{}, conn, std::forward<Args>(args)...);
        watcher->addMatch();
        return watcher;
    }

    DbusSignalWatcher(PrivateTag,
                      std::shared_ptr<sdbusplus::asio::connection> conn,
                      const std::string& intf, const std::string& signal) :
        BASE(conn)

    {
        signalMatchRule = std::format(
            "type='signal',interface='{}',member='{}'", intf, signal);
    }
    DbusSignalWatcher(PrivateTag,
                      std::shared_ptr<sdbusplus::asio::connection> conn,
                      const std::string& matchRule) : BASE(conn)

    {
        signalMatchRule = matchRule;
    }
    DbusSignalWatcher(PrivateTag,
                      std::shared_ptr<sdbusplus::asio::connection> conn) :
        BASE(conn)
    {}

  private:
    void addMatch()
    {
        LOG_DEBUG("Adding signal match rule: {}", signalMatchRule);
        // Use weak_ptr to avoid use-after-free if watcher is destroyed
        // while D-Bus callback is queued or executing
        std::weak_ptr<DbusSignalWatcher<TYPE>> weak =
            BASE::derived().shared_from_this();
        BASE::match.emplace(*BASE::conn, signalMatchRule,
                            [weak](sdbusplus::message_t& msg) {
                                if (auto self = weak.lock())
                                {
                                    self->handleSignalChange(msg);
                                }
                            });
    }
    void handleSignalChange(sdbusplus::message_t& msg)
    {
        if constexpr (std::is_same_v<PropType, sdbusplus::message_t>)
        {
            LOG_DEBUG("Received Signal message");
            BASE::notifyChange(boost::system::error_code{}, std::move(msg));
            return;
        }
        else
        {
            PropType value;
            msg.read(value);
            LOG_DEBUG("Recieved Signal value {}", value);
            BASE::notifyChange(boost::system::error_code{}, value);
        }
    }
};

} // namespace NSNAME
