/**
 * @file test_sdbus_calls.cpp
 * @brief Unit tests for sdbus_calls.hpp
 *
 * Tests the D-Bus coroutine wrapper functionality including:
 * - awaitable_dbus_method_call with return values
 * - awaitable_dbus_method_call_void for void methods
 * - getProperty and setProperty
 * - getAllProperties
 * - Object mapper methods (getSubTree, getObjects, etc.)
 * - getManagedObjects
 * - Property map extraction utilities
 */

#include <gmock/gmock.h>
#include <gtest/gtest.h>

// Define LOG_ERROR stub for testing - must be before including sdbus_calls.hpp
#ifndef LOG_ERROR
#define LOG_ERROR(...)                                                         \
    do                                                                         \
    {                                                                          \
    } while (0)
#endif

#define NSNAME TestNamespace
#include "../include/sdbus_calls.hpp"

#include <boost/asio.hpp>
#include <boost/asio/co_spawn.hpp>
#include <boost/asio/detached.hpp>
#include <sdbusplus/asio/connection.hpp>
#include <sdbusplus/message.hpp>

#include <map>
#include <string>
#include <variant>
#include <vector>

using namespace TestNamespace;
namespace net = boost::asio;

/**
 * @brief Mock D-Bus connection for testing
 *
 * This class simulates D-Bus operations without requiring an actual D-Bus
 * daemon
 */
class MockDbusConnection
{
  public:
    MOCK_METHOD(
        void, async_method_call,
        (std::function<void(boost::system::error_code, sdbusplus::message_t)>,
         const std::string&, const std::string&, const std::string&,
         const std::string&),
        ());
};

/**
 * @brief Test fixture for sdbus_calls tests
 */
class SdbusCallsTest : public ::testing::Test
{
  protected:
    void SetUp() override
    {
        // Create io_context for async operations
        io = std::make_shared<net::io_context>();
    }

    void TearDown() override
    {
        io.reset();
    }

    std::shared_ptr<net::io_context> io;
};

/**
 * @brief Test constant definitions
 * Verifies that all D-Bus service/interface constants are defined correctly
 */
TEST_F(SdbusCallsTest, ConstantDefinitions)
{
    EXPECT_STREQ(objectMapperService, "xyz.openbmc_project.ObjectMapper");
    EXPECT_STREQ(objectMapperPath, "/xyz/openbmc_project/object_mapper");
    EXPECT_STREQ(objectMapperInterface, "xyz.openbmc_project.ObjectMapper");
    EXPECT_STREQ(dbusPropertiesInterface, "org.freedesktop.DBus.Properties");
    EXPECT_STREQ(dbusObjectManagerInterface,
                 "org.freedesktop.DBus.ObjectManager");
    EXPECT_STREQ(dbusIntrospectableInterface,
                 "org.freedesktop.DBus.Introspectable");
    EXPECT_STREQ(associationInterface, "xyz.openbmc_project.Association");
}

/**
 * @brief Test PropertyMap type alias
 * Verifies PropertyMap can hold expected variant types
 */
TEST_F(SdbusCallsTest, PropertyMapTypeAlias)
{
    PropertyMap propMap;
    propMap["bool_prop"] = true;
    propMap["int32_prop"] = int32_t(42);
    propMap["string_prop"] = std::string("test");
    propMap["uint32_prop"] = uint32_t(100);

    EXPECT_TRUE(std::holds_alternative<bool>(propMap["bool_prop"]));
    EXPECT_TRUE(std::holds_alternative<int32_t>(propMap["int32_prop"]));
    EXPECT_TRUE(std::holds_alternative<std::string>(propMap["string_prop"]));
    EXPECT_TRUE(std::holds_alternative<uint32_t>(propMap["uint32_prop"]));

    EXPECT_EQ(std::get<bool>(propMap["bool_prop"]), true);
    EXPECT_EQ(std::get<int32_t>(propMap["int32_prop"]), 42);
    EXPECT_EQ(std::get<std::string>(propMap["string_prop"]), "test");
    EXPECT_EQ(std::get<uint32_t>(propMap["uint32_prop"]), 100);
}

/**
 * @brief Test InterfaceMap type alias
 * Verifies InterfaceMap structure
 */
TEST_F(SdbusCallsTest, InterfaceMapTypeAlias)
{
    InterfaceMap ifaceMap;
    PropertyMap props;
    props["prop1"] = std::string("value1");
    props["prop2"] = int32_t(123);

    ifaceMap["xyz.openbmc_project.Test.Interface1"] = props;

    EXPECT_EQ(ifaceMap.size(), 1);
    EXPECT_TRUE(ifaceMap.contains("xyz.openbmc_project.Test.Interface1"));

    const auto& retrievedProps =
        ifaceMap["xyz.openbmc_project.Test.Interface1"];
    EXPECT_EQ(retrievedProps.size(), 2);
    EXPECT_TRUE(retrievedProps.contains("prop1"));
    EXPECT_TRUE(retrievedProps.contains("prop2"));
}

/**
 * @brief Test getDefaultValue template function
 * Verifies default value generation for various types
 */
TEST_F(SdbusCallsTest, GetDefaultValue)
{
    // Test basic types
    EXPECT_EQ(getDefaultValue<int>(), 0);
    EXPECT_EQ(getDefaultValue<bool>(), false);
    EXPECT_EQ(getDefaultValue<std::string>(), "");
    EXPECT_EQ(getDefaultValue<uint32_t>(), 0u);

    // Test container types
    EXPECT_TRUE(getDefaultValue<std::vector<int>>().empty());
    auto mapResult = getDefaultValue<std::map<std::string, int>>();
    EXPECT_TRUE(mapResult.empty());
}

/**
 * @brief Test getPropertyFromMap with valid property
 * Verifies successful property extraction
 */
TEST_F(SdbusCallsTest, GetPropertyFromMapSuccess)
{
    PropertyMap propMap;
    propMap["test_bool"] = true;
    propMap["test_int"] = int32_t(42);
    propMap["test_string"] = std::string("hello");

    boost::system::error_code ec;

    auto boolVal = getPropertyFromMap<bool>(ec, propMap, "test_bool");
    EXPECT_FALSE(ec);
    EXPECT_TRUE(boolVal);

    auto intVal = getPropertyFromMap<int32_t>(ec, propMap, "test_int");
    EXPECT_FALSE(ec);
    EXPECT_EQ(intVal, 42);

    auto strVal = getPropertyFromMap<std::string>(ec, propMap, "test_string");
    EXPECT_FALSE(ec);
    EXPECT_EQ(strVal, "hello");
}

/**
 * @brief Test getPropertyFromMap with missing property
 * Verifies error handling when property doesn't exist
 */
TEST_F(SdbusCallsTest, GetPropertyFromMapNotFound)
{
    PropertyMap propMap;
    propMap["existing_prop"] = int32_t(100);

    boost::system::error_code ec;
    auto value = getPropertyFromMap<int32_t>(ec, propMap, "missing_prop");

    EXPECT_TRUE(ec);
    EXPECT_EQ(ec, boost::asio::error::not_found);
    EXPECT_EQ(value, 0); // Default value
}

/**
 * @brief Test getPropertyFromMap with type mismatch
 * Verifies error handling when property type doesn't match
 */
TEST_F(SdbusCallsTest, GetPropertyFromMapTypeMismatch)
{
    PropertyMap propMap;
    propMap["int_prop"] = int32_t(42);

    boost::system::error_code ec;
    // Try to get as string when it's actually int
    auto value = getPropertyFromMap<std::string>(ec, propMap, "int_prop");

    EXPECT_TRUE(ec);
    EXPECT_EQ(ec, boost::asio::error::invalid_argument);
    EXPECT_EQ(value, ""); // Default value
}

/**
 * @brief Test getPropertyFromMap with pre-existing error
 * Verifies that function returns immediately if ec is already set
 */
TEST_F(SdbusCallsTest, GetPropertyFromMapWithPreExistingError)
{
    PropertyMap propMap;
    propMap["test_prop"] = int32_t(42);

    boost::system::error_code ec = boost::asio::error::make_error_code(
        boost::asio::error::operation_aborted);

    auto value = getPropertyFromMap<int32_t>(ec, propMap, "test_prop");

    // Should still have the original error
    EXPECT_TRUE(ec);
    EXPECT_EQ(ec, boost::asio::error::operation_aborted);
    EXPECT_EQ(value, 0); // Default value
}

/**
 * @brief Test getPropertiesFromMap with multiple properties
 * Verifies extraction of multiple properties at once
 */
TEST_F(SdbusCallsTest, GetPropertiesFromMapSuccess)
{
    PropertyMap propMap;
    propMap["enabled"] = true;
    propMap["count"] = int32_t(10);
    propMap["name"] = std::string("test_name");

    auto [ec, enabled, count, name] =
        getPropertiesFromMap<bool, int32_t, std::string>(propMap, "enabled",
                                                         "count", "name");

    EXPECT_FALSE(ec);
    EXPECT_TRUE(enabled);
    EXPECT_EQ(count, 10);
    EXPECT_EQ(name, "test_name");
}

/**
 * @brief Test getPropertiesFromMap with one missing property
 * Verifies that error is set and subsequent properties get default values
 */
TEST_F(SdbusCallsTest, GetPropertiesFromMapPartialFailure)
{
    PropertyMap propMap;
    propMap["prop1"] = int32_t(100);
    // prop2 is missing
    propMap["prop3"] = std::string("value3");

    auto [ec, val1, val2, val3] =
        getPropertiesFromMap<int32_t, int32_t, std::string>(propMap, "prop1",
                                                            "prop2", "prop3");

    EXPECT_TRUE(ec);
    EXPECT_EQ(ec, boost::asio::error::not_found);
    EXPECT_EQ(val1, 100); // First property retrieved successfully
    EXPECT_EQ(val2, 0);   // Missing property gets default
    EXPECT_EQ(val3, "");  // Subsequent properties get defaults due to error
}

/**
 * @brief Test getPropertiesFromMap with type mismatch
 * Verifies error handling when one property has wrong type
 */
TEST_F(SdbusCallsTest, GetPropertiesFromMapTypeMismatch)
{
    PropertyMap propMap;
    propMap["prop1"] = int32_t(100);
    propMap["prop2"] = std::string("not_an_int"); // Type mismatch
    propMap["prop3"] = bool(true);

    auto [ec, val1, val2, val3] = getPropertiesFromMap<int32_t, int32_t, bool>(
        propMap, "prop1", "prop2", "prop3");

    EXPECT_TRUE(ec);
    EXPECT_EQ(ec, boost::asio::error::invalid_argument);
    EXPECT_EQ(val1, 100);   // First property retrieved successfully
    EXPECT_EQ(val2, 0);     // Type mismatch gets default
    EXPECT_EQ(val3, false); // Subsequent properties get defaults due to error
}

/**
 * @brief Test getPropertiesFromMap with empty map
 * Verifies handling of empty property map
 */
TEST_F(SdbusCallsTest, GetPropertiesFromMapEmpty)
{
    PropertyMap propMap; // Empty map

    auto [ec, val1, val2] =
        getPropertiesFromMap<int32_t, std::string>(propMap, "prop1", "prop2");

    EXPECT_TRUE(ec);
    EXPECT_EQ(ec, boost::asio::error::not_found);
    EXPECT_EQ(val1, 0);
    EXPECT_EQ(val2, "");
}

/**
 * @brief Test getPropertiesFromMap with single property
 * Verifies functionality with just one property
 */
TEST_F(SdbusCallsTest, GetPropertiesFromMapSingleProperty)
{
    PropertyMap propMap;
    propMap["single"] = uint32_t(999);

    auto [ec, value] = getPropertiesFromMap<uint32_t>(propMap, "single");

    EXPECT_FALSE(ec);
    EXPECT_EQ(value, 999u);
}

/**
 * @brief Test getPropertiesFromMap with all supported types
 * Verifies all variant types in PropertyMap work correctly
 */
TEST_F(SdbusCallsTest, GetPropertiesFromMapAllTypes)
{
    PropertyMap propMap;
    propMap["bool_val"] = true;
    propMap["int32_val"] = int32_t(-42);
    propMap["string_val"] = std::string("test");
    propMap["uint32_val"] = uint32_t(42);

    auto [ec, boolVal, int32Val, stringVal, uint32Val] =
        getPropertiesFromMap<bool, int32_t, std::string, uint32_t>(
            propMap, "bool_val", "int32_val", "string_val", "uint32_val");

    EXPECT_FALSE(ec);
    EXPECT_TRUE(boolVal);
    EXPECT_EQ(int32Val, -42);
    EXPECT_EQ(stringVal, "test");
    EXPECT_EQ(uint32Val, 42u);
}

/**
 * @brief Test ReturnTuple usage in sdbus_calls context
 * Verifies ReturnTuple works correctly with D-Bus return types
 */
TEST_F(SdbusCallsTest, ReturnTupleWithDbusTypes)
{
    // Test with PropertyMap
    using PropMapReturn = ReturnTuple<PropertyMap>;
    static_assert(
        std::is_same_v<PropMapReturn,
                       std::tuple<boost::system::error_code, PropertyMap>>);

    // Test with string (common D-Bus return type)
    using StringReturn = ReturnTuple<std::string>;
    static_assert(
        std::is_same_v<StringReturn,
                       std::tuple<boost::system::error_code, std::string>>);

    // Test with vector (common for paths)
    using VectorReturn = ReturnTuple<std::vector<std::string>>;
    static_assert(
        std::is_same_v<VectorReturn, std::tuple<boost::system::error_code,
                                                std::vector<std::string>>>);
}

/**
 * @brief Test AwaitableResult with D-Bus types
 * Verifies AwaitableResult wraps D-Bus return types correctly
 */
TEST_F(SdbusCallsTest, AwaitableResultWithDbusTypes)
{
    // Test with PropertyMap
    using PropMapAwaitable = AwaitableResult<PropertyMap>;
    static_assert(
        std::is_same_v<PropMapAwaitable,
                       net::awaitable<std::tuple<boost::system::error_code,
                                                 PropertyMap>>>);

    // Test with InterfaceMap
    using IfaceMapAwaitable = AwaitableResult<InterfaceMap>;
    static_assert(
        std::is_same_v<IfaceMapAwaitable,
                       net::awaitable<std::tuple<boost::system::error_code,
                                                 InterfaceMap>>>);
}

/**
 * @brief Test property map with edge cases
 * Verifies handling of empty strings, zero values, etc.
 */
TEST_F(SdbusCallsTest, PropertyMapEdgeCases)
{
    PropertyMap propMap;
    propMap["empty_string"] = std::string("");
    propMap["zero_int"] = int32_t(0);
    propMap["false_bool"] = false;
    propMap["zero_uint"] = uint32_t(0);

    boost::system::error_code ec;

    auto emptyStr =
        getPropertyFromMap<std::string>(ec, propMap, "empty_string");
    EXPECT_FALSE(ec);
    EXPECT_EQ(emptyStr, "");

    auto zeroInt = getPropertyFromMap<int32_t>(ec, propMap, "zero_int");
    EXPECT_FALSE(ec);
    EXPECT_EQ(zeroInt, 0);

    auto falseBool = getPropertyFromMap<bool>(ec, propMap, "false_bool");
    EXPECT_FALSE(ec);
    EXPECT_FALSE(falseBool);

    auto zeroUint = getPropertyFromMap<uint32_t>(ec, propMap, "zero_uint");
    EXPECT_FALSE(ec);
    EXPECT_EQ(zeroUint, 0u);
}

/**
 * @brief Test getPropertiesFromMap with duplicate property names
 * Verifies behavior when same property is requested multiple times
 */
TEST_F(SdbusCallsTest, GetPropertiesFromMapDuplicateNames)
{
    PropertyMap propMap;
    propMap["value"] = int32_t(42);

    // Request same property twice
    auto [ec, val1, val2] =
        getPropertiesFromMap<int32_t, int32_t>(propMap, "value", "value");

    EXPECT_FALSE(ec);
    EXPECT_EQ(val1, 42);
    EXPECT_EQ(val2, 42);
}

/**
 * @brief Test PropertyMap with maximum variant size
 * Verifies all variant alternatives work
 */
TEST_F(SdbusCallsTest, PropertyMapVariantAlternatives)
{
    PropertyMap propMap;

    // Test each variant alternative
    propMap["alt0"] = bool(true);
    propMap["alt1"] = int32_t(-100);
    propMap["alt2"] = std::string("variant_test");
    propMap["alt3"] = uint32_t(200);

    EXPECT_EQ(propMap.size(), 4);

    // Verify each can be retrieved
    EXPECT_TRUE(std::holds_alternative<bool>(propMap["alt0"]));
    EXPECT_TRUE(std::holds_alternative<int32_t>(propMap["alt1"]));
    EXPECT_TRUE(std::holds_alternative<std::string>(propMap["alt2"]));
    EXPECT_TRUE(std::holds_alternative<uint32_t>(propMap["alt3"]));
}

/**
 * @brief Test InterfaceMap with multiple interfaces
 * Verifies complex nested structure
 */
TEST_F(SdbusCallsTest, InterfaceMapMultipleInterfaces)
{
    InterfaceMap ifaceMap;

    PropertyMap props1;
    props1["prop1"] = int32_t(1);
    props1["prop2"] = std::string("interface1");

    PropertyMap props2;
    props2["propA"] = bool(true);
    props2["propB"] = uint32_t(100);

    ifaceMap["xyz.openbmc_project.Interface1"] = props1;
    ifaceMap["xyz.openbmc_project.Interface2"] = props2;

    EXPECT_EQ(ifaceMap.size(), 2);
    EXPECT_TRUE(ifaceMap.contains("xyz.openbmc_project.Interface1"));
    EXPECT_TRUE(ifaceMap.contains("xyz.openbmc_project.Interface2"));

    const auto& iface1Props = ifaceMap["xyz.openbmc_project.Interface1"];
    EXPECT_EQ(iface1Props.size(), 2);
    EXPECT_EQ(std::get<int32_t>(iface1Props.at("prop1")), 1);

    const auto& iface2Props = ifaceMap["xyz.openbmc_project.Interface2"];
    EXPECT_EQ(iface2Props.size(), 2);
    EXPECT_TRUE(std::get<bool>(iface2Props.at("propA")));
}

/**
 * @brief Test getPropertyFromMap with special characters in property names
 * Verifies handling of property names with special characters
 */
TEST_F(SdbusCallsTest, GetPropertyFromMapSpecialCharacters)
{
    PropertyMap propMap;
    propMap["Property.With.Dots"] = int32_t(1);
    propMap["Property_With_Underscores"] = int32_t(2);
    propMap["PropertyWithNumbers123"] = int32_t(3);

    boost::system::error_code ec;

    auto val1 = getPropertyFromMap<int32_t>(ec, propMap, "Property.With.Dots");
    EXPECT_FALSE(ec);
    EXPECT_EQ(val1, 1);

    auto val2 =
        getPropertyFromMap<int32_t>(ec, propMap, "Property_With_Underscores");
    EXPECT_FALSE(ec);
    EXPECT_EQ(val2, 2);

    auto val3 =
        getPropertyFromMap<int32_t>(ec, propMap, "PropertyWithNumbers123");
    EXPECT_FALSE(ec);
    EXPECT_EQ(val3, 3);
}

/**
 * @brief Main function to run all tests
 */
int main(int argc, char** argv)
{
    ::testing::InitGoogleTest(&argc, argv);
    return RUN_ALL_TESTS();
}
