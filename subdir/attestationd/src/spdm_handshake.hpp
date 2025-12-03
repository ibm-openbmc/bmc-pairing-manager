#pragma once
#include "certificate_exchange.hpp"
#include "measurements.hpp"

#include <openssl/evp.h>
#include <openssl/pem.h>
#include <openssl/sha.h>

#include <ranges>
using namespace NSNAME;
static constexpr auto SPDM_BEGIN_REQ = "SPDM_BEGIN_REQ";
static constexpr auto SPDM_BEGIN_READY = "SPDM_BEGIN_READY";
static constexpr auto MEASUREMENT_REQ_EVENT = "MEASUREMENT_REQ_EVENT";
static constexpr auto MEASUREMENT_RES_EVENT = "MEASUREMENT_RES_EVENT";
static constexpr auto MEASUREMENT_DONE_EVENT = "MEASUREMENT_DONE_EVENT";
struct SpdmHandler
{
    MeasurementTaker measurementTaker;
    MeasurementVerifier measurementVerifier;
    EventQueue& eventQueue;
    net::io_context& ioContext;
    std::vector<std::string> toMeasure;
    using MeasurementResult = std::map<std::string, bool>;
    using SPDM_FINISH_HANDLER = std::function<net::awaitable<void>(bool, bool)>;
    SPDM_FINISH_HANDLER onSpdmFinish;
    SpdmHandler(MeasurementTaker mesTaker, MeasurementVerifier mesVerifier,
                EventQueue& eventQueue, net::io_context& ioContext) :
        measurementTaker(std::move(mesTaker)),
        measurementVerifier(std::move(mesVerifier)), eventQueue(eventQueue),
        ioContext(ioContext)
    {
        eventQueue.addEventProvider(
            SPDM_BEGIN_REQ,
            std::bind_front(&SpdmHandler::spdmBeginHandler, this));
        eventQueue.addEventConsumer(
            SPDM_BEGIN_REQ,
            std::bind_front(&SpdmHandler::spdmBeginConsumer, this));
    }

    void setSpdmFinishHandler(SPDM_FINISH_HANDLER handler)
    {
        onSpdmFinish = std::move(handler);
    }
    net::awaitable<void> finish(bool status, bool responder)
    {
        LOG_INFO("SPDM Handshake finished with status: {}", status);
        if (onSpdmFinish)
        {
            co_await onSpdmFinish(status, responder);
        }
        co_return;
    }
    void setEndPoint(const std::string& ip, const std::string& port)
    {
        eventQueue.setQueEndPoint(ip, port);
    }
    SpdmHandler(const SpdmHandler&) = delete;
    SpdmHandler& operator=(const SpdmHandler&) = delete;
    SpdmHandler(SpdmHandler&& o) = delete;
    SpdmHandler& addToMeasure(const std::string& exePath)
    {
        toMeasure.push_back(exePath);
        return *this;
    }

    net::awaitable<boost::system::error_code> spdmBeginConsumer(
        Streamer streamer, const std::string& eventReplay)
    {
        LOG_DEBUG("Received event: {}", eventReplay);
        auto [id, body] = parseEvent(eventReplay);
        if (id == SPDM_BEGIN_REQ)
        {
            auto [ec, size] = co_await sendHeader(
                streamer, makeEvent(SPDM_BEGIN_READY, "SPDM Begin Ready"));
            if (ec)
            {
                co_await finish(false, true);
                LOG_ERROR("Failed to send SPDM Begin Ready: {}", ec.message());
                co_return ec;
            }
            std::string measreq;
            std::tie(ec, measreq) = co_await readHeader(streamer);
            if (ec)
            {
                co_await finish(false, true);
                LOG_ERROR("Failed to read event: {}", ec.message());
                co_return ec;
            }
            auto success =
                co_await processMeasurementRequest(streamer, measreq);
            if (!success)
            {
                co_await finish(false, true);
                LOG_ERROR("Failed to make  measurement response");
                co_return boost::system::error_code{};
            }
            LOG_INFO("SPDM measurement completed successfully");
            LOG_INFO("Waiting for certificate exchange");
            auto exchanged = co_await waitForCertExchange(streamer);
            if (!exchanged)
            {
                LOG_ERROR("Failed to exchange certificates");
            }
            co_await finish(exchanged, true);
            co_return boost::system::error_code{};
        }
    }
    net::awaitable<boost::system::error_code> spdmBeginHandler(
        Streamer streamer, const std::string& event)
    {
        LOG_DEBUG("Received event: {}", event);
        auto [id, body] = parseEvent(event);
        if (id == SPDM_BEGIN_READY)
        {
            auto success = co_await startMeasurement(streamer);
            if (success)
            {
                LOG_INFO("Starting Certificate Exchange");
                auto success = co_await exchangeCertificate(streamer);
                if (success)
                {
                    co_await finish(success, false);
                    co_return boost::system::error_code{};
                }
            }
            co_await finish(false, false);
            co_return boost::system::error_code{};
        }
        LOG_ERROR("Failed to start SPDM measurement: {}", event);
        co_return boost::system::error_code{};
    }
    net::awaitable<bool> processMeasurementRequest(
        Streamer streamer, const std::string& eventReplay)
    {
        std::string event = eventReplay;
        auto [id, body] = parseEvent(event);
        while (id == MEASUREMENT_REQ_EVENT)
        {
            LOG_DEBUG("Received measurement Req event: {}", body);
            auto jsonBody = nlohmann::json::parse(body);
            auto bin = jsonBody.value("bin", std::string{});
            nlohmann::json response;
            response["bin"] = bin;
            if (bin.empty())
            {
                response["measurement"] = "NULL";
                LOG_ERROR("No executable path provided in the event body.");
            }
            else
            {
                LOG_DEBUG("Computing measurement for: {}", bin);
                auto measurement = measurementTaker(bin);
                response["measurement"] = measurement;
            }
            auto replay = makeEvent(MEASUREMENT_RES_EVENT, response.dump());
            auto [ec, size] = co_await sendHeader(streamer, replay);
            if (ec)
            {
                LOG_ERROR("Failed to send measurement event: {}", ec.message());
                co_return false;
            }
            std::tie(ec, event) = co_await readHeader(streamer);
            if (ec)
            {
                LOG_ERROR("Failed to read response: {}", ec.message());
                co_return false;
            }
            std::tie(id, body) = parseEvent(event);
        }
        if (id == MEASUREMENT_DONE_EVENT)
        {
            LOG_DEBUG("Measurement done event received: {}", body);
            auto jsonBody = nlohmann::json::parse(body);
            auto status = jsonBody.value("status", false);
            if (status)
            {
                LOG_DEBUG("All measurements passed successfully.");
                co_return true;
            }
            co_return false;
        }
        LOG_ERROR("Measurement Failed {}", event);
        co_return false;
    }

    void processMeasurement(const std::string& measurement,
                            const std::string& exePath,
                            MeasurementResult& measurements)
    {
        LOG_DEBUG("measurement response for: {}", exePath);
        if (!measurement.empty())
        {
            nlohmann::json jsonMeasurement;
            auto result = measurementVerifier(exePath, measurement);
            LOG_DEBUG("Verification result for measurement: {}",
                      result ? "Success" : "Failure");
            measurements[exePath] = result;
            return;
        }

        measurements[exePath] = false;
    }
    net::awaitable<bool> startMeasurement(Streamer streamer)
    {
        MeasurementResult measurements;
        measurements = MeasurementResult{};
        for (const auto& exePath : toMeasure)
        {
            nlohmann::json request;
            request["bin"] = exePath;
            auto [ec, size] = co_await sendHeader(
                streamer, makeEvent(MEASUREMENT_REQ_EVENT, request.dump()));
            std::string measurement;
            std::tie(ec, measurement) = co_await readHeader(streamer);
            if (ec)
            {
                LOG_ERROR("Failed to read measurement response: {}",
                          ec.message());
                co_return false;
            }
            auto [id, body] = parseEvent(measurement);
            if (id == MEASUREMENT_RES_EVENT)
            {
                LOG_DEBUG("Received measurement response for: {}", exePath);
                auto jsonBody = nlohmann::json::parse(body);
                measurement = jsonBody.value("measurement", std::string{});
                processMeasurement(measurement, exePath, measurements);
            }
        }
        bool success =
            std::all_of(measurements.begin(), measurements.end(),
                        [](const auto& pair) { return pair.second; });
        if (!co_await sendMeasurementDone(streamer, success))
        {
            LOG_ERROR("Failed to send measurement Done");
            co_return false;
        }
        co_return success;
    }
    net::awaitable<bool> sendMeasurementDone(Streamer streamer, bool success)
    {
        nlohmann::json jsonBody;
        jsonBody["status"] = success;
        auto replay = makeEvent(MEASUREMENT_DONE_EVENT, jsonBody.dump());
        auto [ec, size] = co_await sendHeader(streamer, replay);
        if (ec)
        {
            LOG_ERROR("Failed to send measurement Done: {}", ec.message());
            co_return false;
        }
        LOG_INFO("Measurement Done sent successfully");
        co_return true;
    }

    net::awaitable<bool> exchangeCertificate(Streamer streamer)
    {
        CertificateExchanger exchanger(eventQueue, ioContext);
        co_return co_await exchanger.exchange(streamer);
    }
    net::awaitable<bool> waitForCertExchange(Streamer streamer)
    {
        CertificateExchanger exchanger(eventQueue, ioContext);
        co_return co_await exchanger.waitForExchange(streamer);
    }
    void startHandshake()
    {
        LOG_DEBUG("Starting SPDM handshake");
        nlohmann::json jsonBody;
        jsonBody["bin"] = "spdm_handshake";
        auto replay = makeEvent(SPDM_BEGIN_REQ, jsonBody.dump());
        eventQueue.addEvent(replay);
    }
};
