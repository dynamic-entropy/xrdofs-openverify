#pragma once

#include <condition_variable>
#include <functional>
#include <memory>
#include <mutex>
#include <string>
#include <unordered_map>

class OpenVerifySingleFlight {
   public:
    struct Result {
        bool ok{false};
        std::string failure_reason;
    };

    OpenVerifySingleFlight() = default;
    OpenVerifySingleFlight(const OpenVerifySingleFlight&) = delete;
    OpenVerifySingleFlight& operator=(const OpenVerifySingleFlight&) = delete;

    // Runs `fn` once per key while in-flight; concurrent callers wait and receive the same result.
    Result Run(const std::string& key, const std::function<Result()>& fn);

   private:
    struct InFlight {
        std::mutex mtx;
        std::condition_variable cv;
        bool done{false};
        Result result;
    };

    mutable std::mutex m_map_mutex;
    std::unordered_map<std::string, std::shared_ptr<InFlight>> m_in_flight_map;
};
