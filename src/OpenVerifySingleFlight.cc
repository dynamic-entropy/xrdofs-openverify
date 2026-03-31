#include "OpenVerifySingleFlight.hh"

OpenVerifySingleFlight::Result OpenVerifySingleFlight::Run(const std::string& key, const std::function<Result()>& fn) {
    std::shared_ptr<InFlight> in_flight;
    bool leader = false;
    {
        std::lock_guard<std::mutex> map_lock(m_map_mutex);
        auto existing = m_in_flight_map.find(key);
        if (existing == m_in_flight_map.end()) {
            in_flight = std::make_shared<InFlight>();
            m_in_flight_map.emplace(key, in_flight);
            leader = true;
        } else {
            in_flight = existing->second;
        }
    }

    if (leader) {
        Result result;
        try {
            // run the lambda 
            result = fn ? fn() : Result{false, "openverify_noop"};
        } catch (...) {
            result = Result{false, "openverify_exception"};
        }

        {
            std::lock_guard<std::mutex> lk(in_flight->mtx);
            in_flight->result = result;
            in_flight->done = true;
        }
        in_flight->cv.notify_all();

        std::lock_guard<std::mutex> erase_lock(m_map_mutex);
        auto it = m_in_flight_map.find(key);
        if (it != m_in_flight_map.end() && it->second == in_flight) {
            m_in_flight_map.erase(it);
        }

        return result;
    }

    std::unique_lock<std::mutex> lk(in_flight->mtx);
    in_flight->cv.wait(lk, [&in_flight] { return in_flight->done; });
    return in_flight->result;
}
