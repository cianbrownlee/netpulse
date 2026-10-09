#include "aggregate/observed_names.hpp"

namespace netpulse {

void ObservedNames::record(const DnsNameAnswer& answer) {
    for (const IpAddress& ip : answer.addresses) {
        auto [it, inserted] = names_.try_emplace(ip, answer.name);
        if (!inserted) {
            it->second = answer.name;  // the latest answer wins; no change to eviction order
            continue;
        }
        order_.push_back(ip);
        if (names_.size() > capacity_) {
            names_.erase(order_.front());
            order_.pop_front();
        }
    }
}

const std::string* ObservedNames::find(const IpAddress& ip) const {
    const auto it = names_.find(ip);
    return it == names_.end() ? nullptr : &it->second;
}

}  // namespace netpulse
