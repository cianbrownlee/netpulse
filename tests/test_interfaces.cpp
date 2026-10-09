#include <catch2/catch_test_macros.hpp>
#include <string>
#include <vector>

#include "capture/packet_capture.hpp"

using namespace netpulse;
using Interface = PacketCapture::InterfaceInfo;

namespace {

Interface adapter(std::string label, std::string description, std::vector<std::string> networks,
                  bool disconnected = false) {
    Interface i;
    i.name = "\\Device\\NPF_{" + label + "}";
    i.label = std::move(label);
    i.description = std::move(description);
    i.up = true;
    i.disconnected = disconnected;
    i.is_virtual = PacketCapture::looks_virtual(i.label, i.description);
    for (const auto& n : networks) i.networks.add(*IpPrefix::parse(n));
    return i;
}

// Modeled on a real Windows laptop: WSL's and VirtualBox's virtual adapters come before the
// Wi-Fi in the list and have addresses too; spare Wi-Fi and Ethernet ports have only the
// self-assigned 169.254.x.x address of an adapter no network answered.
std::vector<Interface> windows_laptop() {
    std::vector<Interface> list = {
        adapter("vEthernet (WSL (Hyper-V firewall))", "Hyper-V Virtual Ethernet Adapter", {"172.20.160.0/20"}),
        adapter("Bluetooth Network Connection", "Bluetooth Device (Personal Area Network)", {"169.254.0.0/16"},
                true),
        adapter("Ethernet 2", "VirtualBox Host-Only Ethernet Adapter", {"192.168.56.0/24"}),
        adapter("Wi-Fi", "MediaTek Wi-Fi 7 MT7925 Wireless LAN Card", {"192.168.4.0/22", "fe80::/64"}),
        adapter("Wi-Fi 5", "MediaTek Wi-Fi 7 MT7925 Wireless LAN Card #5", {"169.254.0.0/16"}),
        adapter("Ethernet", "Realtek Gaming 2.5GbE Family Controller", {"169.254.0.0/16"}),
    };
    Interface loopback = adapter("Loopback", "Adapter for loopback traffic capture", {"127.0.0.0/8"});
    loopback.loopback = true;
    list.push_back(loopback);
    return list;
}

}  // namespace

TEST_CASE("virtual adapters are recognized by name or description", "[interfaces]") {
    CHECK(PacketCapture::looks_virtual("vEthernet (WSL)", "Hyper-V Virtual Ethernet Adapter"));
    CHECK(PacketCapture::looks_virtual("Ethernet 2", "VirtualBox Host-Only Ethernet Adapter"));
    CHECK(PacketCapture::looks_virtual("docker0", ""));
    CHECK_FALSE(PacketCapture::looks_virtual("Wi-Fi", "MediaTek Wi-Fi 7 MT7925 Wireless LAN Card"));
    CHECK_FALSE(PacketCapture::looks_virtual("eth0", ""));
}

TEST_CASE("the default interface is the connected hardware one", "[interfaces]") {
    // Not WSL's adapter (first, with an address), not VirtualBox's, not the spare ports.
    CHECK(PacketCapture::pick_default(windows_laptop()) == "\\Device\\NPF_{Wi-Fi}");

    // Linux: the first ordinary interface with an IPv4 address, as before.
    Interface lo = adapter("lo", "", {"127.0.0.0/8"});
    lo.loopback = true;
    const std::vector<Interface> linux_box = {lo, adapter("eth0", "", {"172.20.160.0/20"}),
                                              adapter("docker0", "", {"172.17.0.0/16"})};
    CHECK(PacketCapture::pick_default(linux_box) == "\\Device\\NPF_{eth0}");

    // Nothing but self-assigned addresses: no default (NetPulse asks for --interface).
    CHECK_FALSE(PacketCapture::pick_default({adapter("Ethernet", "Realtek", {"169.254.0.0/16"})}));
}

TEST_CASE("interfaces can be named by Windows' name or part of their description", "[interfaces]") {
    const auto list = windows_laptop();
    CHECK(PacketCapture::match_interface(list, "Wi-Fi")->label == "Wi-Fi");            // exact, not "Wi-Fi 5"
    CHECK(PacketCapture::match_interface(list, "\\Device\\NPF_{Ethernet}")->label == "Ethernet");
    CHECK(PacketCapture::match_interface(list, "realtek")->label == "Ethernet");      // description
    CHECK_FALSE(PacketCapture::match_interface(list, "token ring"));
    CHECK_THROWS_AS(PacketCapture::match_interface(list, "mediatek"), CaptureError);  // ambiguous
}
