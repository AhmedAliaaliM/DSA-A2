
#include <iostream>
#include <condition_variable>
#include <iomanip>
#include <deque> 
#include <arpa/inet.h>
#include <chrono>
#include <cstring>
#include <errno.h>
#include <ifaddrs.h>
#include <mutex>
#include <net/ethernet.h>
#include <net/if.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <netinet/ip6.h>
#include <netpacket/packet.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <thread>
#include <unistd.h>
#include <vector>
#include <atomic>
#include <sstream>
#include <string>


using TimePoint = std::chrono::time_point<Clock>;
using Clock = std::chrono::steady_clock;

static inline std::string stamp_now() {
    using namespace std::chrono;
    auto t = system_clock::now();
    time_t tt = system_clock::to_time_t(t);
    struct tm tm;
    localtime_r(&tt, &tm);
    char buf[64];
    strftime(buf, sizeof(buf), "%F %T", &tm);
    auto ms = duration_cast<milliseconds>(t.time_since_epoch()).count() % 1000;
    char out[80];
    snprintf(out, sizeof(out), "%s.%03lld", buf, (long long)ms);
    return std::string(out);
}


struct PacketItem {
    uint64_t id = 0;
    TimePoint ts;
    std::vector<uint8_t> data;
    std::string src;
    std::string dst;
    int attempts = 0;
};


template<typename T>
class LifoParse {
    std::vector<T> s;
public:
    void push(const T& v) { s.push_back(v); }
    T pop() { if (s.empty()) throw std::runtime_error("pop empty"); T v = s.back(); s.pop_back(); return v; }
    T& top() { if (s.empty()) throw std::runtime_error("top empty"); return s.back(); }
    bool empty() const { return s.empty(); }
    size_t size() const { return s.size(); }
};


std::deque<PacketItem> ingress_buffer; 
std::mutex mtx_ingress;
std::condition_variable cv_ingress;

std::vector<PacketItem> to_replay_pool;
std::vector<PacketItem> fallback_pool;
std::mutex mtx_replay;

std::atomic<bool> terminate_flag(false);

std::atomic<uint64_t> pkt_seq_num(0);
const size_t OVERSIZE_LIMIT = 100;
std::atomic<size_t> bigpkt_skip_count(0);


static std::string ipv6_to_str(const in6_addr& a) {
    char buf[INET6_ADDRSTRLEN];
    inet_ntop(AF_INET6, &a, buf, sizeof(buf));
    return std::string(buf);
}

// it is to capture thread
void capture_loop(const std::string& ifname) {
    int fd = socket(AF_PACKET, SOCK_RAW, htons(ETH_P_ALL));
    if (fd < 0) {
        std::cerr << "capture: socket failed: " << strerror(errno) << "\n";
        return;
    }

    
    struct ifreq ifr;
    memset(&ifr, 0, sizeof(ifr));
    strncpy(ifr.ifr_name, ifname.c_str(), IFNAMSIZ - 1);
    ifr.ifr_name[IFNAMSIZ - 1] = '\0'; 

    if (ioctl(fd, SIOCGIFINDEX, &ifr) == -1) {
        std::cerr << "capture: SIOCGIFINDEX failed: " << strerror(errno) << "\n";
        close(fd);
        return;
    }

    struct sockaddr_ll sll;
    memset(&sll, 0, sizeof(sll));
    sll.sll_family = AF_PACKET;
    sll.sll_ifindex = ifr.ifr_ifindex;
    sll.sll_protocol = htons(ETH_P_ALL);

    if (bind(fd, (struct sockaddr*)&sll, sizeof(sll)) == -1) {
        std::cerr << "capture: bind failed: " << strerror(errno) << "\n";
        close(fd);
        return;
    }

    const size_t BUF_SZ = 65536;
    std::vector<uint8_t> buf(BUF_SZ);

    while (!terminate_flag.load()) {
        ssize_t r = recv(fd, buf.data(), BUF_SZ, 0);
        if (r < 0) {
            if (errno == EINTR) continue;
            std::cerr << "capture: recv error: " << strerror(errno) << "\n";
            break;
        }
        if (r == 0) continue;
        
        if (r < 14) continue;

        PacketItem p;
        p.id = ++pkt_seq_num;
        p.ts = Clock::now();
        p.data.assign(buf.begin(), buf.begin() + r);

        if (p.data.size() > 1500) {
            size_t prev = ++bigpkt_skip_count;
            if (prev > OVERSIZE_LIMIT) {
                continue;
            }
        }
        {
            std::lock_guard<std::mutex> lk(mtx_ingress);
            ingress_buffer.push_back(std::move(p));
        }
        cv_ingress.notify_one();
    }

    close(fd);
}


void layer_parser_loop() {
    while (!terminate_flag.load()) {
        std::unique_lock<std::mutex> lk(mtx_ingress);
        cv_ingress.wait_for(lk, std::chrono::milliseconds(200), [] {
            return !ingress_buffer.empty() || terminate_flag.load();
            });

        if (ingress_buffer.empty()) {
            if (terminate_flag.load()) break;
            continue;
        }

        PacketItem pkt = std::move(ingress_buffer.front());
        ingress_buffer.pop_front();
        lk.unlock();

        LifoParse<std::pair<std::string, size_t>> layers;
        layers.push({ "ETH", 0 });

        if (pkt.data.size() < 14) continue; 

        uint16_t ethertype = (uint16_t(pkt.data[12]) << 8) | uint16_t(pkt.data[13]);

        // it handle IPv4
        if (ethertype == 0x0800) {
            layers.push({ "IPv4", 14 });
            size_t off = 14;
            if (pkt.data.size() < off + 20) continue; 

            uint8_t ihl = pkt.data[off] & 0x0F;
            uint8_t proto = pkt.data[off + 9];

            struct in_addr sa, da;

        
            if (pkt.data.size() < off + 20) continue;

            memcpy(&sa.s_addr, &pkt.data[off + 12], sizeof(uint32_t));
            memcpy(&da.s_addr, &pkt.data[off + 16], sizeof(uint32_t));

            char s1[INET_ADDRSTRLEN] = { 0 }, d1[INET_ADDRSTRLEN] = { 0 };
            inet_ntop(AF_INET, &sa, s1, sizeof(s1));
            inet_ntop(AF_INET, &da, d1, sizeof(d1));
            pkt.src = s1;
            pkt.dst = d1;

            size_t iphdrlen = size_t(ihl) * 4;
            size_t tOff = off + iphdrlen;

            if (proto == IPPROTO_TCP && pkt.data.size() >= tOff + 20) {
                layers.push({ "TCP", tOff });
                uint16_t sp = (uint16_t(pkt.data[tOff]) << 8) | uint16_t(pkt.data[tOff + 1]);
                uint16_t dp = (uint16_t(pkt.data[tOff + 2]) << 8) | uint16_t(pkt.data[tOff + 3]);
                pkt.src += ":" + std::to_string(sp);
                pkt.dst += ":" + std::to_string(dp);
            }
            else if (proto == IPPROTO_UDP && pkt.data.size() >= tOff + 8) {
                layers.push({ "UDP", tOff });
                uint16_t sp = (uint16_t(pkt.data[tOff]) << 8) | uint16_t(pkt.data[tOff + 1]);
                uint16_t dp = (uint16_t(pkt.data[tOff + 2]) << 8) | uint16_t(pkt.data[tOff + 3]);
                pkt.src += ":" + std::to_string(sp);
                pkt.dst += ":" + std::to_string(dp);
            }
        }
        // handle IPv6

        else if (ethertype == 0x86DD) {
            layers.push({ "IPv6", 14 });
            size_t off = 14;

            const size_t IPV6_HDR_SIZE = sizeof(struct ip6_hdr); // 40 bytes
            if (pkt.data.size() < off + IPV6_HDR_SIZE) continue;

            struct ip6_hdr h6;
            memcpy(&h6, pkt.data.data() + off, IPV6_HDR_SIZE);

            pkt.src = ipv6_to_str(h6.ip6_src);
            pkt.dst = ipv6_to_str(h6.ip6_dst);

            uint8_t nxt = h6.ip6_nxt;
            size_t tOff = off + IPV6_HDR_SIZE;

            if (nxt == IPPROTO_TCP && pkt.data.size() >= tOff + 20) {
                layers.push({ "TCP", tOff });
                uint16_t sp = (uint16_t(pkt.data[tOff]) << 8) | uint16_t(pkt.data[tOff + 1]);
                uint16_t dp = (uint16_t(pkt.data[tOff + 2]) << 8) | uint16_t(pkt.data[tOff + 3]);
                pkt.src += ":" + std::to_string(sp);
                pkt.dst += ":" + std::to_string(dp);
            }
            else if (nxt == IPPROTO_UDP && pkt.data.size() >= tOff + 8) {
                layers.push({ "UDP", tOff });
                uint16_t sp = (uint16_t(pkt.data[tOff]) << 8) | uint16_t(pkt.data[tOff + 1]);
                uint16_t dp = (uint16_t(pkt.data[tOff + 2]) << 8) | uint16_t(pkt.data[tOff + 3]);
                pkt.src += ":" + std::to_string(sp);
                pkt.dst += ":" + std::to_string(dp);
            }
        }
        else {
            continue;
        }

        {
            std::lock_guard<std::mutex> lk(mtx_replay);
            to_replay_pool.push_back(std::move(pkt));
        }
    }
}


static bool match_addr(const std::string& packetAddr, const std::string& filter) {
    if (filter.empty()) return true;
    if (packetAddr.empty()) return false;
    if (filter.find(':') != std::string::npos) {
        return packetAddr == filter;
    }
    else {
        size_t pos = packetAddr.find(':');
        std::string ip = (pos == std::string::npos) ? packetAddr : packetAddr.substr(0, pos);
        return ip == filter;
    }
}

// this is to replay the thread

void replay_loop(const std::string& ifname, const std::string& filterSrc, const std::string& filterDst) {
    int outfd = socket(AF_PACKET, SOCK_RAW, htons(ETH_P_ALL));
    if (outfd < 0) {
        std::cerr << "replay: socket failed: " << strerror(errno) << "\n";
        return;
    }

    struct ifreq ifr;
    memset(&ifr, 0, sizeof(ifr));
    strncpy(ifr.ifr_name, ifname.c_str(), IFNAMSIZ - 1);
    ifr.ifr_name[IFNAMSIZ - 1] = '\0'; 

    if (ioctl(outfd, SIOCGIFINDEX, &ifr) == -1) {
        std::cerr << "replay: SIOCGIFINDEX failed: " << strerror(errno) << "\n";
        close(outfd);
        return;
    }

    struct sockaddr_ll dest;
    memset(&dest, 0, sizeof(dest));
    dest.sll_family = AF_PACKET;
    dest.sll_ifindex = ifr.ifr_ifindex;
    dest.sll_halen = ETH_ALEN;

    while (!terminate_flag.load()) {
        std::vector<PacketItem> work;
        {
            std::lock_guard<std::mutex> lk(mtx_replay);
            if (!to_replay_pool.empty()) work.swap(to_replay_pool);
        }
        if (work.empty()) {
            std::this_thread::sleep_for(std::chrono::milliseconds(200));
            continue;
        }

        for (auto& p : work) {
            if (!match_addr(p.src, filterSrc)) continue;
            if (!match_addr(p.dst, filterDst)) continue;

            if (p.data.size() > 1500 && bigpkt_skip_count.load() > OVERSIZE_LIMIT) continue;

            bool sent = false;
            for (int attempt = 0; attempt <= 2; ++attempt) {
                ssize_t s = sendto(outfd, p.data.data(), p.data.size(), 0, (struct sockaddr*)&dest, sizeof(dest));
                if (s == (ssize_t)p.data.size()) { sent = true; break; }
                std::this_thread::sleep_for(std::chrono::milliseconds(100));
            }
            if (!sent) {
                std::lock_guard<std::mutex> lk(mtx_replay);
                p.attempts++;
                fallback_pool.push_back(p);
            }
            else {
                double delay_ms = double(p.data.size()) / 1000.0;
                std::cout << "[REPLAYED] id=" << p.id << " time=" << stamp_now()
                    << " src=" << p.src << " dst=" << p.dst
                    << " delay(ms)=" << std::fixed << std::setprecision(2) << delay_ms
                    << " size=" << p.data.size() << "\n";
            }
        }

        
        {
            std::lock_guard<std::mutex> lk(mtx_replay);
            if (!fallback_pool.empty()) {
                std::vector<PacketItem> keep;
                for (auto& fp : fallback_pool) {
                    if (fp.attempts >= 2) { keep.push_back(fp); continue; }
                    bool ok = false;
                    for (int r = 0; r < 2; ++r) {
                        ssize_t s = sendto(outfd, fp.data.data(), fp.data.size(), 0, (struct sockaddr*)&dest, sizeof(dest));
                        if (s == (ssize_t)fp.data.size()) { ok = true; break; }
                        std::this_thread::sleep_for(std::chrono::milliseconds(100));
                    }
                    if (!ok) { fp.attempts++; keep.push_back(fp); }
                    else { std::cout << "[RECOVERED] id=" << fp.id << " time=" << stamp_now() << "\n"; }
                }
                fallback_pool.swap(keep);
            }
        }
    }

    close(outfd);
}

//  displays output 
void show_snapshot() {
    std::lock_guard<std::mutex> lk(mtx_replay);
    if (to_replay_pool.empty()) { std::cout << "No parsed packets.\n"; return; }
    std::cout << "Parsed packets snapshot (" << to_replay_pool.size() << "):\n";
    for (auto& p : to_replay_pool) {
        std::cout << "id=" << p.id << " time=" << stamp_now() << " src=" << p.src << " dst=" << p.dst << " size=" << p.data.size() << "\n";
    }
}
void show_fallbacks() {
    std::lock_guard<std::mutex> lk(mtx_replay);
    if (fallback_pool.empty()) { std::cout << "No fallback items.\n"; return; }
    std::cout << "Fallback list:\n";
    for (auto& p : fallback_pool) {
        std::cout << "id=" << p.id << " attempts=" << p.attempts << " src=" << p.src << " dst=" << p.dst << " size=" << p.data.size() << "\n";
    }
}


int main(int argc, char** argv) {
    if (argc < 2) {
        std::cerr << "Usage: sudo " << argv[0] << " <interface> [filterSrc] [filterDst]\n";
        return 1;
    }
    std::string iface = argv[1];
    std::string filterSrc = (argc >= 3) ? argv[2] : "";
    std::string filterDst = (argc >= 4) ? argv[3] : "";

    std::cout << "Network Monitor (unique names) starting on " << iface << "\n";
    if (!filterSrc.empty()) std::cout << "Filter src: " << filterSrc << "\n";
    if (!filterDst.empty()) std::cout << "Filter dst: " << filterDst << "\n";

    std::thread t_cap(capture_loop, iface);
    std::thread t_par(layer_parser_loop);
    std::thread t_rep(replay_loop, iface, filterSrc, filterDst);

    auto start = Clock::now();
    auto dur = std::chrono::seconds(60);
    while (Clock::now() - start < dur) {
        std::this_thread::sleep_for(std::chrono::seconds(10));
        std::cout << "----- status at " << stamp_now() << " -----\n";
        std::cout << "Captured approx: " << pkt_seq_num.load()
            << "  ingress size: " << ingress_buffer.size()
            << "  oversize skipped: " << bigpkt_skip_count.load() << "\n";
        show_snapshot();
        show_fallbacks();
        std::cout << "-------------------------------\n";
    }

    terminate_flag.store(true);
    cv_ingress.notify_all();

    if (t_cap.joinable()) t_cap.join();
    if (t_par.joinable()) t_par.join();
    if (t_rep.joinable()) t_rep.join();

    std::cout << "Demo finished. Final fallback list:\n";
    show_fallbacks();
    std::cout << "Done.\n";
    return 0;
}