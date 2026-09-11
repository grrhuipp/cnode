#pragma once

#include <asio/as_tuple.hpp>
#include <asio/co_spawn.hpp>
#include <asio/io_context.hpp>
#include <asio/ip/tcp.hpp>
#include <asio/ip/udp.hpp>
#include <asio/read.hpp>
#include <asio/read_until.hpp>
#include <asio/streambuf.hpp>
#include <asio/steady_timer.hpp>
#include <asio/use_awaitable.hpp>
#include <asio/write.hpp>

#include <array>
#include <atomic>
#include <chrono>
#include <condition_variable>
#include <exception>
#include <filesystem>
#include <fstream>
#include <iostream>
#include <mutex>
#include <string>
#include <thread>
#include <utility>
#include <vector>

// Real cnode integration fixture. Every DNS answer and listener is loopback-only.
class PanelHttpFixture {
    using tcp = asio::ip::tcp;
    using udp = asio::ip::udp;
public:
    enum class Mode { Replay, Fallback, Timeout, Heartbeat, Lifecycle, Collision,
                      CollisionRace, StaticCollision };
    struct Post {
        std::string address;
        std::string body;
    };

    explicit PanelHttpFixture(Mode mode)
        : dns_(io_, udp::endpoint(asio::ip::make_address("127.77.0.1"), 0)),
          first_(io_), second_(io_), mode_(mode) {
        first_.open(tcp::v4());
        first_.bind({asio::ip::make_address("127.77.0.2"), 0});
        panel_port_ = first_.local_endpoint().port();
        // A bound, non-listening first candidate deterministically refuses TCP.
        if (mode != Mode::Fallback) first_.listen();
        second_.open(tcp::v4());
        second_.bind({asio::ip::make_address("127.77.0.3"), panel_port_});
        second_.listen();
        tcp::acceptor node_port(io_, {asio::ip::address_v4::loopback(), 0});
        node_port_ = node_port.local_endpoint().port();
        if (mode == Mode::Lifecycle) {
            tcp::acceptor companion(io_, {asio::ip::address_v4::loopback(), 0});
            companion_port_ = companion.local_endpoint().port();
        }
        if (CollisionMode()) companion_port_ = node_port_;
        node_port.close();
        auto report = [](std::exception_ptr failure) {
            if (!failure) return;
            try { std::rethrow_exception(failure); }
            catch (const std::exception& error) { std::cerr << "panel fixture: " << error.what() << '\n'; }
        };
        asio::co_spawn(io_, Resolve(), report);
        if (mode != Mode::Fallback) asio::co_spawn(io_, Accept(first_, true), report);
        asio::co_spawn(io_, Accept(second_, false), report);
        thread_ = std::thread([this] { io_.run(); });
    }

    ~PanelHttpFixture() {
        io_.stop();
        if (thread_.joinable()) thread_.join();
    }

    bool WriteConfig(const std::filesystem::path& root) const {
        std::filesystem::create_directories(root);
        std::ofstream config(root / "config.json", std::ios::binary);
        config << R"({"workers":)" << (CollisionMode() ? 2 : 1)
               << R"(,"log":{"disableUpload":true,"logDir":")"
               << (root / "logs").generic_string()
               << R"("},"dns":{"servers":["127.77.0.1:)" << dns_.local_endpoint().port()
               << R"("],"timeout":2,"cacheSize":32,"minTTL":1,"maxTTL":60},"panels":[{"Name":"replay-panel","Type":"V2board","APIHost":"http://panel-replay.test:)"
               << panel_port_
               << R"(","Key":"local-test-key","NodeIDs":)"
               << (mode_ == Mode::StaticCollision ? "[2]" :
                   mode_ == Mode::Lifecycle || CollisionMode() ? "[1,2]" : "[1]")
               << R"(,"NodeType":"vmess","ListenIP":"127.0.0.1","RequestTimeout":)"
               << (mode_ == Mode::Timeout ? 1 : mode_ == Mode::Heartbeat ? 120 : 30) << "}]}";
        if (!config) return false;
        if (mode_ == Mode::StaticCollision) {
            std::ofstream inbounds(root / "inbounds.json", std::ios::binary);
            inbounds << R"([{"tag":"static-owner","protocol":"vmess","listen":"0.0.0.0","port":)"
                     << node_port_
                     << R"(,"settings":{"clients":[{"id":"b831381d-6324-4d53-ad4f-8cda48b30811"}]},"streamSettings":{"network":"tcp","security":"none"}}])";
            return static_cast<bool>(inbounds);
        }
        return true;
    }

    bool WaitForPost() {
        std::unique_lock lock(mutex_);
        return posted_.wait_for(lock, std::chrono::seconds(12), [this] { return !posts_.empty(); });
    }

    std::vector<Post> Posts() {
        std::lock_guard lock(mutex_);
        return posts_;
    }

    bool WaitForClientClose() {
        std::unique_lock lock(mutex_);
        return posted_.wait_for(lock, std::chrono::seconds(3), [this] { return client_closed_; });
    }

    bool RequestPending() {
        std::lock_guard lock(mutex_);
        return request_pending_;
    }

    bool WaitForUserRequests(size_t count) {
        std::unique_lock lock(mutex_);
        return posted_.wait_for(lock, std::chrono::seconds(8),
            [this, count] { return user_requests_ >= count; });
    }

    unsigned short NodePort() const noexcept { return node_port_; }
    unsigned short CompanionPort() const noexcept { return companion_port_; }

    void ReleaseCompanion() noexcept { companion_released_.store(true); }

private:
    bool CollisionMode() const noexcept {
        return mode_ == Mode::Collision || mode_ == Mode::CollisionRace || mode_ == Mode::StaticCollision;
    }

    asio::awaitable<void> Resolve() {
        std::array<unsigned char, 512> request{};
        udp::endpoint peer;
        for (;;) {
            const auto size = co_await dns_.async_receive_from(asio::buffer(request), peer, asio::use_awaitable);
            if (size < 17) continue;
            size_t end = 12;
            while (end < size && request[end] != 0) end += 1 + request[end];
            if (end + 5 > size) continue;
            const bool ipv4 = request[end + 1] == 0 && request[end + 2] == 1;
            std::vector<unsigned char> response(request.begin(), request.begin() + end + 5);
            response[2] = 0x81;
            response[3] = 0x80;
            response[6] = 0;
            response[7] = ipv4 ? 2 : 0;
            response[8] = response[9] = response[10] = response[11] = 0;
            if (ipv4) {
                for (unsigned char last : std::array<unsigned char, 2>{2, 3}) {
                    const std::array<unsigned char, 16> answer{
                        0xc0, 0x0c, 0, 1, 0, 1, 0, 0, 0, 60, 0, 4, 127, 77, 0, last};
                    response.insert(response.end(), answer.begin(), answer.end());
                }
            }
            co_await dns_.async_send_to(asio::buffer(response), peer, asio::use_awaitable);
        }
    }

    asio::awaitable<void> Accept(tcp::acceptor& acceptor, bool truncate_response) {
        for (;;) {
            auto socket = co_await acceptor.async_accept(asio::use_awaitable);
            asio::co_spawn(io_, Serve(std::move(socket), truncate_response),
                [](std::exception_ptr failure) {
                    if (!failure) return;
                    try { std::rethrow_exception(failure); }
                    catch (const std::exception& error) { std::cerr << "mock HTTP: " << error.what() << '\n'; }
                });
        }
    }

    asio::awaitable<void> Serve(tcp::socket socket, bool truncate_response) {
        asio::streambuf buffer(64 * 1024);
        co_await asio::async_read_until(socket, buffer, "\r\n\r\n", asio::use_awaitable);
        std::istream input(&buffer);
        std::string method, path, version, line;
        input >> method >> path >> version;
        std::getline(input, line);
        size_t body_size = 0;
        while (std::getline(input, line) && line != "\r") {
            if (line.starts_with("Content-Length:")) body_size = std::stoul(line.substr(15));
        }
        if (buffer.size() < body_size) {
            co_await asio::async_read(socket, buffer, asio::transfer_exactly(body_size - buffer.size()),
                                    asio::use_awaitable);
        }
        std::string body(body_size, '\0');
        input.read(body.data(), static_cast<std::streamsize>(body_size));
        std::string payload = "{}";
        std::string status = "200 OK";
        const bool primary = path.find("node_id=1&") != std::string::npos;
        if (path.find("/config?") != std::string::npos) {
            if (mode_ == Mode::Collision && !primary) {
                asio::steady_timer wait(io_);
                while (!companion_released_.load()) {
                    wait.expires_after(std::chrono::milliseconds(20));
                    co_await wait.async_wait(asio::use_awaitable);
                }
            }
            if (primary) ++config_requests_;
            payload = R"({"server_port":)" + std::to_string(primary ? node_port_ : companion_port_) +
                (mode_ == Mode::Lifecycle && primary
                    ? R"(,"network":"tcp","tls":0,"base_config":{"pull_interval":2,"push_interval":1}})"
                    : R"(,"network":"tcp","tls":0,"base_config":{"pull_interval":60,"push_interval":2}})");
            if (mode_ == Mode::Lifecycle && primary && config_requests_ == 2) {
                status = "503 Service Unavailable";
                payload = R"({"message":"fixture pull failure"})";
            } else if (mode_ == Mode::Lifecycle && primary && config_requests_ == 4) {
                status = "404 Not Found";
                payload = "{}";
            }
        } else if (path.find("/user?") != std::string::npos) {
            payload = R"({"users":[]})";
            {
                std::lock_guard lock(mutex_);
                if (primary) ++user_requests_;
            }
            posted_.notify_one();
        } else if (method == "POST" && path.find("/push?") != std::string::npos) {
            {
                std::lock_guard lock(mutex_);
                posts_.push_back({socket.local_endpoint().address().to_string(), body});
                request_pending_ = mode_ == Mode::Timeout || mode_ == Mode::Heartbeat;
            }
            posted_.notify_one();
            if (mode_ == Mode::Timeout || mode_ == Mode::Heartbeat) {
                // Keep the request open until cnode itself releases the socket.
                std::array<char, 1> extra{};
                const auto [ec, size] = co_await socket.async_read_some(
                    asio::buffer(extra), asio::as_tuple(asio::use_awaitable));
                {
                    std::lock_guard lock(mutex_);
                    client_closed_ = ec == asio::error::eof && size == 0;
                    request_pending_ = false;
                }
                posted_.notify_one();
                co_return;
            }
            if (truncate_response && mode_ != Mode::Lifecycle && !CollisionMode()) {
                const std::string response = "HTTP/1.1 200 OK\r\nContent-Length: 20\r\nConnection: close\r\n\r\n{";
                co_await asio::async_write(socket, asio::buffer(response), asio::use_awaitable);
                co_return;
            }
        }
        const std::string response = "HTTP/1.1 " + status + "\r\nContent-Length: " +
            std::to_string(payload.size()) + "\r\nConnection: close\r\n\r\n" + payload;
        co_await asio::async_write(socket, asio::buffer(response), asio::use_awaitable);
    }

    asio::io_context io_;
    udp::socket dns_;
    tcp::acceptor first_;
    tcp::acceptor second_;
    Mode mode_;
    unsigned short panel_port_ = 0;
    unsigned short node_port_ = 0;
    unsigned short companion_port_ = 0;
    std::mutex mutex_;
    std::condition_variable posted_;
    std::vector<Post> posts_;
    bool client_closed_ = false;
    bool request_pending_ = false;
    std::atomic<bool> companion_released_{false};
    size_t config_requests_ = 0;
    size_t user_requests_ = 0;
    std::thread thread_;
};
