#include <asio/io_context.hpp>
#include <asio/ip/tcp.hpp>
#include <asio/post.hpp>
#include <asio/steady_timer.hpp>

#include "panel_http_fixture.hpp"

#include <chrono>
#include <ctime>
#include <filesystem>
#include <fstream>
#include <functional>
#include <iomanip>
#include <iostream>
#include <sstream>
#include <string>
#include <thread>
#include <vector>

#ifdef _WIN32
#include <windows.h>
#else
#include <csignal>
#include <fcntl.h>
#include <sys/wait.h>
#include <unistd.h>
#endif

namespace {

namespace fs = std::filesystem;
using namespace std::chrono_literals;

bool WriteConfig(const fs::path& root,
                 const std::vector<unsigned short>& ports,
                 unsigned short panel_port) {
    std::error_code ec;
    fs::create_directories(root, ec);
    if (ec) return false;

    std::ofstream main_config(root / "config.json", std::ios::binary);
    main_config
        << R"({"log":{"disableUpload":true,"logDir":")" << (root / "logs").generic_string() << R"("},"workers":2,"dns":{"servers":["127.0.0.1","::1"],"timeout":5,"cacheSize":1000,"minTTL":30,"maxTTL":3600},"limits":{"maxConnections":0,"maxConnectionsPerIP":100},"timeouts":{"handshake":60,"dial":10,"read":15,"write":30,"idle":300,"uplinkOnly":5,"downlinkOnly":5},"panels":[{"Name":"shutdown-panel","Type":"V2board","APIHost":"http://127.0.0.1:)"
        << panel_port
        << R"(","Key":"shutdown-key","NodeIDs":[1],"NodeType":"vmess","ListenIP":"auto","SendIP":"auto"}]})"
        << '\n';
    if (!main_config) return false;

    std::ofstream inbounds(root / "inbounds.json", std::ios::binary);
    inbounds << '[';
    for (size_t i = 0; i < ports.size(); ++i) {
        if (i != 0) inbounds << ',';
        inbounds
            << R"({"tag":"shutdown-test-)" << i
            << R"(","protocol":"vmess","listen":"127.0.0.1","port":)" << ports[i]
            << R"(,"settings":{"clients":[{"id":"b831381d-6324-4d53-ad4f-8cda48b30811"}]},"streamSettings":{"network":"tcp","security":"none"}})";
    }
    inbounds << "]\n";
    if (!inbounds) return false;

    std::ofstream outbounds(root / "outbounds.json", std::ios::binary);
    outbounds
        << R"([{"tag":"explicit-bind","protocol":"freedom","sendThrough":"127.0.0.1"}])"
        << '\n';
    if (!outbounds) return false;

    std::ofstream routing(root / "routing.json", std::ios::binary);
    routing
        << R"({"rules":[{"port":"80,443,1000-2000","sourcePort":[53,"1024-65535"],"outboundTag":"direct"}]})"
        << '\n';
    return static_cast<bool>(routing);
}

#ifdef _WIN32

int RunAndSignal(const fs::path& executable,
                 const fs::path& config_root,
                 const fs::path& output_path,
                 bool send_signal,
                 const std::function<void()>& before_signal = {},
                 bool enable_test_mode = false) {
    const bool allocated_console = send_signal && GetConsoleCP() == 0 && AllocConsole() != FALSE;

    SECURITY_ATTRIBUTES attributes{};
    attributes.nLength = sizeof(attributes);
    attributes.bInheritHandle = TRUE;
    HANDLE output = CreateFileW(
        output_path.c_str(),
        GENERIC_WRITE,
        FILE_SHARE_READ | FILE_SHARE_WRITE,
        &attributes,
        CREATE_ALWAYS,
        FILE_ATTRIBUTE_NORMAL,
        nullptr);
    if (output == INVALID_HANDLE_VALUE) {
        if (allocated_console) FreeConsole();
        return -1;
    }

    STARTUPINFOW startup{};
    startup.cb = sizeof(startup);
    startup.dwFlags = STARTF_USESTDHANDLES | STARTF_USESHOWWINDOW;
    startup.wShowWindow = SW_HIDE;
    startup.hStdInput = GetStdHandle(STD_INPUT_HANDLE);
    startup.hStdOutput = output;
    startup.hStdError = output;

    PROCESS_INFORMATION process{};
    std::wstring command = L"\"" + executable.wstring()
        + L"\" --config-dir \"" + config_root.wstring() + L"\"";
    if (enable_test_mode) command += L" --test";
    std::vector<wchar_t> command_buffer(command.begin(), command.end());
    command_buffer.push_back(L'\0');

    const BOOL created = CreateProcessW(
        nullptr,
        command_buffer.data(),
        nullptr,
        nullptr,
        TRUE,
        CREATE_NEW_PROCESS_GROUP,
        nullptr,
        nullptr,
        &startup,
        &process);
    CloseHandle(output);
    if (!created) {
        if (allocated_console) FreeConsole();
        return -1;
    }

    if (send_signal) {
        if (before_signal) before_signal();
        else std::this_thread::sleep_for(1s);
    }
    if (send_signal && !GenerateConsoleCtrlEvent(CTRL_BREAK_EVENT, process.dwProcessId)) {
        TerminateProcess(process.hProcess, 98);
        WaitForSingleObject(process.hProcess, 5'000);
        CloseHandle(process.hThread);
        CloseHandle(process.hProcess);
        if (allocated_console) FreeConsole();
        return -3;
    }

    const DWORD wait_result = WaitForSingleObject(process.hProcess, 10'000);
    if (wait_result == WAIT_TIMEOUT) {
        TerminateProcess(process.hProcess, 99);
        WaitForSingleObject(process.hProcess, 5'000);
        CloseHandle(process.hThread);
        CloseHandle(process.hProcess);
        if (allocated_console) FreeConsole();
        return -2;
    }

    DWORD exit_code = 0;
    const BOOL got_exit_code = GetExitCodeProcess(process.hProcess, &exit_code);
    CloseHandle(process.hThread);
    CloseHandle(process.hProcess);
    if (allocated_console) FreeConsole();
    return got_exit_code ? static_cast<int>(exit_code) : -1;
}

#else

int RunAndSignal(const fs::path& executable,
                 const fs::path& config_root,
                 const fs::path& output_path,
                 bool send_signal,
                 const std::function<void()>& before_signal = {},
                 bool enable_test_mode = false) {
    const pid_t child = fork();
    if (child < 0) return -1;
    if (child == 0) {
        const int output = open(output_path.c_str(), O_CREAT | O_TRUNC | O_WRONLY, 0600);
        if (output < 0) _exit(126);
        (void)dup2(output, STDOUT_FILENO);
        (void)dup2(output, STDERR_FILENO);
        close(output);
        execl(executable.c_str(),
              executable.c_str(),
              "--config-dir",
              config_root.c_str(),
              enable_test_mode ? "--test" : static_cast<const char*>(nullptr),
              static_cast<char*>(nullptr));
        _exit(127);
    }

    if (send_signal) {
        if (before_signal) before_signal();
        else std::this_thread::sleep_for(1s);
        if (kill(child, SIGTERM) != 0) {
            kill(child, SIGKILL);
            (void)waitpid(child, nullptr, 0);
            return -3;
        }
    }

    const auto deadline = std::chrono::steady_clock::now() + 10s;
    int status = 0;
    while (std::chrono::steady_clock::now() < deadline) {
        const pid_t result = waitpid(child, &status, WNOHANG);
        if (result == child) {
            return WIFEXITED(status) ? WEXITSTATUS(status) : -1;
        }
        if (result < 0) return -1;
        std::this_thread::sleep_for(20ms);
    }

    kill(child, SIGKILL);
    (void)waitpid(child, &status, 0);
    return -2;
}

#endif

bool HasFixedPanelHeartbeat(const std::string& output) {
    std::istringstream lines(output);
    std::string line;
    std::vector<std::time_t> times;
    bool ready = false;
    while (std::getline(lines, line)) {
        if (line.find("Panel replay-panel/1 status:") == std::string::npos) continue;
        std::tm timestamp{};
        timestamp.tm_isdst = -1;
        std::istringstream prefix(line);
        prefix >> std::get_time(&timestamp, "%Y/%m/%d %H:%M:%S");
        if (prefix.fail()) return false;
        times.push_back(std::mktime(&timestamp));
        ready = line.find("status: ready | inbound ready") != std::string::npos;
    }
    if (times.size() != 2 || !ready) return false;
    // Log timestamps have second resolution; allow scheduler jitter without
    // accepting two startup messages or a heartbeat tied to the 2-second push.
    const double elapsed = std::difftime(times[1], times[0]);
    std::cout << "panel heartbeat count=" << times.size() << " gap=" << elapsed
              << "s while the same POST remained pending\n";
    return elapsed >= 59 && elapsed <= 62;
}

bool WaitForOutput(const fs::path& path, std::string_view needle,
                   size_t count, std::chrono::seconds timeout) {
    const auto deadline = std::chrono::steady_clock::now() + timeout;
    do {
        const auto read = [](const fs::path& file_path) {
            std::ifstream file(file_path, std::ios::binary);
            return std::string{std::istreambuf_iterator<char>(file), {}};
        };
        std::string output;
        if (fs::is_directory(path)) {
            for (const auto& file : fs::directory_iterator(path)) {
                if (file.path().filename().string().starts_with("error_") &&
                    file.path().extension() == ".log") output += read(file.path());
            }
        } else {
            output = read(path);
        }
        size_t found = 0;
        for (size_t at = 0; (at = output.find(needle, at)) != std::string::npos; at += needle.size()) {
            ++found;
        }
        if (found >= count) return true;
        std::this_thread::sleep_for(50ms);
    } while (std::chrono::steady_clock::now() < deadline);
    return false;
}

bool NodeListening(unsigned short port) {
    asio::io_context io;
    asio::ip::tcp::socket socket(io);
    asio::steady_timer deadline(io, 1s);
    std::error_code result = asio::error::would_block;
    socket.async_connect({asio::ip::address_v4::loopback(), port},
        [&](const std::error_code& error) { result = error; deadline.cancel(); });
    deadline.async_wait([&](const std::error_code& error) { if (!error) socket.cancel(); });
    io.run();
    return !result;
}

int WaitForReadyNode(const fs::path& path) {
    const auto deadline = std::chrono::steady_clock::now() + 12s;
    do {
        std::ifstream file(path, std::ios::binary);
        const std::string output{std::istreambuf_iterator<char>(file), {}};
        for (const int node : {1, 2}) {
            if (output.find("Panel replay-panel/" + std::to_string(node) + " config: ready") !=
                std::string::npos) return node;
        }
        std::this_thread::sleep_for(50ms);
    } while (std::chrono::steady_clock::now() < deadline);
    return 0;
}

}  // namespace

int main(int argc, char** argv) {
    if (argc != 3 && argc != 4) return 1;
    const bool startup_failure = argc == 4 && std::string(argv[3]) == "startup-failure";
    const bool panel_replay = argc == 4 && std::string(argv[3]) == "panel-replay";
    const bool panel_fallback = argc == 4 && std::string(argv[3]) == "panel-fallback";
    const bool panel_timeout = argc == 4 && std::string(argv[3]) == "panel-timeout";
    const bool panel_heartbeat = argc == 4 && std::string(argv[3]) == "panel-heartbeat";
    const bool panel_lifecycle = argc == 4 && std::string(argv[3]) == "panel-lifecycle";
    const bool panel_collision = argc == 4 && std::string(argv[3]) == "panel-collision";
    const bool panel_collision_race = argc == 4 && std::string(argv[3]) == "panel-collision-race";
    const bool panel_static_collision = argc == 4 && std::string(argv[3]) == "panel-static-collision";
    const bool any_collision = panel_collision || panel_collision_race || panel_static_collision;
    const std::string startup_case = argc == 4 ? argv[3] : "";
    const bool test_tag_collision = startup_case == "test-mode-tag-collision";
    const bool test_port_collision = startup_case == "test-mode-port-collision";
    const bool test_coexist = startup_case == "test-mode-coexist";
    const bool test_implicit = startup_case == "test-mode-implicit";
    const bool test_startup = test_tag_collision || test_port_collision || test_coexist || test_implicit;
    if (argc == 4 && !startup_failure && !panel_replay && !panel_fallback &&
        !panel_timeout && !panel_heartbeat && !panel_lifecycle && !any_collision && !test_startup) return 1;

    const fs::path executable = fs::absolute(argv[1]);
    const fs::path root = fs::absolute(argv[2]);
    std::error_code ec;
    fs::remove_all(root, ec);

    if (test_startup) {
        fs::create_directories(root);
        asio::io_context io;
        asio::ip::tcp::acceptor available(io, {asio::ip::address_v4::loopback(), 0});
        const unsigned short static_port = test_port_collision ? 10086 : available.local_endpoint().port();
        available.close();
        {
            std::ofstream config(root / "config.json", std::ios::binary);
            config << R"({"workers":2,"log":{"disableUpload":true,"logDir":")"
                   << (root / "logs").generic_string() << R"("}})";
            if (!config) return 15;
            if (!test_implicit) {
                std::ofstream inbound(root / "inbounds.json", std::ios::binary);
                inbound << R"([{"tag":")" << (test_tag_collision ? "test-vmess-10086" : "static-test-owner")
                        << R"(","protocol":"vmess","listen":"127.0.0.1","port":)" << static_port
                        << R"(,"settings":{"clients":[{"id":"22f6ee21-7dd1-4e62-9cf3-96ca6c7e8b72"}]},"streamSettings":{"network":"tcp","security":"none"}}])";
                if (!inbound) return 15;
            }
        }
        const bool expected_ready = test_coexist || test_implicit;
        bool listeners_ready = false;
        const auto output_path = root / "child-output.log";
        const int exit_code = RunAndSignal(executable, root, output_path, expected_ready, [&] {
            listeners_ready = WaitForOutput(output_path,
                "static_inbound ready tag=test-vmess-10086 port=10086", 1, 8s) && NodeListening(10086);
            if (test_coexist) listeners_ready = listeners_ready &&
                WaitForOutput(output_path, "static_inbound ready tag=static-test-owner", 1, 1s) &&
                NodeListening(static_port);
        }, !test_implicit);
        std::ifstream file(output_path, std::ios::binary);
        const std::string output{std::istreambuf_iterator<char>(file), {}};
        const bool valid = expected_ready ? exit_code == 0 && listeners_ready :
            exit_code == 1 && output.find("Failed to initialize runtime: startup inbound") != std::string::npos &&
            output.find(test_tag_collision ? "duplicates tag" : "duplicates listen endpoint") != std::string::npos &&
            output.find("static_inbound ready") == std::string::npos &&
            output.find("server started") == std::string::npos;
        if (!valid) {
            std::cerr << "unexpected " << startup_case << ": exit=" << exit_code << '\n' << output;
            return 16;
        }
        std::cout << startup_case << " validated\n";
        return 0;
    }

    if (panel_replay || panel_fallback || panel_timeout || panel_heartbeat || panel_lifecycle || any_collision) {
        try {
            const auto mode = panel_static_collision ? PanelHttpFixture::Mode::StaticCollision :
                panel_collision_race ? PanelHttpFixture::Mode::CollisionRace :
                panel_collision ? PanelHttpFixture::Mode::Collision :
                panel_lifecycle ? PanelHttpFixture::Mode::Lifecycle :
                panel_heartbeat ? PanelHttpFixture::Mode::Heartbeat :
                panel_timeout ? PanelHttpFixture::Mode::Timeout :
                panel_fallback ? PanelHttpFixture::Mode::Fallback : PanelHttpFixture::Mode::Replay;
            PanelHttpFixture fixture(mode);
            if (!fixture.WriteConfig(root)) return 11;
            bool posted = false;
            bool closed_before_stop = !panel_timeout;
            bool held_open_for_heartbeat = false;
            bool lifecycle_valid = false;
            bool collision_valid = false;
            int collision_loser = 2;
            const auto output_path = root / "child-output.log";
            const int exit_code = RunAndSignal(executable, root, output_path, true, [&] {
                if (any_collision) {
                    const auto port = fixture.NodePort();
                    bool owner_ready = false;
                    if (panel_static_collision) {
                        owner_ready = WaitForOutput(output_path, "server started workers=2", 1, 12s) &&
                            NodeListening(port);
                    } else if (panel_collision_race) {
                        const int winner = WaitForReadyNode(output_path);
                        collision_loser = winner == 1 ? 2 : 1;
                        owner_ready = winner != 0 && NodeListening(port);
                    } else {
                        owner_ready = WaitForOutput(output_path, "Panel replay-panel/1 config: ready", 1, 12s) &&
                            NodeListening(port);
                    }
                    fixture.ReleaseCompanion();
                    collision_valid = owner_ready &&
                        WaitForOutput(root / "logs", "Panel replay-panel/" + std::to_string(collision_loser) +
                                      " sync: unavailable | pull", 1, 8s) &&
                        WaitForOutput(root / "logs", panel_static_collision ?
                            "TCP listener conflict tag=panel/replay-panel/2/vmess/" :
                            "panel listener endpoint conflict owner=", 1, 1s) &&
                        NodeListening(port);
                    std::cout << "panel same-endpoint rejection preserves original listener="
                              << collision_valid << '\n';
                    return;
                }
                if (panel_lifecycle) {
                    const auto port = fixture.NodePort();
                    const auto companion = fixture.CompanionPort();
                    lifecycle_valid =
                        WaitForOutput(output_path, "Panel replay-panel/1 config: ready", 1, 12s) &&
                        WaitForOutput(output_path, "Panel replay-panel/2 config: ready", 1, 12s) &&
                        NodeListening(port) && NodeListening(companion) &&
                        WaitForOutput(root / "logs", "Panel replay-panel/1 sync: unavailable | pull", 1, 8s) &&
                        NodeListening(port) && NodeListening(companion) &&
                        fixture.WaitForUserRequests(2) && NodeListening(port) && NodeListening(companion) &&
                        WaitForOutput(output_path, "Panel replay-panel/1 sync: missing | removed", 1, 8s) &&
                        !NodeListening(port) && NodeListening(companion) &&
                        // A missing node uses the default 60-second pull interval.
                        WaitForOutput(output_path, "Panel replay-panel/1 config: ready", 2, 65s) &&
                        NodeListening(port) && NodeListening(companion);
                    std::cout << "panel lifecycle ready/failure/refresh/missing/recovery with isolated companion="
                              << lifecycle_valid << '\n';
                    return;
                }
                posted = fixture.WaitForPost();
                if (posted && panel_timeout) closed_before_stop = fixture.WaitForClientClose();
                if (posted && panel_heartbeat) {
                    std::this_thread::sleep_for(60s);
                    held_open_for_heartbeat = fixture.RequestPending();
                    return;
                }
                // This is shorter than the configured 2-second push interval.
                if (posted) std::this_thread::sleep_for(500ms);
            });
            const auto posts = fixture.Posts();
            std::ifstream output_file(output_path, std::ios::binary);
            const std::string output{std::istreambuf_iterator<char>(output_file), {}};
            if (any_collision) {
                if (exit_code != 0 || !collision_valid ||
                    output.find("Panel replay-panel/" + std::to_string(collision_loser) +
                                " config: ready") != std::string::npos) {
                    std::cerr << "unexpected panel collision: exit=" << exit_code << '\n' << output;
                    return 14;
                }
                return 0;
            }
            if (panel_lifecycle) {
                if (exit_code != 0 || !lifecycle_valid) {
                    std::cerr << "unexpected panel lifecycle: exit=" << exit_code << '\n' << output;
                    return 13;
                }
                return 0;
            }
            const auto expected_address = panel_fallback ? "127.77.0.3" : "127.77.0.2";
            const auto expected_report = panel_fallback ? "traffic ok/0" : "traffic failed/0";
            const bool report_valid = panel_heartbeat
                ? held_open_for_heartbeat && HasFixedPanelHeartbeat(output) &&
                    output.find("traffic failed/0") == std::string::npos &&
                    output.find("traffic ok/0") == std::string::npos
                : output.find(expected_report) != std::string::npos;
            if (exit_code != 0 || !posted || !closed_before_stop || posts.size() != 1 ||
                posts[0].address != expected_address || posts[0].body != "{}" ||
                !report_valid) {
                std::cerr << "unexpected panel request behavior: exit=" << exit_code
                          << " posts=" << posts.size() << " closed_before_stop=" << closed_before_stop
                          << '\n' << output;
                return 12;
            }
        } catch (const std::system_error& error) {
            std::cerr << "Panel fixture failed: " << error.what() << '\n';
            return 12;
        }
        fs::remove_all(root, ec);
        return 0;
    }

    asio::io_context io_context;
    asio::ip::tcp::acceptor port_reservation(io_context);
    port_reservation.open(asio::ip::tcp::v4(), ec);
    if (ec) return 2;
#ifdef _WIN32
    // cnode enables SO_REUSEADDR; make the conflicting binding exclusive.
    if (startup_failure) {
        const BOOL exclusive = TRUE;
        if (setsockopt(port_reservation.native_handle(), SOL_SOCKET,
                       SO_EXCLUSIVEADDRUSE, reinterpret_cast<const char*>(&exclusive),
                       sizeof(exclusive)) != 0) return 2;
    }
#endif
    port_reservation.bind({asio::ip::address_v4::loopback(), 0}, ec);
    if (ec) return 3;
    const auto port = port_reservation.local_endpoint(ec).port();
    if (ec || port == 0) return 4;
    if (startup_failure) {
        port_reservation.listen(asio::socket_base::max_listen_connections, ec);
        if (ec) return 4;
        // The first inbound starts before the second encounters the conflict.
        asio::ip::tcp::acceptor available_port(io_context,
            {asio::ip::address_v4::loopback(), 0});
        const auto ready_port = available_port.local_endpoint().port();
        available_port.close();
        if (!WriteConfig(root, {ready_port, port}, 1)) return 5;
        const fs::path output_path = root / "child-output.log";
        const int exit_code = RunAndSignal(executable, root, output_path, false);
        std::ifstream output_file(output_path, std::ios::binary);
        const std::string output{std::istreambuf_iterator<char>(output_file), {}};
        if (exit_code != 1 ||
            output.find("runtime failed phase=inbound-startup") == std::string::npos ||
            output.find("tag=shutdown-test-1 port=" + std::to_string(port) + " stage=tcp-listen") == std::string::npos ||
            output.find("status=forced") == std::string::npos ||
            output.find("server started") != std::string::npos ||
            output.find("cnode stopped") != std::string::npos) {
            std::cerr << "unexpected startup failure exit or diagnostic: " << exit_code << '\n' << output;
            return 10;
        }
        output_file.close();
        fs::remove_all(root, ec);
        return 0;
    }
    port_reservation.close(ec);

    asio::io_context panel_io;
    asio::ip::tcp::acceptor panel_acceptor(panel_io);
    panel_acceptor.open(asio::ip::tcp::v4(), ec);
    if (ec) return 5;
    panel_acceptor.set_option(asio::socket_base::reuse_address(true), ec);
    if (ec) return 5;
    panel_acceptor.bind({asio::ip::address_v4::loopback(), 0}, ec);
    if (ec) return 5;
    panel_acceptor.listen(asio::socket_base::max_listen_connections, ec);
    if (ec) return 5;
    const auto panel_port = panel_acceptor.local_endpoint(ec).port();
    if (ec || panel_port == 0) return 5;

    if (!WriteConfig(root, {port}, panel_port)) return 5;

    std::shared_ptr<asio::ip::tcp::socket> hanging_panel_socket;
    auto panel_work = asio::make_work_guard(panel_io);
    panel_acceptor.async_accept(
        [&](const std::error_code& accept_error,
            asio::ip::tcp::socket socket) {
            if (!accept_error) {
                hanging_panel_socket =
                    std::make_shared<asio::ip::tcp::socket>(std::move(socket));
            }
        });
    std::thread panel_thread([&] { panel_io.run(); });

    const fs::path output_path = root / "child-output.log";
    const int exit_code = RunAndSignal(executable, root, output_path, true);

    asio::post(panel_io, [&] {
        if (hanging_panel_socket) {
            hanging_panel_socket->close(ec);
        }
        panel_acceptor.close(ec);
        panel_work.reset();
    });
    panel_thread.join();
    const bool panel_connected = static_cast<bool>(hanging_panel_socket);

    std::ifstream output_file(output_path, std::ios::binary);
    const std::string output{
        std::istreambuf_iterator<char>(output_file),
        std::istreambuf_iterator<char>()};
    if (exit_code != 0) {
        std::cerr << "unexpected child exit code: " << exit_code << "\n" << output;
        return 6;
    }
    if (!panel_connected) {
        std::cerr << "child never reached hanging panel endpoint\n" << output;
        return 8;
    }
    if (output.find("status=forced") == std::string::npos) {
        std::cerr << "missing forced shutdown diagnostic\n" << output;
        return 7;
    }
    if (output.find("cnode stopped") != std::string::npos) {
        std::cerr << "forced shutdown entered the runtime teardown path\n" << output;
        return 9;
    }

    fs::remove_all(root, ec);
    return 0;
}
