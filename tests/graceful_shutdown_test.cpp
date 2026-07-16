#include <asio/io_context.hpp>
#include <asio/ip/tcp.hpp>
#include <asio/post.hpp>

#include <chrono>
#include <filesystem>
#include <fstream>
#include <iostream>
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
                 unsigned short port,
                 unsigned short panel_port) {
    std::error_code ec;
    fs::create_directories(root, ec);
    if (ec) return false;

    std::ofstream main_config(root / "config.json", std::ios::binary);
    main_config
        << R"({"workers":2,"dns":{"servers":["127.0.0.1","::1"],"timeout":5,"cacheSize":1000,"minTTL":30,"maxTTL":3600},"limits":{"maxConnections":0,"maxConnectionsPerIP":100},"timeouts":{"handshake":60,"dial":10,"read":15,"write":30,"idle":300,"uplinkOnly":5,"downlinkOnly":5},"panels":[{"Name":"shutdown-panel","Type":"V2board","APIHost":"http://127.0.0.1:)"
        << panel_port
        << R"(","Key":"shutdown-key","NodeIDs":[1],"NodeType":"vmess","ListenIP":"auto","SendIP":"auto"}]})"
        << '\n';
    if (!main_config) return false;

    std::ofstream inbounds(root / "inbounds.json", std::ios::binary);
    inbounds
        << R"([{"tag":"shutdown-test","protocol":"vmess","listen":"127.0.0.1","port":)"
        << port
        << R"(,"settings":{"clients":[{"id":"b831381d-6324-4d53-ad4f-8cda48b30811"}]},"streamSettings":{"network":"tcp","security":"none"}}])"
        << '\n';
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
                 const fs::path& output_path) {
    const bool allocated_console = GetConsoleCP() == 0 && AllocConsole() != FALSE;

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
    startup.dwFlags = STARTF_USESTDHANDLES;
    startup.hStdInput = GetStdHandle(STD_INPUT_HANDLE);
    startup.hStdOutput = output;
    startup.hStdError = output;

    PROCESS_INFORMATION process{};
    std::wstring command = L"\"" + executable.wstring()
        + L"\" --config-dir \"" + config_root.wstring() + L"\"";
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

    std::this_thread::sleep_for(1s);
    if (!GenerateConsoleCtrlEvent(CTRL_BREAK_EVENT, process.dwProcessId)) {
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
                 const fs::path& output_path) {
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
              static_cast<char*>(nullptr));
        _exit(127);
    }

    std::this_thread::sleep_for(1s);
    if (kill(child, SIGTERM) != 0) return -3;

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

}  // namespace

int main(int argc, char** argv) {
    if (argc != 3) return 1;

    const fs::path executable = fs::absolute(argv[1]);
    const fs::path root = fs::absolute(argv[2]);
    std::error_code ec;
    fs::remove_all(root, ec);

    asio::io_context io_context;
    asio::ip::tcp::acceptor port_reservation(io_context);
    port_reservation.open(asio::ip::tcp::v4(), ec);
    if (ec) return 2;
    port_reservation.bind({asio::ip::address_v4::loopback(), 0}, ec);
    if (ec) return 3;
    const auto port = port_reservation.local_endpoint(ec).port();
    if (ec || port == 0) return 4;
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

    if (!WriteConfig(root, port, panel_port)) return 5;

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
    const int exit_code = RunAndSignal(executable, root, output_path);

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
    if (output.find("status=stopping") == std::string::npos ||
        output.find("cnode stopped") == std::string::npos) {
        std::cerr << "missing graceful shutdown diagnostic\n" << output;
        return 7;
    }

    fs::remove_all(root, ec);
    return 0;
}
