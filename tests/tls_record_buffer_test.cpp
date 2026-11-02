#include "acppnode/common/allocator.hpp"
#include <asio/ssl/context.hpp>
#include <asio/ssl/detail/stream_core.hpp>
#include <asio/ssl/stream.hpp>
#include <asio/ip/tcp.hpp>
#include <cstring>
#include <iostream>
#include <stdexcept>

namespace {
void Require(bool v, const char* why) { if (!v) throw std::runtime_error(why); }
class Resource : public std::pmr::memory_resource {
public:
    size_t bytes = 0, allocations = 0;
    bool reject = false;
private:
    void* do_allocate(size_t n, size_t alignment) override {
        if (reject) throw std::bad_alloc();
        void* p = pool.allocate(n, alignment);
        bytes += n; ++allocations;
        return p;
    }
    void do_deallocate(void* p, size_t n, size_t alignment) override {
        bytes -= n; pool.deallocate(p, n, alignment);
    }
    bool do_is_equal(const std::pmr::memory_resource& r) const noexcept override { return this == &r; }
    acpp::memory::ThreadPoolFacade pool;
};
struct SelectResource {
    explicit SelectResource(Resource& r) : previous(std::pmr::set_default_resource(&r)) {}
    ~SelectResource() { std::pmr::set_default_resource(previous); }
    std::pmr::memory_resource* previous;
};
using Core = asio::ssl::detail::stream_core;
constexpr size_t record_size = Core::max_tls_record_size;

void Buffers(Resource& resource) {
    SelectResource select(resource);
    asio::io_context io;
    asio::ssl::context context(asio::ssl::context::tls);
    {
        Core control(context.native_handle(), io.get_executor());
        (void)control.prepare_input_buffer();
        Require(resource.bytes == 0, "control-plane/default Asio streams must not inherit the Worker PMR");
    }
    Core core(context.native_handle(), io.get_executor(), &resource);
    Require(resource.bytes == 0, "TLS construction must not allocate record buffers");
    auto input = core.prepare_input_buffer();
    auto output = core.prepare_output_buffer();
    Require(resource.bytes == 2 * record_size && resource.allocations == 2,
            "record buffers must allocate once through the selected PMR resource");
    std::memset(input.data(), 0xa5, input.size());
    Require(core.prepare_input_buffer().data() == input.data() &&
            core.prepare_output_buffer().data() == output.data() && resource.allocations == 2,
            "active I/O must reuse existing storage without per-record allocations");
    core.input_ = asio::buffer(input + 7, 5);
    core.release_idle_buffers();
    Require(resource.bytes == record_size && core.input_.size() == 5 &&
            static_cast<const unsigned char*>(core.input_.data())[0] == 0xa5,
            "idle collection must retain unconsumed ciphertext");
    core.input_ = {};
    resource.reject = true;
    core.release_idle_buffers();
    Require(resource.bytes == 0 && core.input_buffer_.size() == 0 && core.output_buffer_.size() == 0,
            "idle release must allocate nothing and clear borrowed buffer views");
    bool failed = false;
    try { (void)core.prepare_input_buffer(); } catch (const std::bad_alloc&) { failed = true; }
    Require(failed && resource.bytes == 0 && core.input_buffer_.size() == 0,
            "allocation failure must leave empty buffers valid for later recovery");
    resource.reject = false;
    Require(core.prepare_input_buffer().size() == record_size, "input must recover after idle/OOM");
    Require(core.prepare_output_buffer().size() == record_size, "output must recover after idle");
    core.release_idle_buffers();
}

void AsyncAllocationFailure(Resource& resource) {
    for (const auto role : {asio::ssl::stream_base::client, asio::ssl::stream_base::server}) {
        asio::io_context io;
        asio::ssl::context context(asio::ssl::context::tls);
        asio::ssl::stream<asio::ip::tcp::socket> stream(io, SSL_new(context.native_handle()), &resource);
        resource.reject = true;
        bool called = false;
        asio::error_code result;
        stream.async_handshake(role, [&](asio::error_code ec) { called = true; result = ec; });
        Require(!called, "TLS allocation failure must not invoke completion inline");
        io.run();
        resource.reject = false;
        Require(called && result == asio::error::no_memory && resource.bytes == 0,
                "lazy read/write buffer OOM must complete the operation, not escape io_context::run");
    }
}

void MoveBuffers(Resource& first) {
    SelectResource select(first);
    asio::io_context io;
    asio::ssl::context context(asio::ssl::context::tls);
    Core source(context.native_handle(), io.get_executor(), &first);
    auto input = source.prepare_input_buffer();
    std::memset(input.data(), 0x3c, input.size());
    source.input_ = asio::buffer(input + 19, 11);
    (void)source.prepare_output_buffer();
    Core moved(std::move(source));
    Require(moved.input_.data() == static_cast<unsigned char*>(input.data()) + 19,
            "move construction must preserve ciphertext views");
    Resource second;
    SelectResource select_second(second);
    {
        Core destination(context.native_handle(), io.get_executor(), &second);
        destination = std::move(moved);
        Require(destination.input_.size() == 11 &&
                destination.input_.data() == destination.input_buffer_space_.data() + 19 &&
                static_cast<const unsigned char*>(destination.input_.data())[0] == 0x3c &&
                second.bytes == 2 * record_size,
                "move assignment across resources must rebind ciphertext views");
        destination.input_ = {};
        destination.release_idle_buffers();
        Require(second.bytes == 0, "destination must release through its own resource");
    }
}
}
int main() {
    try {
        Resource resource;
        Buffers(resource);
        Require(resource.bytes == 0, "buffers must be fully released");
        MoveBuffers(resource);
        AsyncAllocationFailure(resource);
        Require(resource.bytes == 0, "moved buffers must be fully released");
        std::cout << "TLS record buffers: PMR / lazy allocation / reuse / idle release / pending input / OOM / move PASS\n";
    } catch (const std::exception& e) { std::cerr << e.what() << '\n'; return 1; }
}
