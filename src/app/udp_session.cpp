#include "acppnode/app/udp_session.hpp"
#include "acppnode/common/error.hpp"
#include "acppnode/infra/log.hpp"

namespace acpp {

// ============================================================================
// 辅助函数：规范化地址字符串（IPv4-mapped IPv6 -> IPv4）
// ============================================================================
static std::string NormalizeAddress(const net::ip::address& addr) {
    if (addr.is_v6()) {
        auto v6 = addr.to_v6();
        if (v6.is_v4_mapped()) {
            // 转换为 IPv4
            return net::ip::make_address_v4(net::ip::v4_mapped, v6).to_string();
        }
    }
    return addr.to_string();
}

// ============================================================================
// 辅助函数：生成 endpoint key（用于回调路由）
// 优化：使用栈上缓冲区，避免多次堆分配
// ============================================================================
static std::string MakeEndpointKey(const net::ip::address& addr, uint16_t port) {
    // IPv6 最长 45 字符 + ":" + 最长 5 字符端口 = 51，使用 64 字节栈缓冲区
    char buf[64];
    int len;
    
    if (addr.is_v6()) {
        auto v6 = addr.to_v6();
        if (v6.is_v4_mapped()) {
            // IPv4-mapped IPv6 -> 直接格式化为 IPv4
            auto v4 = net::ip::make_address_v4(net::ip::v4_mapped, v6);
            auto bytes = v4.to_bytes();
            len = snprintf(buf, sizeof(buf), "%u.%u.%u.%u:%u",
                          bytes[0], bytes[1], bytes[2], bytes[3], port);
        } else {
            // 纯 IPv6：需要完整格式化（较少见，可容忍 to_string）
            len = snprintf(buf, sizeof(buf), "%s:%u", 
                          v6.to_string().c_str(), port);
        }
    } else {
        // IPv4：直接格式化字节
        auto bytes = addr.to_v4().to_bytes();
        len = snprintf(buf, sizeof(buf), "%u.%u.%u.%u:%u",
                      bytes[0], bytes[1], bytes[2], bytes[3], port);
    }
    
    return std::string(buf, len);
}

// ============================================================================
// UDPSession (Per-Worker, 单线程访问，无需锁)
// ============================================================================

UDPSession::UDPSession(net::any_io_executor executor,
                       const std::string& session_id,
                       PacketCallback on_packet,
                       IDnsService* dns_service)
    : executor_(executor)
    , session_id_(session_id)
    , on_packet_(std::move(on_packet))
    , dns_service_(dns_service)
    , socket_(executor)
    , last_active_(std::chrono::steady_clock::now()) {
}

UDPSession::~UDPSession() {
    if (running_) {
        boost::system::error_code ec;
        socket_.cancel(ec);
        socket_.close(ec);
        running_ = false;
        LOG_ACCESS_DEBUG("UDP session {} destroyed without Stop(), forced close", session_id_);
    }
}

ErrorCode UDPSession::Start(const std::string& bind_address) {
    try {
        auto addr = net::ip::make_address(bind_address);
        udp::endpoint local_ep(addr, 0);  // 端口 0 = 自动分配
        
        socket_.open(local_ep.protocol());
        socket_.set_option(udp::socket::reuse_address(true));
        socket_.bind(local_ep);
        
        local_port_ = socket_.local_endpoint().port();
        running_ = true;
        
        LOG_ACCESS_DEBUG("UDP session {} started on port {}", session_id_, local_port_);
        return ErrorCode::SUCCESS;
        
    } catch (const boost::system::system_error& e) {
        LOG_CONN_FAIL("UDP session {} start failed: {}", session_id_, e.what());
        return ErrorCode::NETWORK_BIND_FAILED;
    }
}

cobalt::task<ErrorCode> UDPSession::Send(const UDPPacket& packet, uint64_t callback_id) {
    if (!running_) {
        co_return ErrorCode::CONNECTION_CLOSED;
    }
    
    try {
        // 解析目标地址
        udp::endpoint remote_ep;
        
        if (packet.target.resolved_addr) {
            remote_ep = udp::endpoint(*packet.target.resolved_addr, packet.target.port);
        } else if (packet.target.type == AddressType::Domain) {
            if (!dns_service_) {
                LOG_CONN_FAIL("UDP session {} DNS service not available", session_id_);
                co_return ErrorCode::DNS_RESOLVE_FAILED;
            }
            
            bool socket_is_v6 = socket_.local_endpoint().address().is_v6();
            auto dns_result = co_await dns_service_->Resolve(packet.target.host, socket_is_v6);
            
            if (!dns_result.Ok()) {
                LOG_ACCESS_DEBUG("UDP session {} DNS resolve failed for {}: {}", 
                         session_id_, packet.target.host, dns_result.error_msg);
                co_return ErrorCode::DNS_RESOLVE_FAILED;
            }
            
            net::ip::address selected_addr;
            bool found = false;
            
            for (const auto& addr : dns_result.addresses) {
                if (addr.is_v6() == socket_is_v6) {
                    selected_addr = addr;
                    found = true;
                    break;
                }
            }
            
            if (!found && !dns_result.addresses.empty()) {
                selected_addr = dns_result.addresses[0];
            }
            
            if (selected_addr.is_unspecified()) {
                co_return ErrorCode::DNS_RESOLVE_FAILED;
            }
            
            remote_ep = udp::endpoint(selected_addr, packet.target.port);
        } else {
            boost::system::error_code ec;
            auto addr = net::ip::make_address(packet.target.host, ec);
            if (ec) {
                co_return ErrorCode::PROTOCOL_INVALID_ADDRESS;
            }
            remote_ep = udp::endpoint(addr, packet.target.port);
        }
        
        // 地址族适配
        bool socket_is_v6 = socket_.local_endpoint().address().is_v6();
        bool target_is_v6 = remote_ep.address().is_v6();
        
        if (socket_is_v6 && !target_is_v6) {
            auto v4 = remote_ep.address().to_v4();
            auto mapped = net::ip::make_address_v6(net::ip::v4_mapped, v4);
            remote_ep = udp::endpoint(mapped, remote_ep.port());
        } else if (!socket_is_v6 && target_is_v6) {
            co_return ErrorCode::PROTOCOL_INVALID_ADDRESS;
        }
        
        // 记录目标映射（用于 Full Cone 回包路由）
        if (callback_id > 0) {
            std::string target_key = MakeEndpointKey(remote_ep.address(), remote_ep.port());
            AddTargetMapping(target_key, callback_id);
        }
        
        // 发送
        size_t sent = co_await socket_.async_send_to(
            net::buffer(packet.data),
            remote_ep,
            cobalt::use_op);
        
        packets_sent_++;
        bytes_sent_ += sent;
        Touch();
        
        LOG_ACCESS_DEBUG("UDP session {} sent {} bytes to {}:{}", 
                 session_id_, sent, remote_ep.address().to_string(), remote_ep.port());
        
        co_return ErrorCode::SUCCESS;
        
    } catch (const boost::system::system_error& e) {
        LOG_ACCESS_DEBUG("UDP session {} send error: {}", session_id_, e.what());
        co_return ErrorCode::NETWORK_IO_ERROR;
    }
}

void UDPSession::SetCallback(PacketCallback callback) {
    on_packet_ = std::move(callback);
    if (on_packet_) {
        LOG_ACCESS_DEBUG("UDP session {} callback set", session_id_);
    } else {
        LOG_ACCESS_DEBUG("UDP session {} callback cleared", session_id_);
    }
}

// ============================================================================
// UDP 发送接口实现
// ============================================================================

cobalt::task<ErrorCode> UDPSession::SendTo(
    const TargetAddress& target,
    const uint8_t* data,
    size_t len) {
    
    if (!running_) {
        co_return ErrorCode::CONNECTION_CLOSED;
    }
    
    try {
        udp::endpoint remote_ep;
        
        if (target.resolved_addr) {
            remote_ep = udp::endpoint(*target.resolved_addr, target.port);
        } else if (target.type == AddressType::Domain) {
            if (!dns_service_) {
                LOG_CONN_FAIL("UDP session {} DNS service not available", session_id_);
                co_return ErrorCode::DNS_RESOLVE_FAILED;
            }
            
            bool socket_is_v6 = socket_.local_endpoint().address().is_v6();
            auto dns_result = co_await dns_service_->Resolve(target.host, socket_is_v6);
            
            if (!dns_result.Ok()) {
                LOG_ACCESS_DEBUG("UDP session {} DNS resolve failed for {}", session_id_, target.host);
                co_return ErrorCode::DNS_RESOLVE_FAILED;
            }
            
            net::ip::address selected_addr;
            for (const auto& addr : dns_result.addresses) {
                if (addr.is_v6() == socket_is_v6) {
                    selected_addr = addr;
                    break;
                }
            }
            
            if (selected_addr.is_unspecified() && !dns_result.addresses.empty()) {
                selected_addr = dns_result.addresses[0];
            }
            
            if (selected_addr.is_unspecified()) {
                co_return ErrorCode::DNS_RESOLVE_FAILED;
            }
            
            remote_ep = udp::endpoint(selected_addr, target.port);
        } else {
            boost::system::error_code ec;
            auto addr = net::ip::make_address(target.host, ec);
            if (ec) {
                co_return ErrorCode::PROTOCOL_INVALID_ADDRESS;
            }
            remote_ep = udp::endpoint(addr, target.port);
        }
        
        // 地址族适配
        bool socket_is_v6 = socket_.local_endpoint().address().is_v6();
        bool target_is_v6 = remote_ep.address().is_v6();
        
        if (socket_is_v6 && !target_is_v6) {
            auto v4 = remote_ep.address().to_v4();
            auto mapped = net::ip::make_address_v6(net::ip::v4_mapped, v4);
            remote_ep = udp::endpoint(mapped, remote_ep.port());
        } else if (!socket_is_v6 && target_is_v6) {
            co_return ErrorCode::PROTOCOL_INVALID_ADDRESS;
        }
        
        size_t sent = co_await socket_.async_send_to(
            net::buffer(data, len),
            remote_ep,
            cobalt::use_op);
        
        packets_sent_++;
        bytes_sent_ += sent;
        Touch();
        
        co_return ErrorCode::SUCCESS;
        
    } catch (const boost::system::system_error& e) {
        LOG_ACCESS_DEBUG("UDP session {} SendTo error: {}", session_id_, e.what());
        co_return ErrorCode::NETWORK_IO_ERROR;
    }
}

void UDPSession::SetReceiveCallback(UDPReceiveCallback callback) {
    receive_callback_ = std::move(callback);
    LOG_ACCESS_DEBUG("UDP session {} receive_callback {}", 
             session_id_, receive_callback_ ? "set" : "cleared");
}

void UDPSession::StartReceive() {
    if (!running_) return;
    DoReceive();
}

// Per-Worker 简化版：无需 executor 参数
uint64_t UDPSession::RegisterCallback(const std::string& destination, 
                                       PacketCallback callback) {
    uint64_t id = next_callback_id_++;
    registered_callbacks_[id] = CallbackEntry{destination, std::move(callback), {}};
    
    if (!destination.empty()) {
        target_to_callbacks_[destination].insert(id);
    }
    
    if (destination.empty()) {
        LOG_ACCESS_DEBUG("UDP session {} registered Full Cone callback {}", session_id_, id);
    } else {
        LOG_ACCESS_DEBUG("UDP session {} registered callback {} for {}", session_id_, id, destination);
    }
    return id;
}

void UDPSession::UnregisterCallback(uint64_t callback_id) {
    auto it = registered_callbacks_.find(callback_id);
    if (it != registered_callbacks_.end()) {
        // 清理反向索引
        if (!it->second.destination.empty()) {
            auto& callbacks = target_to_callbacks_[it->second.destination];
            callbacks.erase(callback_id);
            if (callbacks.empty()) {
                target_to_callbacks_.erase(it->second.destination);
            }
        }
        
        // 清理 sent_targets 对应的反向索引
        for (const auto& target : it->second.sent_targets) {
            auto t_it = target_to_callbacks_.find(target);
            if (t_it != target_to_callbacks_.end()) {
                t_it->second.erase(callback_id);
                if (t_it->second.empty()) {
                    target_to_callbacks_.erase(t_it);
                }
            }
        }
        
        if (it->second.destination.empty()) {
            LOG_ACCESS_DEBUG("UDP session {} unregistered Full Cone callback {}", session_id_, callback_id);
        } else {
            LOG_ACCESS_DEBUG("UDP session {} unregistered callback {} for {}", 
                     session_id_, callback_id, it->second.destination);
        }
        registered_callbacks_.erase(it);
    }
}

void UDPSession::DoReceive() {
    if (!running_) {
        return;
    }
    
    socket_.async_receive_from(
        net::buffer(recv_buffer_),
        sender_endpoint_,
        [this, self = shared_from_this()](boost::system::error_code ec, size_t bytes) {
            if (ec) {
                if (ec != net::error::operation_aborted) {
                    LOG_ACCESS_DEBUG("UDP session {} receive error: {} ({})", 
                             session_id_, ec.message(), ec.value());
                }
                if (running_ && ec != net::error::operation_aborted) {
                    DoReceive();
                }
                return;
            }
            
            std::string sender_key = MakeEndpointKey(sender_endpoint_.address(), 
                                                       sender_endpoint_.port());
            
            LOG_ACCESS_DEBUG("UDP session {} received {} bytes from {}",
                     session_id_, bytes, sender_key);
            
            if (bytes > 0) {
                packets_received_++;
                bytes_received_ += bytes;
                Touch();
                
                // 构造回包
                UDPPacket packet;
                std::string normalized_addr = NormalizeAddress(sender_endpoint_.address());
                
                boost::system::error_code parse_ec;
                auto addr = net::ip::make_address(normalized_addr, parse_ec);
                if (!parse_ec && addr.is_v4()) {
                    packet.target.type = AddressType::IPv4;
                } else if (!parse_ec && addr.is_v6()) {
                    packet.target.type = AddressType::IPv6;
                } else {
                    packet.target.type = AddressType::IPv4;
                }
                
                packet.target.host = normalized_addr;
                packet.target.resolved_addr = sender_endpoint_.address();
                packet.target.port = sender_endpoint_.port();
                packet.data.assign(recv_buffer_.begin(), recv_buffer_.begin() + bytes);
                
                // Full Cone NAT 路由 (Per-Worker 单线程，无需锁)
                std::vector<PacketCallback> matched_callbacks;
                matched_callbacks.reserve(4);  // 预分配，覆盖大多数场景
                
                auto t_it = target_to_callbacks_.find(sender_key);
                if (t_it != target_to_callbacks_.end()) {
                    for (uint64_t cb_id : t_it->second) {
                        auto cb_it = registered_callbacks_.find(cb_id);
                        if (cb_it != registered_callbacks_.end()) {
                            matched_callbacks.push_back(cb_it->second.callback);
                        }
                    }
                } else {
                    std::string known_keys;
                    for (const auto& [key, _] : target_to_callbacks_) {
                        if (!known_keys.empty()) known_keys += ", ";
                        known_keys += key;
                    }
                    LOG_ACCESS_DEBUG("UDP session {} sender_key={} not found, known keys: [{}]",
                             session_id_, sender_key, known_keys);
                }

                if (!matched_callbacks.empty()) {
                    
                    // 单线程直接调用，无需 dispatch
                    for (const auto& cb : matched_callbacks) {
                        cb(packet);
                    }
                } else {
                    // 没有匹配的注册回调，尝试全局回调
                    if (receive_callback_) {
                        net::ip::address from_addr = sender_endpoint_.address();
                        if (from_addr.is_v6()) {
                            auto v6 = from_addr.to_v6();
                            if (v6.is_v4_mapped()) {
                                from_addr = net::ip::make_address_v4(net::ip::v4_mapped, v6);
                            }
                        }
                        
                        LOG_ACCESS_DEBUG("UDP session {} calling receive_callback for {}", 
                                 session_id_, sender_key);
                        receive_callback_(from_addr, sender_endpoint_.port(), 
                                         recv_buffer_.data(), bytes);
                    } else if (on_packet_) {
                        LOG_ACCESS_DEBUG("UDP session {} using on_packet_ callback for {}", 
                                 session_id_, sender_key);
                        on_packet_(packet);
                    } else {
                        LOG_ACCESS_DEBUG("UDP session {} no callback for {}", session_id_, sender_key);
                    }
                }
            }
            
            // 继续接收
            DoReceive();
        });
}

void UDPSession::AddTargetMapping(const std::string& target_key, uint64_t callback_id) {
    auto it = registered_callbacks_.find(callback_id);
    if (it != registered_callbacks_.end()) {
        if (it->second.destination.empty()) {
            // Full Cone: 添加发送目标到 sent_targets
            it->second.sent_targets.insert(target_key);
            target_to_callbacks_[target_key].insert(callback_id);
            LOG_ACCESS_DEBUG("UDP session {} added target mapping {} -> callback {}", 
                     session_id_, target_key, callback_id);
        }
    }
}

void UDPSession::RemoveTargetMappings(uint64_t callback_id) {
    auto it = registered_callbacks_.find(callback_id);
    if (it != registered_callbacks_.end()) {
        for (const auto& target : it->second.sent_targets) {
            auto t_it = target_to_callbacks_.find(target);
            if (t_it != target_to_callbacks_.end()) {
                t_it->second.erase(callback_id);
                if (t_it->second.empty()) {
                    target_to_callbacks_.erase(t_it);
                }
            }
        }
        it->second.sent_targets.clear();
    }
}

void UDPSession::Stop() {
    if (!running_) return;
    running_ = false;
    
    boost::system::error_code ec;
    socket_.cancel(ec);
    socket_.close(ec);

    registered_callbacks_.clear();
    target_to_callbacks_.clear();
    on_packet_ = {};
    receive_callback_ = {};
    
    LOG_ACCESS_DEBUG("UDP session {} stopped, sent: {} pkts/{} bytes, recv: {} pkts/{} bytes",
              session_id_, packets_sent_, bytes_sent_,
              packets_received_, bytes_received_);
}

// ============================================================================
// UDPSessionManager (Per-Worker, 单线程访问，无需锁)
// ============================================================================

UDPSessionManager::UDPSessionManager(net::any_io_executor executor,
                                     IDnsService* dns_service,
                                     std::chrono::seconds session_timeout)
    : executor_(executor)
    , dns_service_(dns_service)
    , session_timeout_(session_timeout)
    , cleanup_timer_(executor) {
}

UDPSessionManager::~UDPSessionManager() {
    StopAll();
}

std::shared_ptr<UDPSession> UDPSessionManager::GetOrCreateSession(
    const std::string& session_id,
    net::any_io_executor executor,
    UDPSession::PacketCallback on_packet,
    const std::string& bind_address) {
    
    auto it = sessions_.find(session_id);
    if (it != sessions_.end()) {
        it->second->Touch();
        return it->second;
    }
    
    // 创建新会话
    auto session = std::make_shared<UDPSession>(executor, session_id, std::move(on_packet), dns_service_);
    auto err = session->Start(bind_address);
    
    if (err != ErrorCode::SUCCESS) {
        LOG_CONN_FAIL("Failed to create UDP session {}: {}", session_id, ErrorCodeToString(err));
        return nullptr;
    }
    
    sessions_[session_id] = session;
    session->StartReceive();
    
    LOG_ACCESS_DEBUG("Created UDP session {} on port {}, total sessions: {}",
             session_id, session->LocalPort(), sessions_.size());
    
    return session;
}

std::shared_ptr<UDPSession> UDPSessionManager::GetSession(const std::string& session_id) {
    auto it = sessions_.find(session_id);
    if (it != sessions_.end()) {
        return it->second;
    }
    return nullptr;
}

void UDPSessionManager::RemoveSession(const std::string& session_id) {
    auto it = sessions_.find(session_id);
    if (it != sessions_.end()) {
        it->second->Stop();
        sessions_.erase(it);
        LOG_ACCESS_DEBUG("Removed UDP session {}, remaining: {}", session_id, sessions_.size());
    }
}

void UDPSessionManager::StartCleanup() {
    running_ = true;
    CleanupExpiredSessions();
}

void UDPSessionManager::CleanupExpiredSessions() {
    if (!running_) return;
    
    for (auto it = sessions_.begin(); it != sessions_.end(); ) {
        if (it->second->IsExpired(session_timeout_)) {
            LOG_ACCESS_DEBUG("UDP session {} expired, removing", it->first);
            total_packets_sent_ += it->second->PacketsSent();
            total_packets_received_ += it->second->PacketsReceived();
            it->second->Stop();
            it = sessions_.erase(it);
        } else {
            ++it;
        }
    }
    
    // 每 30 秒清理一次
    cleanup_timer_.expires_after(std::chrono::seconds(30));
    cleanup_timer_.async_wait([this](boost::system::error_code ec) {
        if (!ec && running_) {
            CleanupExpiredSessions();
        }
    });
}

void UDPSessionManager::StopAll() {
    running_ = false;
    cleanup_timer_.cancel();
    
    for (const auto& [id, session] : sessions_) {
        session->Stop();
    }
    sessions_.clear();
}

}  // namespace acpp
