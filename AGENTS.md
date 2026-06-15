# AGENTS

## 沟通与环境

- 与用户沟通时默认使用中文。
- 需要执行诊断、联调或回归时，优先在当前可用的目标环境中完成。
- 若当前会话无法直连目标环境，应先说明限制，再继续给出可在本地完成的分析结果。
- 变更前先分析现有代码和配置，再决定是否需要修改。

## 项目边界

- cnode 是 C++23 代理节点服务端，核心链路必须保持唯一。
- 控制面负责面板同步、配置归一化和运行时快照发布；热路径只读取不可变 runtime snapshot。
- 默认主配置文件是 `config.json`，目录侧车文件固定为 `inbounds.json`、`outbounds.json`、`routing.json`。
- cnode 与 XrayR YAML 配置布局有意不同，不回退到 YAML 默认入口或旧 sidecar path 字段。

## 请求链路

所有 TCP / UDP 请求最终只能经过这一条链路：

```text
Inbound Handler::Process
  -> Dispatcher::Dispatch
  -> Outbound Handler::Process
  -> Relay
```

不允许 Worker、协议实现、router、panel、proxyman、transport 或临时 helper 创建第二条绕过链路。任意协议都只是 Handler 实现，不拥有独立架构。

## 职责边界

### inbound

inbound 是监听连接后的协议入站处理入口。

inbound 负责：

- 认证。
- 入站协议解析。
- 用户识别。
- 目标地址解析。
- 初始 payload 处理。
- 生成统一 session / context 元信息。
- 调用 `dispatcher.Dispatch`。

inbound 不负责：

- 路由选择。
- 出站连接。
- relay 细节。
- 直接访问 outbound manager 内部结构。
- 持有协议私有长期大 buffer。

### dispatcher

dispatcher 是请求链路的路由分发入口。

dispatcher 负责：

- 接收 inbound 交给它的 session / context / link。
- 调用 router 做路由决策。
- 根据路由结果选择 outbound handler。
- 调用 `outbound.Process`。

dispatcher 不负责：

- 解析协议。
- 创建协议专属对象。
- 包含 VMess / Trojan / Shadowsocks / AnyTLS 特判。
- 直接执行 relay。
- 读取或理解 panel 配置字段。

### router

router 只做路由决策。

router 负责：

- 接收归一化后的 session metadata。
- 输出 outbound tag / route decision。

router 不负责：

- 创建连接。
- 访问 relay。
- 访问协议实现。
- 依赖 proxyman 具体类型。
- 理解 Worker 资源细节。

### outbound

outbound 是出站协议处理入口。

outbound 负责：

- 根据 dispatcher 选择执行出站处理。
- 建立目标连接或下一跳连接。
- 执行出站协议握手。
- 执行出站编码。
- 完成出站链路准备后交给 relay。

outbound 不负责：

- 路由决策。
- 读取 panel 原始配置。
- 绕过 dispatcher。
- 保留旧 stream process 入口或协议 wrapper。

### relay

relay 只搬运数据。

relay 负责：

- TCP 双向转发。
- UDP 转发。
- Mux 数据搬运。
- 流量统计打点。

relay 不负责：

- 解析 VMess / Trojan / Shadowsocks / AnyTLS 协议。
- 选择 outbound。
- 访问 panel。
- 持有连接生命周期级别的大 scratch。
- 暴露 wrapper API。

### Worker

Worker 只负责运行时边界。

Worker 负责：

- 事件循环。
- accept 生命周期。
- 运行态组件持有。
- thread-local allocator / buffer provider。

Worker 不负责：

- 理解具体协议 validator。
- 理解具体 outbound 类型。
- 路由。
- 协议解析。
- panel 同步。

### control plane

`service/controller` 与 `api/*` 只属于控制面。

control plane 负责：

- 拉取节点信息。
- 拉取用户列表。
- 拉取规则和面板策略。
- 归一化为运行时配置。
- 构建 inbound / outbound / routing / policy runtime。
- 原子替换运行态。
- 按面板语义上报节点状态和用户流量。

control plane 不负责：

- 进入流量热路径。
- 直接访问 Worker buffer provider。
- 直接修改 live handler 内部状态。
- 持有协议实现细节。

## 开发规范

- 优先沿用现有目录职责、命名风格、协程模型、RAII 和错误处理方式。
- 公共头保持窄接口，避免暴露协议私有 helper、运行态存储、完整配置对象或跨层依赖。
- 协议私有 reader、writer、codec、crypto helper 留在 `src/proxy/<protocol>` 内部。
- 冷路径可以做 JSON 解析、字段兼容和对象构建；热路径避免 JSON 解析、panel 字段判断、重复分配、重复拷贝和不必要锁。
- Buffer / MultiBuffer 必须保持清晰所有权，move 后即视为转移，消费结束后及时归还或释放。
- 新增行为要同步考虑静态配置、面板配置、热更新、TCP、UDP、Mux/子流和源进源出语义。

## 开发约束

- Worker 不直接访问协议 validator、panel 字段或具体 outbound 实现。
- Dispatcher 不 include 具体协议，不绕过 router/outbound/relay。
- Router 只返回路由决策，不创建连接，不访问 relay。
- Relay 只搬运数据，不解析协议，不理解面板。
- Panel/client/controller 不进入热路径，不修改 live handler 内部状态。
- 禁止把 legacy、compat、adapter、wrapper、old 或旧面板私有命名作为最终公开设计保留。
- 禁止协议、transport、relay、panel 维护长期私有大 buffer pool。
- 配置热更新只能原子替换 runtime snapshot，不能原地改写正在运行的对象图。

## 协议约束

- 协议核心必须统一为 `Handler::Process` 模型。
- VMess、Trojan、Shadowsocks、AnyTLS、Freedom、Blackhole 都必须遵守同一职责边界。
- 入站协议实现位于 `proxy/<protocol>/inbound`，负责 decode inbound request、authenticate user、produce session metadata、call dispatcher。
- 出站协议实现位于 `proxy/<protocol>/outbound`，负责 dial target or next proxy、encode outbound request、hand over to relay。
- 协议内部允许存在 reader、writer、codec、crypto helper，但这些只能是私有实现细节，不能成为公开请求链路对象。
- 协议不能拥有独立请求链路，所有协议必须进入 `inbound.Process -> dispatcher.Dispatch -> outbound.Process -> relay`。

## 硬性删除规则

发现以下情况时，不做兼容，不做转接，直接删除、合并或下沉：

1. 公开 wrapper 层。
2. 公开 compat 层。
3. 协议 stream 对象作为请求链路一部分。
4. Worker 直接调用协议 validator。
5. Dispatcher include 具体协议。
6. Router 调用 relay。
7. Relay 解析协议。
8. Panel 修改 live handler。
9. 出站读取面板原始字段。
10. 热路径解析 JSON。
11. 连接对象常驻大 scratch。
12. 协议私有长期 pool。
13. manager 同时承担多个层级职责。
14. legacy 配置字段进入 runtime。

## 最终判断标准

cnode 应满足：

1. 从请求入口到 relay 的数据流一眼可见。
2. 任意协议都只是 Handler 实现，不拥有独立架构。
3. 任意配置来源都先归一化，再进入 runtime。
4. 任意热路径对象都归属 Worker-local 资源边界。
5. 任意模块都不知道不属于自己层级的东西。
6. 删除一个协议不会影响 dispatcher / router / relay / worker 的结构。
7. 替换一个 panel 不会影响协议热路径。
8. 替换 allocator 不会影响协议职责。
9. 替换 router 规则不会影响 inbound / outbound 实现。
10. 仓库结构表达最终职责，而不是表达迁移历史。

## 部署约束

- 部署脚本 `scripts/cnode.sh` 不带参数时只更新二进制。
- `scripts/cnode.sh -debug_file true` 可额外下载对应的 `.debug` 符号文件。
- VPS 或线上环境优先拉取发布产物进行诊断，不默认在目标机上临时编译。
