# AGENTS

## 沟通与环境

- 与用户沟通时默认使用中文。
- 需要执行诊断、联调或回归时，优先在当前可用的目标环境中完成。
- 若当前会话无法直连目标环境，应先说明限制，再继续给出可在本地完成的分析结果。
- 变更前先分析现有代码和配置，再决定是否需要修改。

## 项目边界

- cnode 是 C++23 代理节点服务端，核心链路必须保持 `inbound.Process -> dispatcher.Dispatch -> outbound.Process -> relay`。
- 控制面负责面板同步、配置归一化和运行时快照发布；热路径只读取不可变 runtime snapshot。
- 默认主配置文件是 `config.json`，目录侧车文件固定为 `inbounds.json`、`outbounds.json`、`routing.json`。
- cnode 与 XrayR YAML 配置布局有意不同，不回退到 YAML 默认入口或旧 sidecar path 字段。

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

## 部署约束

- 部署脚本 `scripts/cnode.sh` 不带参数时只更新二进制。
- `scripts/cnode.sh -debug_file true` 可额外下载对应的 `.debug` 符号文件。
- VPS 或线上环境优先拉取发布产物进行诊断，不默认在目标机上临时编译。
