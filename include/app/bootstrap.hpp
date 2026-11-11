#pragma once

// 进程入口：解析命令行、加载配置并运行完整生命周期，返回进程退出码。
namespace app {

int RunFromCommandLine(int argc, char* argv[]);

}  // namespace app
