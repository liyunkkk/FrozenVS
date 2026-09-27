// 独立探测: 检查内核是否注册了 Re:Kernel 的 Generic Netlink family
// 静态编译后推到设备以 root 运行, 用于验证 rekernel.hpp 的探测路径。
#include "../include/rekernel.hpp"
#include <cstdio>

int main() {
    printf("/proc/rekernel exists : %s\n", access("/proc/rekernel", F_OK) ? "no" : "yes");
    printf("ReKernel::isInstalled : %s\n", ReKernel::isInstalled() ? "yes" : "no");

    ReKernel rk;
    if (!rk.connect()) {
        printf("connect              : FAILED\n");
        return 1;
    }
    printf("connect              : ok (%s)\n", rk.transportName());
    if (rk.transport() == ReKernel::Transport::LEGACY)
        printf("legacy unit          : %d\n", rk.legacyUnit());

    const auto ver = rk.queryVersion();
    printf("version              : %s\n", ver.empty() ? "(unknown)" : ver.c_str());

    printf("monitorNet(10000,on) : %s\n", rk.monitorNet(10000, true) ? "sent" : "failed");
    printf("monitorNet(10000,off): %s\n", rk.monitorNet(10000, false) ? "sent" : "failed");

    rk.closeSocket();
    return 0;
}