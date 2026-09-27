#pragma once

// Re:Kernel 通信层
//
// Re:Kernel v11.0 起, 默认传输方式已由 raw netlink 改为 Generic Netlink:
//   family = "rekernel"   multicast group = "events"
// 并且 /proc/rekernel 目录 **仅在** 内核侧定义了 LEGACY_NETLINK 时才会创建
// (见 rekernel_netlink.c: "genl resolves by family name")。
//
// 因此旧的探测方式 access("/proc/rekernel/") 在新版内核上必然失败, 导致
// Binder / 网络 临时解冻整条链路静默失效。
//
// 本文件同时实现两种传输:
//   1. Generic Netlink (v11+ 默认)   -> 按 family 名解析 + 加入 events 组播
//   2. Legacy raw netlink (unit 22~25) -> 兼容旧模块, 并修正命令格式
//
// 事件载荷两种传输完全一致, 均为形如
//   "type=Binder,bindertype=transaction,oneway=0,from=10123,target=10456,...;"
// 的字符串, 所以上层解析代码可以原样复用。

#include <linux/netlink.h>
#include <linux/genetlink.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <unistd.h>
#include <dirent.h>
#include <errno.h>

#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <mutex>
#include <string>

#ifndef NETLINK_GENERIC
#define NETLINK_GENERIC 16
#endif

#ifndef SOL_NETLINK
#define SOL_NETLINK 270
#endif

#ifndef NETLINK_ADD_MEMBERSHIP
#define NETLINK_ADD_MEMBERSHIP 1
#endif

#ifndef GENL_ID_CTRL
#define GENL_ID_CTRL NLMSG_MIN_TYPE
#endif

class ReKernel {
public:
    enum class Transport : uint8_t {
        NONE = 0,
        GENL = 1,    // Generic Netlink, v11+
        LEGACY = 2,  // raw netlink unit 22~25
    };

    // 内核侧 ABI (rekernel.h)
    enum : uint8_t {
        C_EVENT = 1,            // kernel -> user, 组播事件
        C_ADD_MONITOR_NET = 2,  // user -> kernel, 订阅某 uid 的网络事件
        C_DEL_MONITOR_NET = 3,  // user -> kernel, 取消订阅
        C_GET_VERSION = 4,      // user -> kernel, 查询版本(单播回复)
    };
    enum : uint16_t {
        A_MSG = 1,  // string
        A_UID = 2,  // u32
        A_PID = 3,  // u32
    };
    // legacy: struct rekernel_cmd { int type; }
    enum : int {
        LEGACY_CMD_REMOVE_PROC = 1,
        LEGACY_CMD_ADD_MONITOR_NET = 2,
        LEGACY_CMD_DEL_MONITOR_NET = 3,
    };

    static constexpr const char* PROC_DIR = "/proc/rekernel";
    static constexpr const char* FAMILY_NAME = "rekernel";
    static constexpr const char* MCGRP_NAME = "events";

    static constexpr int LEGACY_USER_PORT = 100;
    static constexpr int LEGACY_UNIT_MIN = 22;
    static constexpr int LEGACY_UNIT_MAX = 26;  // 闭区间上界, 容忍旧文档里的 26

    static constexpr size_t RECV_BUF_SIZE = 8192;

    ReKernel() = default;
    ReKernel(const ReKernel&) = delete;
    ReKernel& operator=(const ReKernel&) = delete;

    ~ReKernel() { closeSocket(); }

    Transport transport() const { return trans; }
    int legacyUnit() const { return unit; }
    bool isConnected() const { return fd >= 0; }

    // 只做存在性探测, 不建立长连接。用于替代旧的 access("/proc/rekernel/")
    static bool isInstalled() {
        if (!access(PROC_DIR, F_OK)) return true;
        return probeGenlFamily(nullptr, nullptr);
    }

    const char* transportName() const {
        switch (trans) {
        case Transport::GENL:   return "GenericNetlink";
        case Transport::LEGACY: return "LegacyNetlink";
        default:                return "None";
        }
    }

    // 建立连接。优先 Generic Netlink, 失败则回退 legacy。
    // 返回 false 表示 Re:Kernel 不可用。
    bool connect() {
        closeSocket();

        if (connectGenl()) {
            trans = Transport::GENL;
            return true;
        }
        if (connectLegacy()) {
            trans = Transport::LEGACY;
            return true;
        }

        trans = Transport::NONE;
        return false;
    }

    void closeSocket() {
        std::lock_guard<std::mutex> lock(sendMutex);
        if (fd >= 0) {
            close(fd);
            fd = -1;
        }
    }

    // 阻塞接收一条事件。
    //   > 0 : out 中为以 '\0' 结尾的事件字符串, 返回其长度
    //   = 0 : 本次收到的是可忽略的消息(控制消息 / 非事件命令), 继续循环即可
    //   < 0 : 链路异常, 调用方应重连
    int recvEvent(char* out, size_t outLen) {
        if (fd < 0 || out == nullptr || outLen == 0) return -1;

        const ssize_t len = recv(fd, recvBuf, sizeof(recvBuf), 0);
        if (len <= 0) {
            if (len < 0 && (errno == EINTR || errno == EAGAIN)) return 0;
            return -1;
        }

        if (trans == Transport::LEGACY)
            return parseLegacy(recvBuf, static_cast<size_t>(len), out, outLen);

        return parseGenl(recvBuf, static_cast<size_t>(len), out, outLen);
    }

    // 订阅 / 取消订阅某个 uid 的网络事件。
    // v11 的 netfilter 钩子里有 net_uid_monitored(uid) 门控, 不订阅则永远收不到
    // type=Network 事件, 所以"网络解冻"必须显式登记 uid。
    bool monitorNet(const int uid, const bool add) {
        if (fd < 0) return false;

        std::lock_guard<std::mutex> lock(sendMutex);

        if (trans == Transport::GENL) {
            // nlmsghdr + genlmsghdr + nlattr(u32)
            const int total = NLMSG_HDRLEN + GENL_HDRLEN + NLA_HDRLEN + 4;
            char buf[64] = {};

            auto* nlh = reinterpret_cast<nlmsghdr*>(buf);
            nlh->nlmsg_len = total;
            nlh->nlmsg_type = static_cast<uint16_t>(familyId);
            nlh->nlmsg_flags = NLM_F_REQUEST;
            nlh->nlmsg_seq = ++seq;
            nlh->nlmsg_pid = 0;

            auto* gnlh = reinterpret_cast<genlmsghdr*>(buf + NLMSG_HDRLEN);
            gnlh->cmd = add ? C_ADD_MONITOR_NET : C_DEL_MONITOR_NET;
            gnlh->version = 1;

            auto* attr = reinterpret_cast<nlattr*>(buf + NLMSG_HDRLEN + GENL_HDRLEN);
            attr->nla_len = NLA_HDRLEN + 4;
            attr->nla_type = A_UID;
            const uint32_t u = static_cast<uint32_t>(uid);
            memcpy(reinterpret_cast<char*>(attr) + NLA_HDRLEN, &u, 4);

            return sendRaw(buf, total);
        }

        // legacy: struct rekernel_cmd{int type;} + struct rekernel_monitor_net_args{int uid;}
        int payload[2] = { add ? LEGACY_CMD_ADD_MONITOR_NET : LEGACY_CMD_DEL_MONITOR_NET, uid };
        return sendLegacyPayload(payload, sizeof(payload));
    }

    // 查询模块版本(如 "11.0")。仅 genl 支持; legacy 读 /proc/rekernel/version。
    // 阻塞式, 只在初始化阶段调用。
    std::string queryVersion() {
        if (trans == Transport::LEGACY) {
            char path[64];
            snprintf(path, sizeof(path), "%s/version", PROC_DIR);
            FILE* fp = fopen(path, "r");
            if (!fp) return {};
            char tmp[64] = {};
            if (!fgets(tmp, sizeof(tmp), fp)) { fclose(fp); return {}; }
            fclose(fp);
            for (char& c : tmp) if (c == '\n' || c == '\r') { c = 0; break; }
            return std::string(tmp);
        }

        if (trans != Transport::GENL || familyId < 0) return {};

        // 用独立 socket 收单播回复, 避免和事件接收线程抢包
        const int tmpFd = socket(AF_NETLINK, SOCK_DGRAM, NETLINK_GENERIC);
        if (tmpFd < 0) return {};

        sockaddr_nl local{};
        local.nl_family = AF_NETLINK;
        if (bind(tmpFd, reinterpret_cast<sockaddr*>(&local), sizeof(local))) {
            close(tmpFd);
            return {};
        }

        const int total = NLMSG_HDRLEN + GENL_HDRLEN;
        char buf[64] = {};
        auto* nlh = reinterpret_cast<nlmsghdr*>(buf);
        nlh->nlmsg_len = total;
        nlh->nlmsg_type = static_cast<uint16_t>(familyId);
        nlh->nlmsg_flags = NLM_F_REQUEST;
        nlh->nlmsg_seq = 1;
        auto* gnlh = reinterpret_cast<genlmsghdr*>(buf + NLMSG_HDRLEN);
        gnlh->cmd = C_GET_VERSION;
        gnlh->version = 1;

        sockaddr_nl kernel{};
        kernel.nl_family = AF_NETLINK;
        if (sendto(tmpFd, buf, total, 0, reinterpret_cast<sockaddr*>(&kernel),
                   sizeof(kernel)) < 0) {
            close(tmpFd);
            return {};
        }

        timeval tv{ 2, 0 };
        setsockopt(tmpFd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));

        char reply[512] = {};
        const ssize_t len = recv(tmpFd, reply, sizeof(reply), 0);
        close(tmpFd);
        if (len <= 0) return {};

        char out[128] = {};
        if (parseGenlCmd(reply, static_cast<size_t>(len), C_GET_VERSION, out, sizeof(out)) > 0)
            return std::string(out);

        return {};
    }

private:
    friend struct ReKernelTestProbe;  // test/test_rekernel.cpp 访问纯解析函数

    int fd{ -1 };
    int familyId{ -1 };
    int mcastGroupId{ -1 };
    int unit{ -1 };
    uint32_t seq{ 0 };
    Transport trans{ Transport::NONE };
    std::mutex sendMutex;
    char recvBuf[RECV_BUF_SIZE]{};

    bool sendRaw(const void* buf, const size_t len) const {
        sockaddr_nl kernel{};
        kernel.nl_family = AF_NETLINK;
        return sendto(fd, buf, len, 0, reinterpret_cast<const sockaddr*>(&kernel),
                      sizeof(kernel)) >= 0;
    }

    // ---------------- Generic Netlink ----------------

    // 在 tmpFd 上解析 family, 输出 familyId / mcastGroupId
    static bool probeGenlFamily(int* outFamilyId, int* outGroupId) {
        const int tmpFd = socket(AF_NETLINK, SOCK_DGRAM, NETLINK_GENERIC);
        if (tmpFd < 0) return false;

        sockaddr_nl local{};
        local.nl_family = AF_NETLINK;
        if (bind(tmpFd, reinterpret_cast<sockaddr*>(&local), sizeof(local))) {
            close(tmpFd);
            return false;
        }

        const size_t nameLen = strlen(FAMILY_NAME) + 1;
        const int total = NLMSG_HDRLEN + GENL_HDRLEN +
                          static_cast<int>(NLA_ALIGN(NLA_HDRLEN + nameLen));

        char buf[128] = {};
        auto* nlh = reinterpret_cast<nlmsghdr*>(buf);
        nlh->nlmsg_len = total;
        nlh->nlmsg_type = GENL_ID_CTRL;
        nlh->nlmsg_flags = NLM_F_REQUEST;
        nlh->nlmsg_seq = 1;
        nlh->nlmsg_pid = 0;

        auto* gnlh = reinterpret_cast<genlmsghdr*>(buf + NLMSG_HDRLEN);
        gnlh->cmd = CTRL_CMD_GETFAMILY;
        gnlh->version = 1;

        auto* attr = reinterpret_cast<nlattr*>(buf + NLMSG_HDRLEN + GENL_HDRLEN);
        // nla_len 记录未对齐长度, 但缓冲区需补齐到 4 字节
        attr->nla_len = static_cast<uint16_t>(NLA_HDRLEN + nameLen);
        attr->nla_type = CTRL_ATTR_FAMILY_NAME;
        memcpy(reinterpret_cast<char*>(attr) + NLA_HDRLEN, FAMILY_NAME, nameLen);

        sockaddr_nl kernel{};
        kernel.nl_family = AF_NETLINK;
        if (sendto(tmpFd, buf, total, 0, reinterpret_cast<sockaddr*>(&kernel),
                   sizeof(kernel)) < 0) {
            close(tmpFd);
            return false;
        }

        timeval tv{ 2, 0 };
        setsockopt(tmpFd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));

        char reply[4096] = {};
        const ssize_t len = recv(tmpFd, reply, sizeof(reply), 0);
        close(tmpFd);
        if (len <= static_cast<ssize_t>(NLMSG_HDRLEN + GENL_HDRLEN)) return false;

        const auto* rnlh = reinterpret_cast<const nlmsghdr*>(reply);
        // 家族不存在时内核回 NLMSG_ERROR
        if (rnlh->nlmsg_type != GENL_ID_CTRL) return false;

        int fId = -1, gId = -1;
        const size_t end = rnlh->nlmsg_len < static_cast<uint32_t>(len)
                               ? rnlh->nlmsg_len : static_cast<size_t>(len);

        size_t pos = NLMSG_HDRLEN + GENL_HDRLEN;
        while (pos + NLA_HDRLEN <= end) {
            const auto* a = reinterpret_cast<const nlattr*>(reply + pos);
            const size_t aLen = a->nla_len;
            if (aLen < NLA_HDRLEN || pos + aLen > end) break;

            const uint16_t type = a->nla_type & NLA_TYPE_MASK;
            const char* data = reply + pos + NLA_HDRLEN;
            const size_t dataLen = aLen - NLA_HDRLEN;

            if (type == CTRL_ATTR_FAMILY_ID && dataLen >= 2) {
                uint16_t v = 0;
                memcpy(&v, data, 2);
                fId = v;
            }
            else if (type == CTRL_ATTR_MCAST_GROUPS) {
                gId = parseMcastGroups(data, dataLen);
            }

            pos += NLA_ALIGN(aLen);
        }

        if (fId < 0) return false;
        if (outFamilyId) *outFamilyId = fId;
        if (outGroupId) *outGroupId = gId;
        return true;
    }

    // CTRL_ATTR_MCAST_GROUPS 是"以下标为 type 的嵌套数组", 每项内含 NAME / ID
    static int parseMcastGroups(const char* base, const size_t total) {
        size_t pos = 0;
        while (pos + NLA_HDRLEN <= total) {
            const auto* grp = reinterpret_cast<const nlattr*>(base + pos);
            const size_t grpLen = grp->nla_len;
            if (grpLen < NLA_HDRLEN || pos + grpLen > total) break;

            const char* inner = base + pos + NLA_HDRLEN;
            const size_t innerTotal = grpLen - NLA_HDRLEN;

            const char* name = nullptr;
            int id = -1;

            size_t p = 0;
            while (p + NLA_HDRLEN <= innerTotal) {
                const auto* a = reinterpret_cast<const nlattr*>(inner + p);
                const size_t aLen = a->nla_len;
                if (aLen < NLA_HDRLEN || p + aLen > innerTotal) break;

                const uint16_t type = a->nla_type & NLA_TYPE_MASK;
                if (type == CTRL_ATTR_MCAST_GRP_NAME)
                    name = inner + p + NLA_HDRLEN;
                else if (type == CTRL_ATTR_MCAST_GRP_ID && aLen - NLA_HDRLEN >= 4)
                    memcpy(&id, inner + p + NLA_HDRLEN, 4);

                p += NLA_ALIGN(aLen);
            }

            if (name && !strcmp(name, MCGRP_NAME))
                return id;

            pos += NLA_ALIGN(grpLen);
        }
        return -1;
    }

    bool connectGenl() {
        int fId = -1, gId = -1;
        if (!probeGenlFamily(&fId, &gId)) return false;

        const int sk = socket(AF_NETLINK, SOCK_DGRAM, NETLINK_GENERIC);
        if (sk < 0) return false;

        sockaddr_nl local{};
        local.nl_family = AF_NETLINK;
        local.nl_pid = 0;  // 由内核分配 portid
        if (bind(sk, reinterpret_cast<sockaddr*>(&local), sizeof(local))) {
            close(sk);
            return false;
        }

        int rcvBuf = 512 * 1024;
        setsockopt(sk, SOL_SOCKET, SO_RCVBUF, &rcvBuf, sizeof(rcvBuf));

        if (gId > 0 &&
            setsockopt(sk, SOL_NETLINK, NETLINK_ADD_MEMBERSHIP, &gId, sizeof(gId))) {
            close(sk);
            return false;
        }

        fd = sk;
        familyId = fId;
        mcastGroupId = gId;
        return true;
    }

    int parseGenl(const char* buf, const size_t len, char* out, const size_t outLen) const {
        return parseGenlCmd(buf, len, C_EVENT, out, outLen);
    }

    static int parseGenlCmd(const char* buf, const size_t len, const uint8_t wantCmd,
                            char* out, const size_t outLen) {
        if (len < NLMSG_HDRLEN + GENL_HDRLEN) return 0;

        const auto* nlh = reinterpret_cast<const nlmsghdr*>(buf);
        if (nlh->nlmsg_type < NLMSG_MIN_TYPE) return 0;  // ERROR / DONE / 控制消息

        const auto* gnlh = reinterpret_cast<const genlmsghdr*>(buf + NLMSG_HDRLEN);
        if (gnlh->cmd != wantCmd) return 0;

        const size_t end = nlh->nlmsg_len < len ? nlh->nlmsg_len : len;
        size_t pos = NLMSG_HDRLEN + GENL_HDRLEN;

        while (pos + NLA_HDRLEN <= end) {
            const auto* a = reinterpret_cast<const nlattr*>(buf + pos);
            const size_t aLen = a->nla_len;
            if (aLen < NLA_HDRLEN || pos + aLen > end) break;

            if ((a->nla_type & NLA_TYPE_MASK) == A_MSG) {
                size_t dataLen = aLen - NLA_HDRLEN;
                const char* data = buf + pos + NLA_HDRLEN;
                while (dataLen > 0 && data[dataLen - 1] == 0) dataLen--;
                if (dataLen == 0) return 0;
                if (dataLen >= outLen) dataLen = outLen - 1;
                memcpy(out, data, dataLen);
                out[dataLen] = 0;
                return static_cast<int>(dataLen);
            }

            pos += NLA_ALIGN(aLen);
        }
        return 0;
    }

    // ---------------- Legacy raw netlink ----------------

    // /proc/rekernel/<unit> ; 目录里还有个 "version" 项, 需跳过
    static int scanLegacyUnit() {
        DIR* dir = opendir(PROC_DIR);
        if (dir == nullptr) return -1;

        int found = -1;
        dirent* file;
        while ((file = readdir(dir)) != nullptr) {
            if (file->d_name[0] == '.') continue;
            if (file->d_name[0] < '0' || file->d_name[0] > '9') continue;  // "version"

            const int n = atoi(file->d_name);
            if (LEGACY_UNIT_MIN <= n && n <= LEGACY_UNIT_MAX) {
                found = n;
                break;
            }
        }
        closedir(dir);
        return found;
    }

    bool connectLegacy() {
        if (access(PROC_DIR, F_OK)) return false;

        int u = scanLegacyUnit();
        if (u < 0) u = LEGACY_UNIT_MIN;  // 目录存在但节点已被清理, 退回默认 unit

        const int sk = socket(AF_NETLINK, SOCK_DGRAM, u);
        if (sk < 0) return false;

        sockaddr_nl local{};
        local.nl_family = AF_NETLINK;
        local.nl_pid = LEGACY_USER_PORT;  // 内核侧 netlink_unicast 固定发往 100
        if (bind(sk, reinterpret_cast<sockaddr*>(&local), sizeof(local))) {
            close(sk);
            return false;
        }

        int rcvBuf = 512 * 1024;
        setsockopt(sk, SOL_SOCKET, SO_RCVBUF, &rcvBuf, sizeof(rcvBuf));

        fd = sk;
        unit = u;

        // 通知内核移除 /proc/rekernel 节点, 避免被应用用于环境检测。
        // 注意: 新内核按 struct rekernel_cmd{int type;} 解析, 旧代码直接发
        // "#proc_remove" 字符串是无效的。
        int cmd = LEGACY_CMD_REMOVE_PROC;
        sendLegacyPayload(&cmd, sizeof(cmd));

        return true;
    }

    bool sendLegacyPayload(const void* payload, const size_t payloadLen) const {
        char buf[NLMSG_HDRLEN + 64] = {};
        if (payloadLen > 64) return false;

        auto* nlh = reinterpret_cast<nlmsghdr*>(buf);
        nlh->nlmsg_len = NLMSG_LENGTH(payloadLen);
        nlh->nlmsg_flags = 0;
        nlh->nlmsg_type = 0;
        nlh->nlmsg_seq = 0;
        nlh->nlmsg_pid = LEGACY_USER_PORT;
        memcpy(NLMSG_DATA(nlh), payload, payloadLen);

        return sendRaw(buf, nlh->nlmsg_len);
    }

    static int parseLegacy(const char* buf, const size_t len, char* out, const size_t outLen) {
        if (len < NLMSG_HDRLEN) return 0;

        const auto* nlh = reinterpret_cast<const nlmsghdr*>(buf);
        if (nlh->nlmsg_len < NLMSG_HDRLEN || nlh->nlmsg_len > len) return 0;

        size_t dataLen = nlh->nlmsg_len - NLMSG_HDRLEN;
        const char* data = buf + NLMSG_HDRLEN;
        if (dataLen == 0) return 0;

        // 内核用 scnprintf 填充, 载荷带 '\0'
        const size_t real = strnlen(data, dataLen);
        if (real == 0) return 0;

        dataLen = real >= outLen ? outLen - 1 : real;
        memcpy(out, data, dataLen);
        out[dataLen] = 0;
        return static_cast<int>(dataLen);
    }
};
