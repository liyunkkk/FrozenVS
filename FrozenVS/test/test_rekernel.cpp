// rekernel.hpp 报文解析单元测试
// 仅验证纯解析逻辑(不依赖内核 / 不发包):
//   1. CTRL_CMD_GETFAMILY 回包 -> familyId + events 组播 ID
//   2. C_EVENT 组播事件 -> A_MSG 字符串
//   3. legacy raw netlink 载荷 -> 字符串
//
// 构建: clang++ -std=c++23 -Iinclude -I<stub> test/test_rekernel.cpp -o /tmp/t && /tmp/t

#include "../include/rekernel.hpp"

#include <cassert>
#include <cstdio>

// 测试探针: 由 ReKernel 声明为 friend, 用于访问纯解析函数(必须位于全局作用域)
struct ReKernelTestProbe {
    static int parseGenlCmd(const char* buf, const size_t len, const uint8_t wantCmd,
                            char* out, const size_t outLen) {
        return ReKernel::parseGenlCmd(buf, len, wantCmd, out, outLen);
    }
    static int parseLegacy(const char* buf, const size_t len, char* out, const size_t outLen) {
        return ReKernel::parseLegacy(buf, len, out, outLen);
    }
    static int parseMcastGroups(const char* base, const size_t total) {
        return ReKernel::parseMcastGroups(base, total);
    }
};

namespace {

using Probe = ReKernelTestProbe;

char* putAttr(char* p, const uint16_t type, const void* data, const size_t len) {
    auto* a = reinterpret_cast<nlattr*>(p);
    a->nla_len = static_cast<uint16_t>(NLA_HDRLEN + len);
    a->nla_type = type;
    memcpy(p + NLA_HDRLEN, data, len);
    return p + NLA_ALIGN(NLA_HDRLEN + len);
}

int testGetFamilyReply() {
    char buf[512] = {};

    auto* nlh = reinterpret_cast<nlmsghdr*>(buf);
    nlh->nlmsg_type = GENL_ID_CTRL;
    auto* gnlh = reinterpret_cast<genlmsghdr*>(buf + NLMSG_HDRLEN);
    gnlh->cmd = CTRL_CMD_NEWFAMILY;
    gnlh->version = 2;

    char* p = buf + NLMSG_HDRLEN + GENL_HDRLEN;

    const uint16_t familyId = 31;
    p = putAttr(p, CTRL_ATTR_FAMILY_ID, &familyId, sizeof(familyId));
    p = putAttr(p, CTRL_ATTR_FAMILY_NAME, "rekernel", 9);

    // 嵌套: CTRL_ATTR_MCAST_GROUPS -> [1] -> { NAME, ID }
    char* groupsHead = p;
    auto* groups = reinterpret_cast<nlattr*>(groupsHead);
    groups->nla_type = CTRL_ATTR_MCAST_GROUPS;

    char* entryHead = groupsHead + NLA_HDRLEN;
    auto* entry = reinterpret_cast<nlattr*>(entryHead);
    entry->nla_type = 1;  // 数组下标

    char* inner = entryHead + NLA_HDRLEN;
    const uint32_t groupId = 7;
    inner = putAttr(inner, CTRL_ATTR_MCAST_GRP_NAME, "events", 7);
    inner = putAttr(inner, CTRL_ATTR_MCAST_GRP_ID, &groupId, sizeof(groupId));

    entry->nla_len = static_cast<uint16_t>(inner - entryHead);
    groups->nla_len = static_cast<uint16_t>(inner - groupsHead);
    p = inner;

    nlh->nlmsg_len = static_cast<uint32_t>(p - buf);

    // 复刻 probeGenlFamily 的属性遍历(该函数本身要发包, 无法在离线环境调用)
    int fId = -1, gId = -1;
    size_t pos = NLMSG_HDRLEN + GENL_HDRLEN;
    const size_t end = nlh->nlmsg_len;
    while (pos + NLA_HDRLEN <= end) {
        const auto* a = reinterpret_cast<const nlattr*>(buf + pos);
        const size_t aLen = a->nla_len;
        if (aLen < NLA_HDRLEN || pos + aLen > end) break;

        const uint16_t type = a->nla_type & NLA_TYPE_MASK;
        const char* data = buf + pos + NLA_HDRLEN;
        const size_t dataLen = aLen - NLA_HDRLEN;

        if (type == CTRL_ATTR_FAMILY_ID && dataLen >= 2) {
            uint16_t v = 0;
            memcpy(&v, data, 2);
            fId = v;
        }
        else if (type == CTRL_ATTR_MCAST_GROUPS) {
            gId = Probe::parseMcastGroups(data, dataLen);
        }
        pos += NLA_ALIGN(aLen);
    }

    if (fId != 31) { printf("FAIL familyId=%d\n", fId); return 1; }
    if (gId != 7) { printf("FAIL mcastGroupId=%d\n", gId); return 1; }
    printf("ok  GETFAMILY reply -> family=%d group=%d\n", fId, gId);
    return 0;
}

int testEventMsg() {
    static constexpr const char event[] =
        "type=Binder,bindertype=transaction,oneway=0,from_pid=1234,"
        "from=10123,target_pid=5678,target=10456;";

    char buf[512] = {};
    auto* nlh = reinterpret_cast<nlmsghdr*>(buf);
    nlh->nlmsg_type = 31;  // familyId, 必须 >= NLMSG_MIN_TYPE
    auto* gnlh = reinterpret_cast<genlmsghdr*>(buf + NLMSG_HDRLEN);
    gnlh->cmd = ReKernel::C_EVENT;

    char* p = buf + NLMSG_HDRLEN + GENL_HDRLEN;
    p = putAttr(p, ReKernel::A_MSG, event, sizeof(event));  // 含 '\0'
    nlh->nlmsg_len = static_cast<uint32_t>(p - buf);

    char out[256] = {};
    const int len = Probe::parseGenlCmd(buf, nlh->nlmsg_len, ReKernel::C_EVENT,
                                        out, sizeof(out));
    if (len <= 0 || strcmp(out, event)) {
        printf("FAIL event len=%d out=[%s]\n", len, out);
        return 1;
    }

    // 命令不匹配时应返回 0 而非误判
    if (Probe::parseGenlCmd(buf, nlh->nlmsg_len, ReKernel::C_GET_VERSION,
                            out, sizeof(out)) != 0) {
        printf("FAIL cmd mismatch should return 0\n");
        return 1;
    }

    // 控制消息(NLMSG_ERROR 等)应被忽略
    nlh->nlmsg_type = NLMSG_ERROR;
    if (Probe::parseGenlCmd(buf, nlh->nlmsg_len, ReKernel::C_EVENT,
                            out, sizeof(out)) != 0) {
        printf("FAIL control msg should return 0\n");
        return 1;
    }

    printf("ok  C_EVENT -> [%.40s...]\n", event);
    return 0;
}

int testLegacyMsg() {
    static constexpr const char event[] = "type=Network,target=10456;";

    char buf[256] = {};
    auto* nlh = reinterpret_cast<nlmsghdr*>(buf);
    nlh->nlmsg_len = NLMSG_LENGTH(sizeof(event));
    memcpy(buf + NLMSG_HDRLEN, event, sizeof(event));

    char out[128] = {};
    const int len = Probe::parseLegacy(buf, nlh->nlmsg_len, out, sizeof(out));
    if (len != static_cast<int>(strlen(event)) || strcmp(out, event)) {
        printf("FAIL legacy len=%d out=[%s]\n", len, out);
        return 1;
    }

    // 截断报文不应越界
    if (Probe::parseLegacy(buf, NLMSG_HDRLEN - 1, out, sizeof(out)) != 0) {
        printf("FAIL truncated legacy should return 0\n");
        return 1;
    }

    printf("ok  legacy -> [%s]\n", out);
    return 0;
}

}  // namespace

int main() {
    int fail = 0;
    fail += testGetFamilyReply();
    fail += testEventMsg();
    fail += testLegacyMsg();

    printf(fail ? "\n%d test(s) FAILED\n" : "\nall tests passed\n", fail);
    return fail ? 1 : 0;
}