// 列出内核已注册的所有 Generic Netlink family 名称。
// 用于确认 Re:Kernel 是否真的在运行, 以及它注册的 family 名到底叫什么。
#include <linux/netlink.h>
#include <linux/genetlink.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <unistd.h>

#include <cstdint>
#include <cstdio>
#include <cstring>

#ifndef NETLINK_GENERIC
#define NETLINK_GENERIC 16
#endif
#ifndef GENL_ID_CTRL
#define GENL_ID_CTRL NLMSG_MIN_TYPE
#endif

int main() {
    const int fd = socket(AF_NETLINK, SOCK_DGRAM, NETLINK_GENERIC);
    if (fd < 0) { perror("socket"); return 1; }

    sockaddr_nl local{};
    local.nl_family = AF_NETLINK;
    if (bind(fd, reinterpret_cast<sockaddr*>(&local), sizeof(local))) {
        perror("bind"); close(fd); return 1;
    }

    char req[NLMSG_HDRLEN + GENL_HDRLEN] = {};
    auto* nlh = reinterpret_cast<nlmsghdr*>(req);
    nlh->nlmsg_len = sizeof(req);
    nlh->nlmsg_type = GENL_ID_CTRL;
    nlh->nlmsg_flags = NLM_F_REQUEST | NLM_F_DUMP;
    nlh->nlmsg_seq = 1;
    auto* gnlh = reinterpret_cast<genlmsghdr*>(req + NLMSG_HDRLEN);
    gnlh->cmd = CTRL_CMD_GETFAMILY;
    gnlh->version = 1;

    sockaddr_nl kernel{};
    kernel.nl_family = AF_NETLINK;
    if (sendto(fd, req, sizeof(req), 0, reinterpret_cast<sockaddr*>(&kernel),
               sizeof(kernel)) < 0) {
        perror("sendto"); close(fd); return 1;
    }

    timeval tv{ 3, 0 };
    setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));

    char buf[16384];
    int total = 0;
    bool done = false;

    while (!done) {
        ssize_t len = recv(fd, buf, sizeof(buf), 0);
        if (len <= 0) break;

        for (auto* h = reinterpret_cast<nlmsghdr*>(buf);
             NLMSG_OK(h, static_cast<unsigned>(len));
             h = NLMSG_NEXT(h, len)) {

            if (h->nlmsg_type == NLMSG_DONE) { done = true; break; }
            if (h->nlmsg_type == NLMSG_ERROR) { printf("NLMSG_ERROR\n"); done = true; break; }

            const char* name = nullptr;
            int id = -1;

            size_t pos = NLMSG_HDRLEN + GENL_HDRLEN;
            const size_t end = h->nlmsg_len;
            const char* base = reinterpret_cast<const char*>(h);

            while (pos + NLA_HDRLEN <= end) {
                const auto* a = reinterpret_cast<const nlattr*>(base + pos);
                const size_t aLen = a->nla_len;
                if (aLen < NLA_HDRLEN || pos + aLen > end) break;

                const uint16_t t = a->nla_type & NLA_TYPE_MASK;
                if (t == CTRL_ATTR_FAMILY_NAME) name = base + pos + NLA_HDRLEN;
                else if (t == CTRL_ATTR_FAMILY_ID && aLen - NLA_HDRLEN >= 2) {
                    uint16_t v = 0;
                    memcpy(&v, base + pos + NLA_HDRLEN, 2);
                    id = v;
                }
                pos += NLA_ALIGN(aLen);
            }

            if (name) {
                printf("%4d  %s\n", id, name);
                total++;
            }
        }
    }

    close(fd);
    printf("\ntotal families: %d\n", total);
    return 0;
}