#undef NDEBUG
#define PVEFW_LOGGER_TEST
#include "../pvefw-logger.c"

#include <assert.h>
#include <malloc.h>
#include <stdint.h>
#include <sys/mman.h>

/* packets are accessed through the header structs, so align their buffers like those */
#define PKT_ALIGNED __attribute__((aligned(4)))

static int tests_run = 0;

static void
pass(const char *desc)
{
    tests_run++;
    printf("ok %d - %s\n", tests_run, desc);
}

static void
skip(const char *desc, const char *reason)
{
    tests_run++;
    printf("ok %d - %s # SKIP %s\n", tests_run, desc, reason);
}

static void
assert_log_ends_with(const struct log_entry *le, const char *expected)
{
    size_t len = strlen(expected);

    if (le->len < len || strcmp(le->buf + le->len - len, expected) != 0) {
        fprintf(stderr, "log entry '%s' does not end with '%s'\n", le->buf, expected);
        abort();
    }
}

static char *guard_page = NULL;
static size_t page_size = 0;

static void
setup_guard_page(void)
{
    page_size = (size_t)sysconf(_SC_PAGESIZE);
    char *base = mmap(NULL, page_size * 2, PROT_READ | PROT_WRITE,
                      MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    assert(base != MAP_FAILED);
    guard_page = base + page_size;
    assert(mprotect(guard_page, page_size, PROT_NONE) == 0);
}

/*
 * Place the packet right before the inaccessible guard page, so reading past its end crashes even
 * without a sanitizer. Keep the 4-byte alignment of netlink attributes, which leaves up to three
 * padding bytes before the guard page.
 */
static char *
place_before_guard(const void *data, size_t len)
{
    size_t aligned_len = (len + 3) & ~(size_t)3;
    assert(aligned_len <= page_size);
    char *dst = guard_page - aligned_len;
    memset(dst, 0xAA, aligned_len);
    memcpy(dst, data, len);
    return dst;
}

typedef int (*packet_printer)(struct log_entry *le, char *payload, int payload_len);

/*
 * Run the printer on the guard page copy and on an exact-size heap copy, which a sanitizer build
 * checks without padding, and require both to produce the same result.
 */
static int
run_printer(packet_printer print, const void *pkt, size_t len, struct log_entry *le)
{
    char *heap_buf = malloc(len > 0 ? len : 1);
    assert(heap_buf != NULL);
    memcpy(heap_buf, pkt, len);
    memset(le, 0, sizeof(*le));
    int rc = print(le, heap_buf, (int)len);
    free(heap_buf);

    struct log_entry guard_le;
    memset(&guard_le, 0, sizeof(guard_le));
    int guard_rc = print(&guard_le, place_before_guard(pkt, len), (int)len);

    assert(rc == guard_rc);
    assert(memcmp(le, &guard_le, sizeof(*le)) == 0);
    assert(le->len < LE_MAX);
    assert(le->buf[le->len] == '\0');
    return rc;
}

static void
init_ip4_hdr(struct iphdr *h, uint8_t protocol, uint16_t tot_len)
{
    memset(h, 0, sizeof(*h));
    h->version = 4;
    h->ihl = 5;
    h->tot_len = htons(tot_len);
    h->ttl = 64;
    h->protocol = protocol;
    assert(inet_pton(AF_INET, "192.0.2.1", &h->saddr) == 1);
    assert(inet_pton(AF_INET, "192.0.2.2", &h->daddr) == 1);
}

static void
init_ip6_hdr(struct ip6_hdr *h, uint8_t nxt, uint16_t plen)
{
    memset(h, 0, sizeof(*h));
    h->ip6_flow = htonl(0x60000000);
    h->ip6_plen = htons(plen);
    h->ip6_nxt = nxt;
    h->ip6_hlim = 255;
    assert(inet_pton(AF_INET6, "fe80::1", &h->ip6_src) == 1);
    assert(inet_pton(AF_INET6, "fe80::2", &h->ip6_dst) == 1);
}

static void
init_udp_hdr(struct udphdr *h)
{
    memset(h, 0, sizeof(*h));
    h->source = htons(1234);
    h->dest = htons(5678);
    h->len = htons(sizeof(*h));
}

static void
test_ip4_packets(void)
{
    struct log_entry le;
    uint8_t pkt[sizeof(struct iphdr) + sizeof(struct tcphdr)] PKT_ALIGNED;
    struct iphdr *ip4 = (struct iphdr *)pkt;

    init_ip4_hdr(ip4, IPPROTO_UDP, sizeof(*ip4) + sizeof(struct udphdr));
    init_udp_hdr((struct udphdr *)(ip4 + 1));
    assert(run_printer(print_iphdr, pkt, sizeof(*ip4) + sizeof(struct udphdr), &le) == 0);
    assert(strcmp(le.buf, "SRC=192.0.2.1 DST=192.0.2.2 LEN=28 TOS=0x00 PREC=0x00 TTL=64 ID=0 "
                  "PROTO=UDP SPT=1234 DPT=5678 LEN=8") == 0);
    pass("IPv4 UDP packet is logged");

    init_ip4_hdr(ip4, IPPROTO_TCP, sizeof(pkt));
    struct tcphdr *tcp = (struct tcphdr *)(ip4 + 1);
    memset(tcp, 0, sizeof(*tcp));
    tcp->source = htons(40000);
    tcp->dest = htons(22);
    tcp->seq = htonl(1);
    tcp->window = htons(64240);
    tcp->syn = 1;
    assert(run_printer(print_iphdr, pkt, sizeof(pkt), &le) == 0);
    assert_log_ends_with(&le, "PROTO=TCP SPT=40000 DPT=22 SEQ=1 ACK=0 WINDOW=64240 SYN ");
    pass("IPv4 TCP packet is logged");
}

static void
test_ip6_packets(void)
{
    struct log_entry le;
    uint8_t pkt[sizeof(struct ip6_hdr) + 8 + sizeof(struct icmp6_hdr)] PKT_ALIGNED;
    struct ip6_hdr *ip6 = (struct ip6_hdr *)pkt;
    struct icmp6_hdr *icmp6 = (struct icmp6_hdr *)(ip6 + 1);

    init_ip6_hdr(ip6, IPPROTO_UDP, sizeof(struct udphdr));
    init_udp_hdr((struct udphdr *)(ip6 + 1));
    assert(run_printer(print_ip6hdr, pkt, sizeof(*ip6) + sizeof(struct udphdr), &le) == 0);
    assert(strcmp(le.buf, "SRC=fe80::1 DST=fe80::2 LEN=8 TC=0 FLOWLBL=0 HOPLIMIT=255 "
                  "PROTO=UDP SPT=1234 DPT=5678 LEN=8") == 0);
    pass("IPv6 UDP packet is logged");

    init_ip6_hdr(ip6, IPPROTO_ICMPV6, sizeof(*icmp6));
    memset(icmp6, 0, sizeof(*icmp6));
    icmp6->icmp6_type = ICMP6_ECHO_REQUEST;
    icmp6->icmp6_id = htons(42);
    icmp6->icmp6_seq = htons(7);
    assert(run_printer(print_ip6hdr, pkt, sizeof(*ip6) + sizeof(*icmp6), &le) == 0);
    assert_log_ends_with(&le, "HOPLIMIT=255 PROTO=ICMPV6 TYPE=128 CODE=0 ID=42 SEQ=7 ");
    pass("ICMPv6 echo request is logged");

    for (size_t len = 0; len < sizeof(*icmp6); len++) {
        init_ip6_hdr(ip6, IPPROTO_ICMPV6, len);
        assert(run_printer(print_ip6hdr, pkt, sizeof(*ip6) + len, &le) == -1);
        assert_log_ends_with(&le, "INVALID=LEN ");
    }
    pass("truncated ICMPv6 header is rejected");

    /* MLDv2 listener reports carry a hop-by-hop header with the router alert option */
    uint8_t *hopopts = (uint8_t *)(ip6 + 1);
    init_ip6_hdr(ip6, IPPROTO_HOPOPTS, 8 + sizeof(*icmp6));
    memset(hopopts, 0, 8 + sizeof(*icmp6));
    hopopts[0] = IPPROTO_ICMPV6;
    hopopts[2] = IP6OPT_ROUTER_ALERT;
    hopopts[3] = 2;
    icmp6 = (struct icmp6_hdr *)(hopopts + 8);
    icmp6->icmp6_type = 143;
    assert(run_printer(print_ip6hdr, pkt, sizeof(pkt), &le) == 0);
    assert_log_ends_with(&le, "HOPLIMIT=255 NEXTHDR=HOPOPTS PROTO=ICMPV6 TYPE=143 CODE=0 ");
    pass("hop-by-hop header followed by ICMPv6 is logged");
}

static void
test_log_entry_truncation(void)
{
    struct log_entry le;

    memset(&le, 0, sizeof(le));
    strcpy(le.buf, "abc");
    le.len = 3;
    le_finish_line(&le);
    assert(le.len == 4 && strcmp(le.buf, "abc\n") == 0);
    pass("log entry is terminated with a newline");

    /* each hop-by-hop header adds 16 characters, far more than fit into one entry */
    const size_t n_ext = 100;
    size_t len = sizeof(struct ip6_hdr) + n_ext * 8;
    uint8_t *pkt = calloc(1, len);
    assert(pkt != NULL);

    init_ip6_hdr((struct ip6_hdr *)pkt, IPPROTO_HOPOPTS, n_ext * 8);
    for (size_t i = 0; i < n_ext; i++) {
        struct ip6_ext *ext = (struct ip6_ext *)(pkt + sizeof(struct ip6_hdr) + i * 8);
        ext->ip6e_nxt = i + 1 < n_ext ? IPPROTO_HOPOPTS : IPPROTO_NONE;
    }
    assert(run_printer(print_ip6hdr, pkt, len, &le) == 0);
    free(pkt);
    assert(le.len == LE_MAX - 1);
    le_finish_line(&le);
    assert(le.len == LE_MAX - 1);
    assert(le.buf[LE_MAX - 2] == '\n' && le.buf[LE_MAX - 1] == '\0');
    pass("overlong log entry is truncated and still ends with a newline");
}

static void
test_status_message_truncation(void)
{
    char msg[LE_MAX * 2];

    memset(msg, 'x', sizeof(msg) - 1);
    msg[sizeof(msg) - 1] = '\0';
    queue = g_async_queue_new_full(g_free);

    /* keep the message out of the system log */
    int mask = setlogmask(LOG_MASK(LOG_EMERG));
    log_status_message(3, "%s", msg);
    setlogmask(mask);

    struct log_entry *le = g_async_queue_try_pop(queue);
    assert(le != NULL && le->len == LE_MAX - 1);
    assert(le->buf[LE_MAX - 2] == '\n' && le->buf[LE_MAX - 1] == '\0');
    g_free(le);

    g_async_queue_unref(queue);
    queue = NULL;
    pass("overlong status message is truncated and still ends with a newline");
}

int __real_nfct_snprintf(char *buf, unsigned int size, const struct nf_conntrack *ct,
                         unsigned int msg_type, unsigned int out_type, unsigned int flags);

static int nfct_fake_len = 0;

/* linked in place of nfct_snprintf() with --wrap, to fake events of any length */
int
__wrap_nfct_snprintf(char *buf, unsigned int size, const struct nf_conntrack *ct,
                     unsigned int msg_type, unsigned int out_type, unsigned int flags)
{
    if (nfct_fake_len == 0)
        return __real_nfct_snprintf(buf, size, ct, msg_type, out_type, flags);

    /* like snprintf(), write what fits and return the full length */
    unsigned int n = MIN((unsigned int)nfct_fake_len, size - 1);
    memset(buf, 'x', n);
    buf[n] = '\0';
    return nfct_fake_len;
}

static void
test_conntrack_event_truncation(void)
{
    struct nf_conntrack *ct = nfct_new();
    assert(ct != NULL);
    queue = g_async_queue_new_full(g_free);

    for (int len = LE_MAX - 4; len <= LE_MAX + 1; len++) {
        nfct_fake_len = len;
        nfct_cb(NULL, NFCT_T_NEW, ct, NULL);
        nfct_fake_len = 0;

        struct log_entry *le = g_async_queue_try_pop(queue);
        assert(le != NULL);
        /* a full entry gives up its last character for the newline */
        assert(le->len == (guint32)MIN(len, LE_MAX - 2) + 1);
        assert(strspn(le->buf, "x") == le->len - 1);
        assert(le->buf[le->len - 1] == '\n' && le->buf[le->len] == '\0');
        g_free(le);
    }

    g_async_queue_unref(queue);
    queue = NULL;
    nfct_destroy(ct);
    pass("conntrack event is truncated to the entry size and ends with a newline");
}

static void
test_queue_full(void)
{
    const char *desc = "entries dropped from a full queue are freed";
    const int n_rounds = 10000;
    struct log_entry *probe[64];

    /* other allocators, like the one of sanitizer builds, may lack glibc's statistics */
    size_t used = mallinfo2().uordblks;
    for (size_t i = 0; i < G_N_ELEMENTS(probe); i++)
        probe[i] = g_new0(struct log_entry, 1);
    gboolean have_stats = mallinfo2().uordblks >= used + 32 * sizeof(struct log_entry);
    for (size_t i = 0; i < G_N_ELEMENTS(probe); i++)
        g_free(probe[i]);

    queue = g_async_queue_new_full(g_free);
    for (int i = 0; i < LQ_LEN; i++)
        queue_log_entry(g_new0(struct log_entry, 1));

    size_t used_before = mallinfo2().uordblks;
    for (int i = 0; i < n_rounds; i++) {
        /* the first dropped entry starts the skip count, the next one increases it */
        skipped_logs = 0;
        queue_log_entry(g_new0(struct log_entry, 1));
        queue_log_entry(g_new0(struct log_entry, 1));
        assert(skipped_logs == 2);
    }
    size_t used_after = mallinfo2().uordblks;

    assert(g_async_queue_length(queue) == LQ_LEN);
    g_async_queue_unref(queue);
    queue = NULL;
    skipped_logs = 0;

    /* without the statistics, only a leak checker like the one of sanitizer builds notices */
    if (!have_stats) {
        skip(desc, "no malloc statistics");
        return;
    }
    /* keeping the dropped entries of either kind would take up about 5 MiB */
    assert(used_after < used_before + 64 * 1024);
    pass(desc);
}

static void
test_negative_payload_len(void)
{
    struct log_entry le;

    /* nflog_get_payload() returns -1 and a NULL pointer for messages without packet data */
    memset(&le, 0, sizeof(le));
    assert(print_iphdr(&le, NULL, -1) == -1);
    assert(print_ip6hdr(&le, NULL, -1) == -1);
    assert(print_arp(&le, NULL, -1) == -1);
    assert(print_tcp(&le, NULL, -1) == -1);
    assert(print_udp(&le, NULL, -1) == -1);
    assert(print_icmp(&le, NULL, -1) == -1);
    assert(print_sctp(&le, NULL, -1) == -1);
    assert(print_icmp6(&le, NULL, -1) == -1);
    assert(print_fragment(&le, NULL, -1) == -1);
    assert(check_ip6ext(&le, NULL, -1) == -1);
    pass("negative payload length is rejected");
}

static void
test_icmp6_nonzero_code(void)
{
    struct log_entry le;
    uint8_t pkt[sizeof(struct ip6_hdr) + sizeof(struct icmp6_hdr)] PKT_ALIGNED;
    struct icmp6_hdr *icmp6 = (struct icmp6_hdr *)(pkt + sizeof(struct ip6_hdr));

    init_ip6_hdr((struct ip6_hdr *)pkt, IPPROTO_ICMPV6, sizeof(*icmp6));
    memset(icmp6, 0, sizeof(*icmp6));
    icmp6->icmp6_type = ICMP6_DST_UNREACH;
    icmp6->icmp6_code = ICMP6_DST_UNREACH_NOPORT;
    assert(run_printer(print_ip6hdr, pkt, sizeof(pkt), &le) == 0);
    assert_log_ends_with(&le, "HOPLIMIT=255 PROTO=ICMPV6 TYPE=1 CODE=4 ");
    pass("ICMPv6 destination unreachable with code 4 is logged");

    icmp6->icmp6_type = ICMP6_PACKET_TOO_BIG;
    icmp6->icmp6_code = 255;
    icmp6->icmp6_mtu = htonl(1280);
    assert(run_printer(print_ip6hdr, pkt, sizeof(pkt), &le) == 0);
    assert_log_ends_with(&le, "HOPLIMIT=255 PROTO=ICMPV6 TYPE=2 CODE=255 MTU=1280 ");
    pass("ICMPv6 message with code 255 is logged");
}

static void
test_conntrack_format_error(void)
{
    struct nf_conntrack *ct = nfct_new();
    assert(ct != NULL);
    queue = g_async_queue_new_full(g_free);

    /* without the layer 4 protocol, nfct_snprintf() fails */
    nfct_set_attr_u8(ct, ATTR_L3PROTO, AF_INET);
    nfct_cb(NULL, NFCT_T_NEW, ct, NULL);
    assert(g_async_queue_length(queue) == 0);

    nfct_set_attr_u8(ct, ATTR_L4PROTO, IPPROTO_UDP);
    nfct_cb(NULL, NFCT_T_NEW, ct, NULL);
    struct log_entry *le = g_async_queue_try_pop(queue);
    assert(le != NULL && le->len > 1 && le->buf[le->len - 1] == '\n');
    g_free(le);

    g_async_queue_unref(queue);
    queue = NULL;
    nfct_destroy(ct);
    pass("conntrack event that cannot be formatted is skipped");
}

int
main(void)
{
    setup_guard_page();

    test_ip4_packets();
    test_ip6_packets();
    test_log_entry_truncation();
    test_status_message_truncation();
    test_conntrack_event_truncation();
    test_queue_full();
    test_negative_payload_len();
    test_icmp6_nonzero_code();
    test_conntrack_format_error();

    printf("1..%d\n", tests_run);
    return 0;
}
