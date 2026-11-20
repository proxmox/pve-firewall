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
                  "PROTO=UDP SPT=1234 DPT=5678 LEN=8 ") == 0);
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
                  "PROTO=UDP SPT=1234 DPT=5678 LEN=8 ") == 0);
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

    icmp6->icmp6_type = ICMP6_PARAM_PROB;
    icmp6->icmp6_code = ICMP6_PARAMPROB_NEXTHEADER;
    icmp6->icmp6_pptr = htonl(6);
    assert(run_printer(print_ip6hdr, pkt, sizeof(pkt), &le) == 0);
    assert_log_ends_with(&le, "PROTO=ICMPV6 TYPE=4 CODE=1 PARAMETER=6 ");
    icmp6->icmp6_pptr = htonl(ICMP6_PARAMPROB_OPTION);
    assert(run_printer(print_ip6hdr, pkt, sizeof(pkt), &le) == 0);
    assert_log_ends_with(&le, "PROTO=ICMPV6 TYPE=4 CODE=1 PARAMETER=2 ");
    pass("ICMPv6 parameter problem is logged with its pointer");
}

static void
test_ip6_ext_header_lengths(void)
{
    struct log_entry le;
    uint8_t pkt[sizeof(struct ip6_hdr) + 16] PKT_ALIGNED;
    uint8_t *ext = pkt + sizeof(struct ip6_hdr);
    const uint8_t ext_protos[] = {
        IPPROTO_HOPOPTS, IPPROTO_DSTOPTS, IPPROTO_ROUTING, IPPROTO_MH, IPPROTO_FRAGMENT,
    };

    for (size_t i = 0; i < G_N_ELEMENTS(ext_protos); i++) {
        for (size_t len = 0; len < 8; len++) {
            init_ip6_hdr((struct ip6_hdr *)pkt, ext_protos[i], len);
            memset(ext, 0, 16);
            ext[0] = IPPROTO_TCP;
            assert(run_printer(print_ip6hdr, pkt, sizeof(struct ip6_hdr) + len, &le) == -1);
            assert_log_ends_with(&le, "INVALID=LEN ");
        }
    }
    pass("extension header shorter than 8 bytes is rejected");

    for (size_t len = 8; len < 16; len++) {
        init_ip6_hdr((struct ip6_hdr *)pkt, IPPROTO_DSTOPTS, len);
        memset(ext, 0, 16);
        ext[0] = IPPROTO_TCP;
        ext[1] = 1; /* (1 + 1) * 8 bytes */
        assert(run_printer(print_ip6hdr, pkt, sizeof(struct ip6_hdr) + len, &le) == -1);
        char expected[64];
        snprintf(expected, sizeof(expected), "NEXTHDR=DSTOPTS LEN=%zu INVALID=LEN ", len);
        assert_log_ends_with(&le, expected);
    }
    pass("extension header longer than the remaining packet is rejected");

    /* the reserved byte of a fragment header is where other extension headers have their length */
    struct ip6_frag *frag = (struct ip6_frag *)ext;
    init_ip6_hdr((struct ip6_hdr *)pkt, IPPROTO_FRAGMENT, sizeof(*frag) + sizeof(struct udphdr));
    memset(frag, 0, sizeof(*frag));
    frag->ip6f_nxt = IPPROTO_UDP;
    frag->ip6f_reserved = 0xff;
    init_udp_hdr((struct udphdr *)(frag + 1));
    assert(run_printer(print_ip6hdr, pkt, sizeof(pkt), &le) == 0);
    assert_log_ends_with(&le, "FRAG=0 ID=0 PROTO=UDP SPT=1234 DPT=5678 LEN=8 ");
    pass("fragment header with a non-zero reserved byte is followed");
}

/* IPv6 packet with a routing header of the given length in 8-byte units, followed by UDP */
static size_t
init_routing_pkt(uint8_t *pkt, uint8_t type, uint8_t len, uint8_t segleft)
{
    size_t rt_len = (len + 1) * 8;
    struct ip6_rthdr0 *rt = (struct ip6_rthdr0 *)(pkt + sizeof(struct ip6_hdr));

    init_ip6_hdr((struct ip6_hdr *)pkt, IPPROTO_ROUTING, rt_len + sizeof(struct udphdr));
    memset(rt, 0, rt_len);
    rt->ip6r0_nxt = IPPROTO_UDP;
    rt->ip6r0_len = len;
    rt->ip6r0_type = type;
    rt->ip6r0_segleft = segleft;
    for (int i = 0; i < len / 2; i++)
        assert(inet_pton(AF_INET6, "2001:db8::99", &rt->ip6r0_addr[i]) == 1);
    init_udp_hdr((struct udphdr *)((uint8_t *)rt + rt_len));

    return sizeof(struct ip6_hdr) + rt_len + sizeof(struct udphdr);
}

static void
test_ip6_routing_header(void)
{
    struct log_entry le;
    uint8_t pkt[sizeof(struct ip6_hdr) + 5 * 8 + sizeof(struct udphdr)] PKT_ALIGNED;
    size_t len;

    len = init_routing_pkt(pkt, 0, 2, 0);
    assert(run_printer(print_ip6hdr, pkt, len, &le) == 0);
    assert_log_ends_with(&le, "HOPLIMIT=255 TYPE=0 SEGMENTS=0 PROTO=UDP SPT=1234 DPT=5678 LEN=8 ");
    pass("routing header is logged with separated fields");

    len = init_routing_pkt(pkt, 0, 4, 2);
    assert(run_printer(print_ip6hdr, pkt, len, &le) == 0);
    assert_log_ends_with(&le, "HOPLIMIT=255 TYPE=0 SEGMENTS=2 PROTO=UDP SPT=1234 DPT=5678 LEN=8 ");
    pass("type 0 routing header with all segments left is logged");

    len = init_routing_pkt(pkt, 0, 4, 3);
    assert(run_printer(print_ip6hdr, pkt, len, &le) == 0);
    assert_log_ends_with(&le, "TYPE=0 SEGMENTS=3 INVALID=SEGMENTS "
                         "PROTO=UDP SPT=1234 DPT=5678 LEN=8 ");
    pass("type 0 routing header with more segments left than addresses is flagged");

    len = init_routing_pkt(pkt, 2, 2, 1);
    assert(run_printer(print_ip6hdr, pkt, len, &le) == 0);
    assert_log_ends_with(&le, "TYPE=2 SEGMENTS=1 HOME=2001:db8::99 "
                         "PROTO=UDP SPT=1234 DPT=5678 LEN=8 ");
    pass("type 2 routing header is logged with its home address");

    len = init_routing_pkt(pkt, 2, 2, 2);
    assert(run_printer(print_ip6hdr, pkt, len, &le) == 0);
    assert_log_ends_with(&le, "TYPE=2 SEGMENTS=2 INVALID=SEGMENTS HOME=2001:db8::99 "
                         "PROTO=UDP SPT=1234 DPT=5678 LEN=8 ");
    pass("type 2 routing header with more than one segment left is flagged");

    len = init_routing_pkt(pkt, 2, 1, 1);
    assert(run_printer(print_ip6hdr, pkt, len, &le) == -1);
    assert_log_ends_with(&le, "TYPE=2 SEGMENTS=1 LEN=24 INVALID=LEN ");
    pass("type 2 routing header without room for the home address is rejected");

    memset(&le, 0, sizeof(le));
    assert(print_routing(&le, NULL, -1) == -1);
    pass("routing header is checked before reading its fields");
}

static void
test_icmp6_nd_lengths(void)
{
    struct log_entry le;
    uint8_t pkt[sizeof(struct ip6_hdr) + sizeof(struct nd_redirect)] PKT_ALIGNED;
    struct icmp6_hdr *icmp6 = (struct icmp6_hdr *)(pkt + sizeof(struct ip6_hdr));
    const struct {
        uint8_t type;
        size_t len;
    } nd_msgs[] = {
        { ND_ROUTER_ADVERT, sizeof(struct nd_router_advert) },
        { ND_NEIGHBOR_SOLICIT, sizeof(struct nd_neighbor_solicit) },
        { ND_NEIGHBOR_ADVERT, sizeof(struct nd_neighbor_advert) },
        { ND_REDIRECT, sizeof(struct nd_redirect) },
    };

    for (size_t i = 0; i < G_N_ELEMENTS(nd_msgs); i++) {
        for (size_t len = sizeof(*icmp6); len < nd_msgs[i].len; len++) {
            init_ip6_hdr((struct ip6_hdr *)pkt, IPPROTO_ICMPV6, len);
            memset(icmp6, 0, nd_msgs[i].len);
            icmp6->icmp6_type = nd_msgs[i].type;
            assert(run_printer(print_ip6hdr, pkt, sizeof(struct ip6_hdr) + len, &le) == -1);
            assert_log_ends_with(&le, "INVALID=LEN ");
        }
    }
    pass("truncated neighbor discovery messages are rejected");

    struct nd_router_advert *ra = (struct nd_router_advert *)icmp6;
    init_ip6_hdr((struct ip6_hdr *)pkt, IPPROTO_ICMPV6, sizeof(*ra));
    memset(ra, 0, sizeof(*ra));
    ra->nd_ra_type = ND_ROUTER_ADVERT;
    ra->nd_ra_curhoplimit = 64;
    ra->nd_ra_flags_reserved = ND_RA_FLAG_MANAGED;
    ra->nd_ra_router_lifetime = htons(1800);
    ra->nd_ra_reachable = htonl(30000);
    ra->nd_ra_retransmit = htonl(1000);
    assert(run_printer(print_ip6hdr, pkt, sizeof(struct ip6_hdr) + sizeof(*ra), &le) == 0);
    assert_log_ends_with(&le, "TYPE=134 CODE=0 HOPLIMIT=64 RA=80 LIFETIME=1800 REACHABLE=30000 "
                         "RETRANSMIT=1000 ");
    pass("router advertisement is logged");

    ra->nd_ra_reachable = htonl(0x80000000);
    ra->nd_ra_retransmit = htonl(UINT32_MAX);
    assert(run_printer(print_ip6hdr, pkt, sizeof(struct ip6_hdr) + sizeof(*ra), &le) == 0);
    assert_log_ends_with(&le, "REACHABLE=2147483648 RETRANSMIT=4294967295 ");
    pass("router advertisement timers are logged as unsigned numbers");

    struct nd_neighbor_advert *na = (struct nd_neighbor_advert *)icmp6;
    init_ip6_hdr((struct ip6_hdr *)pkt, IPPROTO_ICMPV6, sizeof(*na));
    memset(na, 0, sizeof(*na));
    na->nd_na_type = ND_NEIGHBOR_ADVERT;
    na->nd_na_flags_reserved = ND_NA_FLAG_SOLICITED | ND_NA_FLAG_OVERRIDE;
    assert(run_printer(print_ip6hdr, pkt, sizeof(struct ip6_hdr) + sizeof(*na), &le) == 0);
    assert_log_ends_with(&le, "TYPE=136 CODE=0 NA=60000000 ");
    pass("neighbor advertisement is logged");

    struct nd_redirect *rd = (struct nd_redirect *)icmp6;
    init_ip6_hdr((struct ip6_hdr *)pkt, IPPROTO_ICMPV6, sizeof(*rd));
    memset(rd, 0, sizeof(*rd));
    rd->nd_rd_type = ND_REDIRECT;
    assert(inet_pton(AF_INET6, "2001:db8::1", &rd->nd_rd_target) == 1);
    assert(inet_pton(AF_INET6, "2001:db8::2", &rd->nd_rd_dst) == 1);
    assert(run_printer(print_ip6hdr, pkt, sizeof(pkt), &le) == 0);
    assert_log_ends_with(&le, "TYPE=137 CODE=0 TARGET=2001:db8::1 DESTINATION=2001:db8::2 ");
    pass("ICMPv6 redirect is logged with its target and destination");
}

static void
test_ip6_fragment_header(void)
{
    struct log_entry le;
    uint8_t pkt[sizeof(struct ip6_hdr) + sizeof(struct ip6_frag)] PKT_ALIGNED;
    struct ip6_frag *frag = (struct ip6_frag *)(pkt + sizeof(struct ip6_hdr));

    init_ip6_hdr((struct ip6_hdr *)pkt, IPPROTO_FRAGMENT, sizeof(*frag));
    memset(frag, 0, sizeof(*frag));
    frag->ip6f_nxt = IPPROTO_NONE;
    frag->ip6f_offlg = htons(1448) | IP6F_MORE_FRAG;
    frag->ip6f_ident = htonl(0x80000001);
    assert(run_printer(print_ip6hdr, pkt, sizeof(pkt), &le) == 0);
    assert_log_ends_with(&le, "HOPLIMIT=255 FRAG=1448 ID=2147483649 MF PROTO=59 ");
    pass("fragment with more fragments following is logged");

    frag->ip6f_offlg = htons(65528);
    frag->ip6f_ident = htonl(42);
    assert(run_printer(print_ip6hdr, pkt, sizeof(pkt), &le) == 0);
    assert_log_ends_with(&le, "HOPLIMIT=255 FRAG=65528 ID=42 PROTO=59 ");
    pass("last fragment at the highest offset is logged");
}

static void
test_icmp_redirect(void)
{
    struct log_entry le;
    uint8_t pkt[sizeof(struct iphdr) + sizeof(struct icmphdr)] PKT_ALIGNED;
    struct icmphdr *icmp = (struct icmphdr *)(pkt + sizeof(struct iphdr));

    init_ip4_hdr((struct iphdr *)pkt, IPPROTO_ICMP, sizeof(pkt));
    memset(icmp, 0, sizeof(*icmp));
    icmp->type = ICMP_REDIRECT;
    icmp->code = ICMP_REDIR_HOST;
    assert(inet_pton(AF_INET, "192.0.2.254", &icmp->un.gateway) == 1);
    assert(run_printer(print_iphdr, pkt, sizeof(pkt), &le) == 0);
    assert_log_ends_with(&le, "PROTO=ICMP TYPE=5 CODE=1 GATEWAY=192.0.2.254 ");
    pass("ICMP redirect is logged with its gateway");
}

static void
test_ip4_header_length(void)
{
    struct log_entry le;
    uint8_t pkt[sizeof(struct iphdr) + sizeof(struct udphdr)] PKT_ALIGNED;
    struct iphdr *ip4 = (struct iphdr *)pkt;

    for (unsigned int ihl = 0; ihl < 5; ihl++) {
        init_ip4_hdr(ip4, IPPROTO_UDP, sizeof(pkt));
        init_udp_hdr((struct udphdr *)(ip4 + 1));
        ip4->ihl = ihl;
        assert(run_printer(print_iphdr, pkt, sizeof(pkt), &le) == -1);
        assert(strcmp(le.buf, "INVALID=IHL ") == 0);
    }
    pass("IPv4 header length below 20 bytes is rejected");

    init_ip4_hdr(ip4, IPPROTO_UDP, sizeof(pkt));
    ip4->ihl = 6;
    assert(run_printer(print_iphdr, pkt, sizeof(*ip4), &le) == -1);
    assert(strcmp(le.buf, "INVALID=IHL ") == 0);
    pass("IPv4 header length beyond the packet is rejected");

    init_ip4_hdr(ip4, IPPROTO_UDP, sizeof(*ip4));
    assert(run_printer(print_iphdr, pkt, sizeof(*ip4), &le) == 0);
    assert(strcmp(le.buf, "SRC=192.0.2.1 DST=192.0.2.2 LEN=20 TOS=0x00 PREC=0x00 TTL=64 ID=0 "
                  "PROTO=UDP LEN=0 INVALID=LEN ") == 0);
    pass("IPv4 packet without transport header is logged");
}

static void
test_non_first_fragments(void)
{
    struct log_entry le;
    uint8_t pkt4[sizeof(struct iphdr) + sizeof(struct udphdr)] PKT_ALIGNED;
    struct iphdr *ip4 = (struct iphdr *)pkt4;

    init_ip4_hdr(ip4, IPPROTO_UDP, sizeof(pkt4));
    init_udp_hdr((struct udphdr *)(ip4 + 1));
    ip4->frag_off = htons(IP_MF);
    assert(run_printer(print_iphdr, pkt4, sizeof(pkt4), &le) == 0);
    assert_log_ends_with(&le, "ID=0 MF PROTO=UDP SPT=1234 DPT=5678 LEN=8 ");
    ip4->frag_off = htons(IP_MF | 185);
    assert(run_printer(print_iphdr, pkt4, sizeof(pkt4), &le) == 0);
    assert_log_ends_with(&le, "ID=0 FRAG=185 MF PROTO=UDP ");
    ip4->protocol = 99;
    assert(run_printer(print_iphdr, pkt4, sizeof(pkt4), &le) == 0);
    assert_log_ends_with(&le, "ID=0 FRAG=185 MF PROTO=99 ");
    pass("only the first IPv4 fragment is logged with its transport header");

    uint8_t pkt6[sizeof(struct ip6_hdr) + 8 + sizeof(struct udphdr)] PKT_ALIGNED;
    struct ip6_frag *frag = (struct ip6_frag *)(pkt6 + sizeof(struct ip6_hdr));

    init_ip6_hdr((struct ip6_hdr *)pkt6, IPPROTO_FRAGMENT, sizeof(*frag) + sizeof(struct udphdr));
    memset(frag, 0, sizeof(*frag));
    frag->ip6f_nxt = IPPROTO_UDP;
    frag->ip6f_offlg = IP6F_MORE_FRAG;
    frag->ip6f_ident = htonl(1);
    init_udp_hdr((struct udphdr *)(frag + 1));
    assert(run_printer(print_ip6hdr, pkt6, sizeof(pkt6), &le) == 0);
    assert_log_ends_with(&le, "FRAG=0 ID=1 MF PROTO=UDP SPT=1234 DPT=5678 LEN=8 ");
    frag->ip6f_offlg = htons(1448) | IP6F_MORE_FRAG;
    assert(run_printer(print_ip6hdr, pkt6, sizeof(pkt6), &le) == 0);
    assert_log_ends_with(&le, "FRAG=1448 ID=1 MF PROTO=UDP ");
    frag->ip6f_nxt = IPPROTO_DSTOPTS;
    assert(run_printer(print_ip6hdr, pkt6, sizeof(pkt6), &le) == 0);
    assert_log_ends_with(&le, "FRAG=1448 ID=1 MF PROTO=60 ");
    pass("only the first IPv6 fragment is logged with its next header");
}

static void
test_capture_beyond_packet(void)
{
    struct log_entry le;
    uint8_t pkt4[sizeof(struct iphdr) + sizeof(struct udphdr)] PKT_ALIGNED;

    /* padding after a packet that ends with its IP header */
    init_ip4_hdr((struct iphdr *)pkt4, IPPROTO_UDP, sizeof(struct iphdr));
    init_udp_hdr((struct udphdr *)(pkt4 + sizeof(struct iphdr)));
    assert(run_printer(print_iphdr, pkt4, sizeof(pkt4), &le) == 0);
    assert_log_ends_with(&le, "LEN=20 TOS=0x00 PREC=0x00 TTL=64 ID=0 PROTO=UDP LEN=0 INVALID=LEN ");
    ((struct iphdr *)pkt4)->tot_len = 0;
    assert(run_printer(print_iphdr, pkt4, sizeof(pkt4), &le) == 0);
    assert_log_ends_with(&le, "PROTO=UDP SPT=1234 DPT=5678 LEN=8 ");
    pass("IPv4 packet is parsed up to its length only");

    uint8_t pkt6[sizeof(struct ip6_hdr) + sizeof(struct udphdr)] PKT_ALIGNED;

    init_ip6_hdr((struct ip6_hdr *)pkt6, IPPROTO_UDP, 4);
    init_udp_hdr((struct udphdr *)(pkt6 + sizeof(struct ip6_hdr)));
    assert(run_printer(print_ip6hdr, pkt6, sizeof(pkt6), &le) == 0);
    assert_log_ends_with(&le, "LEN=4 TC=0 FLOWLBL=0 HOPLIMIT=255 PROTO=UDP LEN=4 INVALID=LEN ");
    ((struct ip6_hdr *)pkt6)->ip6_plen = 0;
    assert(run_printer(print_ip6hdr, pkt6, sizeof(pkt6), &le) == 0);
    assert_log_ends_with(&le, "PROTO=UDP SPT=1234 DPT=5678 LEN=8 ");
    pass("IPv6 packet is parsed up to its length only");
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
    test_ip6_ext_header_lengths();
    test_ip6_routing_header();
    test_icmp6_nd_lengths();
    test_ip6_fragment_header();
    test_ip4_header_length();
    test_icmp_redirect();
    test_non_first_fragments();
    test_capture_beyond_packet();
    test_conntrack_format_error();

    printf("1..%d\n", tests_run);
    return 0;
}
