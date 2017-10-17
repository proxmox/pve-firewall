/*

  Copyright (C) 2014 Proxmox Server Solutions GmbH

  This software is written by Proxmox Server Solutions GmbH <support@proxmox.com>

  This program is free software: you can redistribute it and/or modify
  it under the terms of the GNU Affero General Public License as published by
  the Free Software Foundation, either version 3 of the License, or
  (at your option) any later version.

  This program is distributed in the hope that it will be useful,
  but WITHOUT ANY WARRANTY; without even the implied warranty of
  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
  GNU Affero General Public License for more details.

  You should have received a copy of the GNU Affero General Public License
  along with this program.  If not, see <http://www.gnu.org/licenses/>.

  Author: Dietmar Maurer <dietmar@proxmox.com>

*/

#define _GNU_SOURCE

#include <stdlib.h>
#include <stdio.h>
#include <errno.h>
#include <stdarg.h>
#include <string.h>
#include <signal.h>
#include <sys/signalfd.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <sys/file.h>
#include <linux/netlink.h>
#include <libnfnetlink/libnfnetlink.h>
#include <libnetfilter_log/libnetfilter_log.h>
#include <netinet/ip.h>
#include <netinet/ip_icmp.h>
#include <netinet/ip6.h>
#include <netinet/icmp6.h>
#include <netinet/udp.h>
#include <netinet/tcp.h>
#include <netinet/if_ether.h>
#include <syslog.h>

#include <glib.h>

static struct nflog_handle *logh = NULL;
static struct nlif_handle *nlifh = NULL;
GMainLoop *main_loop;

gboolean foreground = FALSE;
gboolean debug = FALSE;

/*

LOG FORMAT:

Special care was taken to allow fast parsing (and filer messages for a singl VM).

<VMID> <LOGLEVEL> <CHAIN> <TIME> <TIMEZONE> <MSG>

Example:

117 6 tap117i0-IN 14/Mar/2014:12:47:07 +0100 policy REJECT: IN=vmbr1 ...

*/

#define LOGFILE "/var/log/pve-firewall.log"

#define LOCKFILE "/var/lock/pvefw-logger.lck"
#define PIDFILE "/var/run/pvefw-logger.pid"

#define LQ_LEN 512
#define LE_MAX (512 - 4) // try to fit into 512 bytes

#define MAX_CHAIN_LEN 28

struct log_entry {
    guint32 len; // max LE_MAX chars
    char buf[LE_MAX];
};

#define STATIC_ASSERT(cond) \
    extern void pve_static_assert(int test[(cond) ? 1 : -1])

STATIC_ASSERT(sizeof(struct log_entry) == 512);

int outfd = -1;

gboolean terminate_threads = FALSE;

static gboolean write_pidfile(pid_t pid)
{
    gboolean res;

    char *strpid = g_strdup_printf("%d\n", pid);
    res = g_file_set_contents(PIDFILE, strpid, strlen(strpid), NULL);
    g_free(strpid);

    return res;
}

static GAsyncQueue *queue;

ssize_t
safe_write(int fd, char *buf, size_t count)
{
  ssize_t n;

  do {
    n = write(fd, buf, count);
  } while (n < 0 && errno == EINTR);

  return n;
}

static gpointer
log_writer_thread(gpointer data)
{
    while (1) {
        struct log_entry *le = (struct log_entry *)g_async_queue_timeout_pop(queue, 250000);
        if (le == NULL) {
            if (terminate_threads) {
                return NULL;
            }
            continue;
        }

        if (debug) fputs(le->buf, stdout);

        int res = safe_write(outfd, le->buf, le->len);

        g_free(le);

        if (res < 0) {
            syslog(3, "writing log failed, stopping daemon - %s", strerror (errno));
            g_main_loop_quit(main_loop);
            return NULL;
        }
    }

    return NULL;
}

static int skipped_logs = 0;

static void log_status_message(guint loglevel, const char *fmt, ...);

static void
queue_log_entry(struct log_entry *le)
{
    gint len = g_async_queue_length(queue);

    if (skipped_logs > 0) {
        if (len >= (LQ_LEN - 1)) {
            skipped_logs++;
        } else {
            int skip_tmp = skipped_logs;
            skipped_logs = 0; // clear before calling log_status_message()
            log_status_message(3, "skipped %d log entries (queue full)", skip_tmp);
            g_async_queue_push(queue, le);
        }
    } else {
        if (len >= LQ_LEN) {
            skipped_logs++;
        } else {
            g_async_queue_push(queue, le);
        }
    }
}


#define LEPRINTF(format, ...) \
    do { \
        if (le->len < LE_MAX) \
            le->len += snprintf(le->buf + le->len, LE_MAX - le->len, format, ##__VA_ARGS__); \
    } while (0)
#define LEPRINTTIME(sec) \
    do { \
        time_t tmp_sec = sec; \
        if (le->len < (LE_MAX - 30)) \
            le->len += strftime(le->buf + le->len, LE_MAX - le->len, "%d/%b/%Y:%H:%M:%S %z ", localtime(&tmp_sec)); \
    } while (0)

static void
log_status_message(guint loglevel, const char *fmt, ...)
{
    va_list ap;
    va_start(ap, fmt);

    if (loglevel > 7 ) loglevel = 7; // syslog defines level 0-7

    struct log_entry *le = g_new0(struct log_entry, 1);

    LEPRINTF("0 %d - ", loglevel);

    LEPRINTTIME(time(NULL));

    le->len += vsnprintf(le->buf + le->len, LE_MAX - le->len, fmt, ap);

    LEPRINTF("\n");

    queue_log_entry(le);

    // also log to syslog

    vsyslog(loglevel, fmt, ap);
}

static int
print_tcp(struct log_entry *le, struct tcphdr *h, int payload_len)
{
    LEPRINTF("PROTO=TCP ");

    if (payload_len < sizeof(struct tcphdr)) {
        LEPRINTF("LEN=%d ", payload_len);
        LEPRINTF("INVALID=LEN ");
        return -1;
    }

    LEPRINTF("SPT=%u DPT=%u ", ntohs(h->source), ntohs(h->dest));
    LEPRINTF("SEQ=%u ACK=%u ", ntohl(h->seq), ntohl(h->ack_seq));
    LEPRINTF("WINDOW=%u ", ntohs(h->window));

    if (h->urg) LEPRINTF("URG ");
    if (h->ack) LEPRINTF("ACK ");
    if (h->psh) LEPRINTF("PSH ");
    if (h->rst) LEPRINTF("RST ");
    if (h->syn) LEPRINTF("SYN ");
    if (h->fin) LEPRINTF("FIN ");

    if (h->urg) LEPRINTF("URGP=%u ",ntohs(h->urg_ptr));

    return 0;
}

static int
print_udp(struct log_entry *le, struct udphdr *h, int payload_len)
{
    LEPRINTF("PROTO=UDP ");

    if (payload_len < sizeof(struct udphdr)) {
        LEPRINTF("LEN=%d ", payload_len);
        LEPRINTF("INVALID=LEN ");
        return -1;
    }

    LEPRINTF("SPT=%u DPT=%u LEN=%u", ntohs(h->source), ntohs(h->dest), ntohs(h->len));

    return 0;
}

static int
print_icmp(struct log_entry *le, struct icmphdr *h, int payload_len)
{
    char tmp[INET_ADDRSTRLEN];
    u_int32_t gateway;

    LEPRINTF("PROTO=ICMP ");

    if (payload_len < sizeof(struct icmphdr)) {
        LEPRINTF("LEN=%d ", payload_len);
        LEPRINTF("INVALID=LEN ");
        return -1;
    }

    LEPRINTF("TYPE=%u CODE=%u ", h->type, h->code);

    switch (h->type) {
    case ICMP_ECHO:
    case ICMP_ECHOREPLY:
        LEPRINTF("ID=%u SEQ=%u ", ntohs(h->un.echo.id), ntohs(h->un.echo.sequence));
        break;
    case ICMP_PARAMETERPROB:
        LEPRINTF("PARAMETER=%u ", ntohl(h->un.gateway) >> 24);
        break;
    case ICMP_REDIRECT:
        gateway = ntohl(h->un.gateway);
        inet_ntop(AF_INET, &gateway, tmp, sizeof(tmp));
        LEPRINTF("GATEWAY=%s ", tmp);
        break;
    case ICMP_DEST_UNREACH:
        if (h->code == ICMP_FRAG_NEEDED) {
            LEPRINTF("MTU=%u ", ntohs(h->un.frag.mtu));
        }
        break;
    }

    return 0;
}

/* Section 3.1.  SCTP Common Header Format */
typedef struct sctphdr {
	__be16 source;
	__be16 dest;
	__be32 vtag;
	__be32 checksum;
} __attribute__((packed)) sctp_sctphdr_t;

static int
print_sctp(struct log_entry *le, struct sctphdr *h, int payload_len)
{
    LEPRINTF("PROTO=SCTP ");

    if (payload_len < sizeof(struct sctphdr)) {
        LEPRINTF("LEN=%d ", payload_len);
        LEPRINTF("INVALID=LEN ");
        return -1;
    }

    LEPRINTF("SPT=%u DPT=%u ", ntohs(h->source), ntohs(h->dest));

    return 0;
}

static int
print_ipproto(struct log_entry *le, char * nexthdr, int payload_len, u_int8_t proto)
{
    switch (proto) {
    case IPPROTO_TCP:
        print_tcp(le, (struct tcphdr *)nexthdr, payload_len);
        break;
    case IPPROTO_UDP:
        print_udp(le, (struct udphdr *)nexthdr, payload_len);
        break;
    case IPPROTO_ICMP:
        print_icmp(le, (struct icmphdr *)nexthdr, payload_len);
        break;
    case IPPROTO_SCTP:
        print_sctp(le, (struct sctphdr *)nexthdr, payload_len);
        break;
    case IPPROTO_AH:
        LEPRINTF("PROTO=AH ");
        break;
    case IPPROTO_ESP:
        LEPRINTF("PROTO=ESP ");
        break;
    case IPPROTO_IGMP:
        LEPRINTF("PROTO=IGMP ");
        break;
     default:
        return -1;
    }
    return 0;
}

static int
print_iphdr(struct log_entry *le, char * payload, int payload_len)
{
    if (payload_len < sizeof(struct iphdr)) {
       LEPRINTF("LEN=%d ", payload_len);
       LEPRINTF("INVALID=LEN ");
       return -1;
    }

    struct iphdr *h = (struct iphdr *)payload;

    if (payload_len <= (u_int32_t)(h->ihl * 4)) {
        LEPRINTF("INVALID=IHL ");
        return -1;
    }

    char tmp[INET_ADDRSTRLEN];

    inet_ntop(AF_INET, &h->saddr, tmp, sizeof(tmp));
    LEPRINTF("SRC=%s ", tmp);
    inet_ntop(AF_INET, &h->daddr, tmp, sizeof(tmp));
    LEPRINTF("DST=%s ", tmp);

    LEPRINTF("LEN=%u TOS=0x%02X PREC=0x%02X TTL=%u ID=%u ",
             ntohs(h->tot_len),  h->tos & IPTOS_TOS_MASK,
             h->tos & IPTOS_PREC_MASK, h->ttl, ntohs(h->id));

    short ip_off = ntohs(h->frag_off);
    if (ip_off & IP_OFFMASK)
        LEPRINTF("FRAG=%u ", ip_off & IP_OFFMASK);

    if (ip_off & IP_DF) LEPRINTF("DF ");
    if (ip_off & IP_MF) LEPRINTF("MF ");

    void *nexthdr = (u_int32_t *)h + h->ihl;
    payload_len -= h->ihl * 4;

    if (print_ipproto(le, nexthdr, payload_len, h->protocol) < 0) {
        LEPRINTF("PROTO=%u ", h->protocol);
    }

    return 0;
}

static int
print_routing(struct log_entry *le, struct ip6_rthdr *rthdr, int payload_len)
{
    char tmp[INET6_ADDRSTRLEN];
    LEPRINTF("TYPE=%u SEGMENTS=%u", rthdr->ip6r_type, rthdr->ip6r_segleft);

    if (payload_len < sizeof(*rthdr) || payload_len < rthdr->ip6r_len*8) {
        LEPRINTF("LEN=%d ", payload_len);
        LEPRINTF("INVALID=LEN ");
        return -1;
    }

    if (rthdr->ip6r_type == 0) {
        /* Route via waypoints (deprecated), this contains a list of waypoints
         * to visit. (RFC2460 (4.4))
         */
        struct ip6_rthdr0 *h = (struct ip6_rthdr0*)rthdr;
        if (rthdr->ip6r_len*8 < sizeof(*h) + rthdr->ip6r_segleft * sizeof(struct in6_addr)) {
            LEPRINTF("INVALID=SEGMENTS ");
            return 0;
        }
        return 0;
    } else if (rthdr->ip6r_type == 1) {
        /* nimrod routing (RFC1992) */
        return 0;
    } else if (rthdr->ip6r_type == 2) {
        /* RFC3375 (6.4), the layout is like type-0 but with exactly 1 address */
        struct ip6_rthdr0 *h = (struct ip6_rthdr0*)rthdr;
        if (rthdr->ip6r_len*8 < sizeof(*h) + sizeof(struct in6_addr)) {
            LEPRINTF("LEN=%d ", payload_len);
            LEPRINTF("INVALID=LEN ");
            return -1;
        }
        inet_ntop(AF_INET6, &h->ip6r0_addr[0], tmp, sizeof(tmp));
        LEPRINTF("HOME=%s ", tmp);
        return 0;
    }

    return 0;
}

static int
print_fragment(struct log_entry *le, struct ip6_frag *frag, int payload_len)
{
    u_int16_t offlg;

    if (payload_len < sizeof(*frag)) {
        LEPRINTF("LEN=%d ", payload_len);
        LEPRINTF("INVALID=LEN ");
        return -1;
    }

    offlg = ntohs(frag->ip6f_offlg);
    LEPRINTF("FRAG=%d ID=%d ", (offlg&0x2FFF), ntohl(frag->ip6f_ident));
    if (offlg>>15) {
        LEPRINTF("MF ");
    }
    return 0;
}

static int
print_icmp6(struct log_entry *le, struct icmp6_hdr *h, int payload_len)
{
    struct nd_router_advert *ra;
    struct nd_neighbor_advert *na;
    struct nd_redirect *re;
    char tmp[INET6_ADDRSTRLEN];

    if (payload_len < sizeof(struct icmp6_hdr)) {
        LEPRINTF("LEN=%d ", payload_len);
        LEPRINTF("INVALID=LEN ");
        return -1;
    }

    LEPRINTF("TYPE=%u CODE=%u ", h->icmp6_type, h->icmp6_code);

    switch (h->icmp6_type) {
    case ICMP6_ECHO_REQUEST:
    case ICMP6_ECHO_REPLY:
        LEPRINTF("ID=%u SEQ=%u ", ntohs(h->icmp6_id), ntohs(h->icmp6_seq));
        break;

    case ND_ROUTER_SOLICIT:
        /* can be followed by options, otherwise nothing to print */
        break;

    case ND_ROUTER_ADVERT:
        ra = (struct nd_router_advert*)h;
        LEPRINTF("HOPLIMIT=%d ", ra->nd_ra_curhoplimit);
        /* nd_ra_flags_reserved is only 8 bit, so no swapping here as
         * opposed to the neighbor advertisement flags (see below).
         */
        LEPRINTF("RA=%02x LIFETIME=%d REACHABLE=%d RETRANSMIT=%d ",
                 ra->nd_ra_flags_reserved,
                 ntohs(ra->nd_ra_router_lifetime),
                 ntohl(ra->nd_ra_reachable),
                 ntohl(ra->nd_ra_retransmit));
        /* can be followed by options */
        break;

    case ND_NEIGHBOR_SOLICIT:
        /* can be followed by options */
        break;

    case ND_NEIGHBOR_ADVERT:
        na = (struct nd_neighbor_advert*)h;
        LEPRINTF("NA=%08x ", ntohl(na->nd_na_flags_reserved));
        /* can be followed by options */
        break;

    case ND_REDIRECT:
        re = (struct nd_redirect*)h;
        inet_ntop(AF_INET6, &re->nd_rd_target, tmp, sizeof(tmp));
        LEPRINTF("TARGET=%s ", tmp);
        inet_ntop(AF_INET6, &re->nd_rd_dst, tmp, sizeof(tmp));
        LEPRINTF("GATEWAY=%s ", tmp);
        /* can be followed by options */
        break;

    case ICMP6_DST_UNREACH:
        /* CODE shows the type, no extra parameters available in ipv6 */
        break;

    case ICMP6_PACKET_TOO_BIG:
        LEPRINTF("MTU=%u ", ntohl(h->icmp6_mtu));
        break;

    case ICMP6_TIME_EXCEEDED:
        /* CODE shows the type (0 = hop limit, 1 = reassembly timed out) */
        break;

    case ICMP6_PARAM_PROB:
        switch (ntohl(h->icmp6_pptr)) {
        case ICMP6_PARAMPROB_HEADER:
            LEPRINTF("PARAMETER=HEADER "); /* erroneous header */
            break;
        case ICMP6_PARAMPROB_NEXTHEADER:
            LEPRINTF("PARAMETER=NEXTHEADER "); /* bad next-header field */
            break;
        case ICMP6_PARAMPROB_OPTION:
            LEPRINTF("PARAMETER=OPTION "); /* bad ipv6 option (hop/dst header?) */
            break;
        default:
            LEPRINTF("PARAMETER=%u ", ntohl(h->icmp6_pptr)); /* unknown */
            break;
        }
        break;
    }

    return 0;
}

static int
check_ip6ext(struct log_entry *le, struct ip6_ext *exthdr, int payload_len)
{
    if (payload_len < sizeof(*exthdr) ||
        payload_len < exthdr->ip6e_len)
    {
        LEPRINTF("LEN=%d ", payload_len);
        LEPRINTF("INVALID=LEN ");
        return -1;
    }
    return 0;
}

static int
print_nexthdr(struct log_entry *le, char *hdr, int payload_len, u_int8_t proto)
{
    while (1) {
        if (print_ipproto(le, hdr, payload_len, proto) == 0)
            return 0;

        struct ip6_ext *exthdr = (struct ip6_ext*)hdr;

        switch (proto) {
        /* protocols (these return) */
        case IPPROTO_ICMPV6:
            LEPRINTF("PROTO=ICMPV6 ");
            if (check_ip6ext(le, exthdr, payload_len) < 0)
                return -1;
            if (print_icmp6(le, (struct icmp6_hdr*)(hdr + exthdr->ip6e_len),
                            payload_len - exthdr->ip6e_len) < 0)
            {
                return -1;
            }
            return 0;

        /* extension headers (these break to keep iterating) */
        case IPPROTO_ROUTING:
            if (check_ip6ext(le, exthdr, payload_len) < 0)
                return -1;
            if (print_routing(le, (struct ip6_rthdr*)hdr, payload_len) < 0)
                return -1;
            break;
        case IPPROTO_FRAGMENT:
            if (check_ip6ext(le, exthdr, payload_len) < 0)
                return -1;
            if (print_fragment(le, (struct ip6_frag*)hdr, payload_len) < 0)
                return -1;
            break;
        case IPPROTO_HOPOPTS:
            LEPRINTF("NEXTHDR=HOPOPTS ");
            if (check_ip6ext(le, exthdr, payload_len) < 0)
                return -1;
            /* do we want to print these? */
            break;
        case IPPROTO_DSTOPTS:
            LEPRINTF("NEXTHDR=DSTOPTS ");
            if (check_ip6ext(le, exthdr, payload_len) < 0)
                return -1;
            /* do we want to print these? */
            break;
        case IPPROTO_MH:
            LEPRINTF("NEXTHDR=MH ");
            if (check_ip6ext(le, exthdr, payload_len) < 0)
                return -1;
            break;

        /* unknown protocol */
        default:
            LEPRINTF("PROTO=%u ", proto);
            return 0; /* bail */
        }
        /* next header: */
        if (check_ip6ext(le, exthdr, payload_len) < 0)
            return -1;
        hdr += exthdr->ip6e_len;
        payload_len -= exthdr->ip6e_len;
    }
}

static int
print_ip6hdr(struct log_entry *le, char * payload, int payload_len)
{
    if (payload_len < sizeof(struct ip6_hdr)) {
        LEPRINTF("LEN=%d ", payload_len);
        LEPRINTF("INVALID=LEN ");
        return -1;
    }

    struct ip6_hdr *h = (struct ip6_hdr*)payload;

    char tmp[INET6_ADDRSTRLEN];
    inet_ntop(AF_INET6, &h->ip6_src, tmp, sizeof(tmp));
    LEPRINTF("SRC=%s ", tmp);
    inet_ntop(AF_INET6, &h->ip6_dst, tmp, sizeof(tmp));
    LEPRINTF("DST=%s ", tmp);

    LEPRINTF("LEN=%u ", ntohs(h->ip6_plen));

    u_int32_t flow = ntohl(h->ip6_flow);
    LEPRINTF("TC=%d FLOWLBL=%d ", (flow>>20)&0xFF, flow&0xFFFFF);

    LEPRINTF("HOPLIMIT=%d ", h->ip6_hlim);

    return print_nexthdr(le, (char *)(h+1), payload_len - sizeof(*h), h->ip6_nxt);
}

// ebtables -I FORWARD --nflog --nflog-group 0
static int
print_arp(struct log_entry *le, struct ether_arp *h, int payload_len)
{
    if (payload_len < sizeof(struct ether_arp)) {
        LEPRINTF("LEN=%d ", payload_len);
        LEPRINTF("INVALID=LEN ");
        return -1;
    }

    LEPRINTF("SRC=%u.%u.%u.%u ", h->arp_spa[0], h->arp_spa[1],
             h->arp_spa[2], h->arp_spa[3]);

    LEPRINTF("DST=%u.%u.%u.%u ", h->arp_tpa[0], h->arp_tpa[1],
             h->arp_tpa[2], h->arp_tpa[3]);

    LEPRINTF("PROTO=ARP ");

    unsigned short code = ntohs(h->arp_op);
    switch (code) {
    case ARPOP_REQUEST:
        LEPRINTF("REQUEST ");
        break;
    case ARPOP_REPLY:
        LEPRINTF("REPLY MAC=%02x:%02x:%02x:%02x:%02x:%02x ",
                 h->arp_sha[0], h->arp_sha[1], h->arp_sha[2],
                 h->arp_sha[3], h->arp_sha[4], h->arp_sha[5]);
        break;
    case ARPOP_NAK:
        LEPRINTF("NAK ");
        break;
    default:
        LEPRINTF("CODE=%u ", code);
    }


    // LEPRINTF("HTYPE=%u ", ntohs(h->arp_hrd));

    // LEPRINTF("PTYPE=%u ", ntohs(h->arp_pro));

    return 0;
}


static int print_pkt(struct log_entry *le, struct nflog_data *ldata, u_int8_t family)
{
    u_int32_t mark = nflog_get_nfmark(ldata);
    u_int32_t indev = nflog_get_indev(ldata);
    u_int32_t outdev = nflog_get_outdev(ldata);
    u_int32_t physindev = nflog_get_physindev(ldata);
    u_int32_t physoutdev = nflog_get_physoutdev(ldata);

    char *prefix = nflog_get_prefix(ldata);
    char *payload;
    char devname[256];

    guint32 vmid = 0;

    guint8 log_level = 6; // info

    char *chain_name = "-";

    if (prefix != NULL) {
        // Note: parse ":$vmid:$loglevel:$chain: $msg"
        if (prefix[0] == ':') {
            char *p = prefix + 1;
            guint32 tmpid = 0;
            while(*p  >= '0' && *p <= '9') { tmpid *= 10; tmpid += *p - '0'; p++; }

            if ((*p == ':') &&
                (p[1] >= '0' && p[1] <= '7') &&
                (p[2] == ':')) {

                guint8 tmp_level = p[1] - '0'; // store for later use
                char *chain_start = p + 3; // store for later use
                p = chain_start;
                while (*p && *p != ':' && *p != ' ') p++;
                int len = p - chain_start;

                if (*p == ':' && p[1] == ' ' && len && (len <= MAX_CHAIN_LEN)) {
                    // parsing successful

                    *p = 0; // terminate string

                    vmid = tmpid;
                    log_level = tmp_level;
                    chain_name = chain_start;
                    prefix = p + 2; // the rest
                }
            }
        }
    }

    LEPRINTF("%d ", vmid);

    LEPRINTF("%d ", log_level);

    LEPRINTF("%s ", chain_name);

    struct timeval ts;
    if (nflog_get_timestamp(ldata, &ts) == 0) {
        LEPRINTTIME(ts.tv_sec);
    } else {
        LEPRINTTIME(time(NULL));
    }

    if (prefix != NULL) {
        LEPRINTF("%s", prefix);
    }

    if (indev > 0) {
        if (nlif_index2name(nlifh, indev, devname) != -1) {
            LEPRINTF("IN=%s ", devname);
        } else {
            LEPRINTF("IN=%u ", indev);
        }
    }

    if (outdev > 0) {
        if (nlif_index2name(nlifh, outdev, devname) != -1) {
            LEPRINTF("OUT=%s ", devname);
        } else {
            LEPRINTF("OUT=%u ", outdev);
        }
    }

    if (physindev > 0) {
        if (nlif_index2name(nlifh, physindev, devname) != -1) {
            LEPRINTF("PHYSIN=%s ", devname);
        } else {
            LEPRINTF("PHYSIN=%u ", physindev);
        }
    }

    if (physoutdev > 0) {
        if (nlif_index2name(nlifh, physoutdev, devname) != -1) {
            LEPRINTF("PHYSOUT=%s ", devname);
        } else {
            LEPRINTF("PHYSOUT=%u ", physoutdev);
        }
    }

    int payload_len = nflog_get_payload(ldata, &payload);

    int hwhdrlen = nflog_get_msg_packet_hwhdrlen(ldata);
    if (hwhdrlen > 0) {
        unsigned char *hwhdr = (unsigned char *)nflog_get_msg_packet_hwhdr(ldata);
        if (hwhdr != NULL) {
            int i;
            LEPRINTF("MAC=");
            for (i = 0; i < hwhdrlen; i++) {
                LEPRINTF("%02x", hwhdr[i]);
                if (i < (hwhdrlen -1 )) LEPRINTF(":");
            }
            LEPRINTF(" ");
        }
    }

    u_int16_t hw_protocol = 0;
    struct nfulnl_msg_packet_hdr *ph = NULL;

    switch (family) {
    case AF_INET:
        print_iphdr(le, payload, payload_len);
        break;
    case AF_INET6:
        print_ip6hdr(le, payload, payload_len);
        break;
    case AF_BRIDGE:
        ph = nflog_get_msg_packet_hdr(ldata);
        if (ph) hw_protocol = ntohs(ph->hw_protocol);

        switch (hw_protocol) {
        case ETH_P_IP:
            print_iphdr(le, payload, payload_len);
            break;
        case ETH_P_IPV6:
             print_ip6hdr(le, payload, payload_len);
            break;
        case ETH_P_ARP:
            print_arp(le, (struct ether_arp *)payload, payload_len);
            break;
        }
        break;
    }

    if (mark) LEPRINTF("mark=%u ", mark);


    return 0;

}

static int
nflog_cb(struct nflog_g_handle *gh, struct nfgenmsg *nfmsg,
               struct nflog_data *nfa, void *data)
{
    struct log_entry *le = g_new0(struct log_entry, 1);

    print_pkt(le, nfa, nfmsg->nfgen_family);

    LEPRINTF("\n"); // add newline

    queue_log_entry(le);

    return 0;
}

static gboolean
nflog_read_cb(GIOChannel *source,
              GIOCondition condition,
              gpointer data)
{
    int rv = 0;
    gchar buf[8192];

    int fd =  g_io_channel_unix_get_fd(source);

    if ((rv = recv(fd, buf, sizeof(buf), 0)) && rv >= 0) {
         nflog_handle_packet(logh, buf, rv);
    }

    return TRUE;
}

static gboolean
nlif_read_cb(GIOChannel *source,
             GIOCondition condition,
             gpointer data)
{
    static int last_res = 0;
    int res;

    if ((res = nlif_catch(nlifh)) < 0) {
        if (last_res == 0) { // only report once
            log_status_message(3, "nlif_catch failed (res = %d)", res);
        }
        last_res = res;
    } else {
        last_res = 0;
    }

    return TRUE;
}

static gboolean
signal_read_cb(GIOChannel *source,
               GIOCondition condition,
               gpointer data)
{
    int rv = 0;
    struct signalfd_siginfo si;

    int fd =  g_io_channel_unix_get_fd(source);

    if ((rv = read(fd, &si, sizeof(si))) && rv >= 0) {
        terminate_threads = TRUE;
        log_status_message(5, "received terminate request (signal)");
        g_main_loop_quit(main_loop);
    }

    return TRUE;
}

int
main(int argc, char *argv[])
{
    int lockfd = -1;
    int sigfd = -1;

    gboolean wrote_pidfile = FALSE;

    openlog("pvefw-logger", LOG_CONS|LOG_PID, LOG_DAEMON);

    GOptionContext *context;

    GOptionEntry entries[] = {
        { "debug", 'd', 0, G_OPTION_ARG_NONE, &debug, "Turn on debug messages", NULL },
        { "foreground", 'f', 0, G_OPTION_ARG_NONE, &foreground, "Do not daemonize server", NULL },
        { NULL },
    };

    context = g_option_context_new("");
    g_option_context_add_main_entries (context, entries, NULL);

    GError *err = NULL;
    if (!g_option_context_parse (context, &argc, &argv, &err)) {
        fprintf(stderr, "error: %s\n", err->message);
        fprintf(stderr, "%s", g_option_context_get_help(context, FALSE, NULL));
        g_error_free (err);
        exit(-1);
    }

    if (optind < argc) {
        fprintf(stderr, "error: too many arguments\n");
        fprintf(stderr, "%s", g_option_context_get_help(context, FALSE, NULL));
        exit(-1);
    }

    g_option_context_free(context);

    if (debug) foreground = TRUE;

    if ((lockfd = open(LOCKFILE, O_RDWR|O_CREAT|O_APPEND, 0644)) == -1) {
        fprintf(stderr, "unable to create lock '%s': %s\n", LOCKFILE, strerror (errno) );
        exit(-1);
    }

    for (int i = 10; i >= 0; i--) {
        if (flock(lockfd, LOCK_EX|LOCK_NB) != 0) {
            if (!i) {
                fprintf(stderr, "unable to aquire lock '%s': %s\n", LOCKFILE, strerror (errno));
                exit(-1);
            }
            if (i == 10)
                fprintf(stderr, "unable to aquire lock '%s' - trying again.\n", LOCKFILE);

            sleep(1);
        }
    }

    if ((outfd = open(LOGFILE, O_WRONLY|O_CREAT|O_APPEND, 0644)) == -1) {
        fprintf(stderr, "unable to open file '%s': %s\n", LOGFILE, strerror (errno));
        exit(-1);
    }

    if ((logh = nflog_open())  == NULL) {
        fprintf(stderr, "unable to open nflog\n");
        exit(-1);
    }

    if (nflog_bind_pf(logh, AF_INET) < 0) {
        fprintf(stderr, "nflog_bind_pf AF_INET failed\n");
        exit(-1);
    }

#if 0
    if (!nflog_bind_pf(logh, AF_INET6) <= 0) {
        fprintf(stderr, "nflog_bind_pf AF_INET6 failed\n");
        exit(-1);
    }
#endif

    if (nflog_bind_pf(logh, AF_BRIDGE) < 0) {
        fprintf(stderr, "nflog_bind_pf AF_BRIDGE failed\n");
        exit(-1);
    }

    struct nflog_g_handle *qh = nflog_bind_group(logh, 0);
    if (!qh) {
        fprintf(stderr, "no nflog handle for group 0\n");
        exit(-1);
    }

    if (nflog_set_mode(qh, NFULNL_COPY_PACKET, 0xffff) < 0) {
        fprintf(stderr, "can't set packet copy mode\n");
        exit(-1);
    }

    if ((nlifh = nlif_open()) == NULL) {
        fprintf(stderr, "unable to open netlink interface handle\n");
        exit(-1);
    }

    sigset_t mask;
    sigemptyset(&mask);
    sigaddset(&mask, SIGINT);
    sigaddset(&mask, SIGTERM);
    
    sigprocmask(SIG_BLOCK, &mask, NULL);

    if ((sigfd = signalfd(-1, &mask, SFD_NONBLOCK)) < 0) {
        fprintf(stderr, "unable to open signalfd: %s\n", strerror (errno));
        exit(-1);
    }

    if (!foreground) {
        pid_t cpid = fork();

        if (cpid == -1) {
            fprintf(stderr, "failed to daemonize program - %s\n", strerror (errno));
            exit(-1);
        } else if (cpid) {
            write_pidfile(cpid);
            _exit(0);
        } else {
            int nullfd;

            if (chroot("/") != 0) fprintf(stderr, "chroot '/' failed - %s\n", strerror (errno));

            if ((nullfd = open("/dev/null", O_RDWR, 0)) != -1) {
                dup2(nullfd, 0);
                dup2(nullfd, 1);
                dup2(nullfd, 2);
                if (nullfd > 2)
                    close (nullfd);
            }

            setsid();
        }
    } else {
        write_pidfile(getpid());
    }

    wrote_pidfile = TRUE;

    nflog_callback_register(qh, &nflog_cb, logh);

    queue = g_async_queue_new_full(g_free);

    log_status_message(5, "starting pvefw logger");

    nlif_query(nlifh);

    GIOChannel *nlif_ch = g_io_channel_unix_new(nlif_fd(nlifh));

    g_io_add_watch(nlif_ch, G_IO_IN, nlif_read_cb, NULL);

    int logfd = nflog_fd(logh);
    GIOChannel *nflog_ch = g_io_channel_unix_new(logfd);

    g_io_add_watch(nflog_ch, G_IO_IN, nflog_read_cb, NULL);

    GIOChannel *sig_ch = g_io_channel_unix_new(sigfd);
    if (!g_io_add_watch(sig_ch, G_IO_IN, signal_read_cb, NULL)) {
        exit(-1);
    }

    GThread *wthread = g_thread_new("log_writer_thread", log_writer_thread, NULL);

    main_loop = g_main_loop_new(NULL, TRUE);

    g_main_loop_run(main_loop);

    log_status_message(5, "stopping pvefw logger");

    g_thread_join(wthread);

    close(outfd);

    nflog_close(logh);

    if (wrote_pidfile)
        unlink(PIDFILE);

    exit(0);
}
