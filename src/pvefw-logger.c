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
#include <netinet/udp.h>
#include <netinet/tcp.h>
#include <netinet/if_ether.h>

#include <glib.h>
#include <glib-unix.h>

static struct nflog_handle *logh = NULL;
static struct nlif_handle *nlifh = NULL;

#define LOGFILE "/var/log/pve-firewall.log"

#define LOCKFILE "/var/lock/pvefw-logger.lck"
#define PIDFILE "/var/run/pvefw-logger.pid"

#define LQ_LEN 512
#define LE_MAX (512 - 16) // try to fit into 512 bytes

struct log_entry { 
    guint32 len; // max LE_MAX chars
    char buf[LE_MAX];
};

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
 
        int res = safe_write(outfd, le->buf, le->len);

        g_free(le);

        if (res < 0) {
            // printf("write failed\n"); // fixme??
        }
    }

    return NULL;
}

static int skipped_logs = 0;

static void log_status_message(const char *fmt, ...);
 
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
            log_status_message("skipped %d log entries (queue full)", skip_tmp);
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


#define LEPRINTF(format, ...) { if (le->len < LE_MAX) le->len += snprintf(le->buf + le->len, LE_MAX - le->len, format, ##__VA_ARGS__); }
#define LEPRINTTIME(sec) { time_t tmp_sec = sec; if (le->len < (LE_MAX - 30)) le->len += strftime(le->buf + le->len, LE_MAX - le->len, "%d/%b/%Y:%H:%M:%S %z ", localtime(&tmp_sec)); }

static void 
log_status_message(const char *fmt, ...) 
{
    va_list ap;
    va_start(ap, fmt);
    
    struct log_entry *le = g_new0(struct log_entry, 1);

    LEPRINTTIME(time(NULL));

    le->len += vsnprintf(le->buf + le->len, LE_MAX - le->len, fmt, ap);

    LEPRINTF("\n");

    queue_log_entry(le);
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

    switch (h->protocol) {
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
        LEPRINTF("PROTO=%u ", h->protocol);
    }

    return 0;
}

static int 
print_ip6hdr(struct log_entry *le, char * payload, int payload_len)
{
    LEPRINTF("IPV6 logging not implemented ");

    return 0;
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
    
    struct timeval ts;
    nflog_get_timestamp(ldata, &ts);

    LEPRINTTIME(ts.tv_sec);

    //le->len += strftime(le->buf + le->len, LE_MAX - le->len, "%d/%b/%Y:%H:%M:%S %z ", localtime(&ts.tv_sec));

    if (prefix != NULL) {
        LEPRINTF("%s", prefix);
    }
    
    if ((indev > 0) && (nlif_index2name(nlifh, indev, devname) != -1)) {
        LEPRINTF("IN=%s ", devname); 
    }

    if ((outdev > 0) && (nlif_index2name(nlifh, outdev, devname) != -1)) {
        LEPRINTF("OUT=%s ", devname);
    }

    if ((physindev > 0) && (nlif_index2name(nlifh, physindev, devname) != -1)) {
        LEPRINTF("PHYSIN=%s ", devname);
    }
         
    if ((physoutdev > 0) &&  (nlif_index2name(nlifh, physoutdev, devname) != -1)) {
        LEPRINTF("PHYSOUT=%s ", devname);
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
    nlif_catch(nlifh);
    // fixme: report  errors
    return TRUE; 
}

GMainLoop *main_loop;

static gboolean
terminate_request(gpointer data) 
{
    terminate_threads = TRUE;

    log_status_message("received terminate request (signal)");

    g_main_loop_quit(main_loop);
    
    return TRUE;
}
                

int
main(int argc, char *argv[])
{
    int lockfd = -1;
    gboolean foreground = FALSE;
    gboolean wrote_pidfile = FALSE;

    g_thread_init(NULL);

    if ((lockfd = open(LOCKFILE, O_RDWR|O_CREAT|O_APPEND, 0644)) == -1) {
        fprintf(stderr, "unable to create lock '%s': %s", LOCKFILE, strerror (errno));
        exit(-1);
    }

    for (int i = 10; i >= 0; i--) {
        if (flock(lockfd, LOCK_EX|LOCK_NB) != 0) {
            if (!i) {
                fprintf(stderr, "unable to aquire lock '%s': %s", LOCKFILE, strerror (errno));
                exit(-1);
            }
            if (i == 10)
                fprintf(stderr, "unable to aquire lock '%s' - trying again.\n", LOCKFILE);
            
            sleep(1);
        }
    }

    if ((outfd = open(LOGFILE, O_WRONLY|O_CREAT|O_APPEND, 0644)) == -1) {
        fprintf(stderr, "unable to open file '%s': %s", LOGFILE, strerror (errno));
        exit(-1);
    }

    if ((logh = nflog_open())  == NULL) {
        fprintf(stderr, "unable to open nflog\n");
        exit(-1);
    }

    if (!nflog_bind_pf(logh, AF_INET) <= 0) {
        fprintf(stderr, "nflog_bind_pf AF_INET failed\n");
        exit(-1);
    }

#if 0
    if (!nflog_bind_pf(logh, AF_INET6) <= 0) {
        fprintf(stderr, "nflog_bind_pf AF_INET6 failed\n");
        exit(-1);
    }
#endif
    
    if (!nflog_bind_pf(logh, AF_BRIDGE) <= 0) {
        fprintf(stderr, "nflog_bind_pf AF_BRIDGE failed\n");
        exit(-1);
    }

    struct nflog_g_handle *qh = nflog_bind_group(logh, 0);
    if (!qh) {
        fprintf(stderr, "no handle for group 1\n");
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

    log_status_message("starting pvefw logger");

    nlif_query(nlifh);

    GIOChannel *nlif_ch = g_io_channel_unix_new(nlif_fd(nlifh));

    g_io_add_watch(nlif_ch, G_IO_IN, nlif_read_cb, NULL);

    int logfd = nflog_fd(logh);
    GIOChannel *nflog_ch = g_io_channel_unix_new(logfd);

    g_io_add_watch(nflog_ch, G_IO_IN, nflog_read_cb, NULL);

    GThread *wthread = g_thread_new("log_writer_thread", log_writer_thread, NULL);
    
    main_loop = g_main_loop_new(NULL, TRUE);
    
    g_unix_signal_add(SIGINT, terminate_request, NULL);
    g_unix_signal_add(SIGTERM, terminate_request, NULL);
    
    g_main_loop_run(main_loop);

    log_status_message("stopping pvefw logger");

    g_thread_join(wthread);

    close(outfd);

    nflog_close(logh);

    if (wrote_pidfile)
        unlink(PIDFILE);

    exit(0);
}
