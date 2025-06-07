/* SPDX-License-Identifier: GPL-2.0-or-later */
#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/tcp.h>
#include <linux/udp.h>
#include <linux/in.h>
#include <stdbool.h>
#include <linux/types.h>

/* Compat alias per i tipi BSD usati nelle strutture di supporto */
typedef unsigned char  u_int8_t;
typedef unsigned short u_int16_t;
typedef unsigned int   u_int32_t;
#include <stdint.h>

#include "conntrack_structs.h"
#include "conntrack_maps.h"
#include "conntrack_bpf_log.h"
#include "conntrack_parser.h"

/* Costante 1 in order big‑endian (utile per seq/ack) */
static const __u32 BE32_ONE = 0x01000000; /* 1 << 24 */

SEC("xdp")
int xdp_conntrack_prog(struct xdp_md *ctx)
{
    struct packetHeaders pkt = {};
    void *data = (void *)(long)ctx->data;
    void *data_end = (void *)(long)ctx->data_end;

    bpf_printk("Packet received on ifindex %d", ctx->ingress_ifindex);

    if (parse_packet(data, data_end, &pkt) < 0) {
        bpf_log_debug("Failed to parse packet\n");
        return XDP_DROP;
    }
    bpf_log_debug("Packet parsed, starting conntrack\n");

    /* ==== costruzione chiave normalizzata ==== */
    struct ct_k key = {};
    __u8 ipRev = 0, portRev = 0;

    if (pkt.srcIp <= pkt.dstIp) {
        key.srcIp = pkt.srcIp;
        key.dstIp = pkt.dstIp;
        ipRev = 0;
    } else {
        key.srcIp = pkt.dstIp;
        key.dstIp = pkt.srcIp;
        ipRev = 1;
    }

    key.l4proto = pkt.l4proto;

    if (pkt.srcPort < pkt.dstPort) {
        key.srcPort = pkt.srcPort;
        key.dstPort = pkt.dstPort;
        portRev = 0;
    } else if (pkt.srcPort > pkt.dstPort) {
        key.srcPort = pkt.dstPort;
        key.dstPort = pkt.srcPort;
        portRev = 1;
    } else {
        key.srcPort = pkt.srcPort;
        key.dstPort = pkt.dstPort;
        portRev = ipRev; /* per traffico dove porta uguale (es. traceroute) */
    }

    /* ==== variabili utili ==== */
    __u64 now = bpf_ktime_get_ns();
    struct ct_v *ct;
    struct ct_v new_ct = {};

    if (pkt.l4proto == IPPROTO_TCP) {
        /* RST: non tracciamo, lasciamo passare */
        if (pkt.flags & TCPHDR_RST)
            goto PASS;

        ct = bpf_map_lookup_elem(&connections, &key);
        if (ct) {
            /* ===== abbiamo una voce esistente ===== */
            bpf_spin_lock(&ct->lock);
            bool fwd = (ct->ipRev == ipRev)   && (ct->portRev == portRev);
            bool rev = (ct->ipRev != ipRev)   && (ct->portRev != portRev);

            /* direzione inaspettata => INVALID */
            if (!fwd && !rev) {
                pkt.connStatus = INVALID;
                bpf_spin_unlock(&ct->lock);
                goto PASS;
            }

            /* === stato macchina TCP (semplificata) === */
            if (fwd) {
                switch (ct->state) {
                case SYN_SENT:
                    /* aspettiamo solo ACK col flag SYN assente */
                    if (pkt.flags & TCPHDR_ACK) {
                        ct->state = ESTABLISHED; /* handshake completato lato client */
                        ct->ttl   = now + TCP_ESTABLISHED;
                    } else {
                        pkt.connStatus = INVALID;
                    }
                    break;

                case SYN_RECV:
                    if (pkt.flags & TCPHDR_ACK) {
                        ct->state = ESTABLISHED;
                        ct->ttl   = now + TCP_ESTABLISHED;
                    }
                    break;

                case ESTABLISHED:
                    if (pkt.flags & TCPHDR_FIN) {
                        ct->state = FIN_WAIT_1;
                        ct->ttl   = now + TCP_FIN_WAIT;
                    } else {
                        ct->ttl   = now + TCP_ESTABLISHED;
                    }
                    break;

                case FIN_WAIT_1:
                    if (pkt.flags & TCPHDR_ACK) {
                        ct->state = FIN_WAIT_2;
                        ct->ttl   = now + TCP_FIN_WAIT;
                    }
                    break;

                case FIN_WAIT_2:
                    if (pkt.flags & TCPHDR_FIN) {
                        ct->state = LAST_ACK;
                        ct->ttl   = now + TCP_LAST_ACK;
                    }
                    break;

                case LAST_ACK:
                    if (pkt.flags & TCPHDR_ACK) {
                        ct->state = TIME_WAIT;
                        ct->ttl   = now + TCP_TIME_WAIT;
                    }
                    break;

                case TIME_WAIT:
                    /* rinnovo TTL senza cambiare stato */
                    ct->ttl = now + TCP_TIME_WAIT;
                    break;
                default:
                    break;
                }
            } else if (rev) {
                switch (ct->state) {
                case SYN_SENT:
                    /* server risponde con SYN|ACK */
                    if ((pkt.flags & (TCPHDR_SYN|TCPHDR_ACK)) == (TCPHDR_SYN|TCPHDR_ACK)) {
                        ct->state    = SYN_RECV;
                        ct->ttl      = now + TCP_SYN_RECV;
                    } else {
                        pkt.connStatus = INVALID;
                    }
                    break;

                case SYN_RECV:
                    /* resto del handshake */
                    if (pkt.flags & TCPHDR_ACK)
                        ct->ttl = now + TCP_SYN_RECV;
                    break;

                case ESTABLISHED:
                    if (pkt.flags & TCPHDR_FIN) {
                        ct->state = FIN_WAIT_1;
                        ct->ttl   = now + TCP_FIN_WAIT;
                    } else {
                        ct->ttl   = now + TCP_ESTABLISHED;
                    }
                    break;

                case FIN_WAIT_1:
                    if (pkt.flags & TCPHDR_ACK) {
                        ct->state = FIN_WAIT_2;
                        ct->ttl   = now + TCP_FIN_WAIT;
                    }
                    break;

                case FIN_WAIT_2:
                    if (pkt.flags & TCPHDR_FIN) {
                        ct->state = LAST_ACK;
                        ct->ttl   = now + TCP_LAST_ACK;
                    }
                    break;

                case LAST_ACK:
                    if (pkt.flags & TCPHDR_ACK) {
                        ct->state = TIME_WAIT;
                        ct->ttl   = now + TCP_TIME_WAIT;
                    }
                    break;
                case TIME_WAIT:
                    ct->ttl = now + TCP_TIME_WAIT;
                    break;
                default:
                    break;
                }
            }
            bpf_spin_unlock(&ct->lock);
            goto PASS;
        }

        /* ===== entry mancante (TCP_MISS) ===== */
        if (pkt.flags & TCPHDR_SYN) {
            new_ct.state    = SYN_SENT;
            new_ct.ttl      = now + TCP_SYN_SENT;
            new_ct.sequence = pkt.seqN;
            new_ct.ipRev    = ipRev;
            new_ct.portRev  = portRev;
            bpf_map_update_elem(&connections, &key, &new_ct, BPF_ANY);
            pkt.connStatus = NEW;
        } else {
            pkt.connStatus = INVALID;
        }
    }

PASS:
    /* === aggiornamento statistiche === */
    struct pkt_md *md;
    __u32 zero = 0;
    md = bpf_map_lookup_elem(&metadata, &zero);
    if (md) {
        __sync_fetch_and_add(&md->cnt, 1);
        __sync_fetch_and_add(&md->bytes_cnt, (__u16)(data_end - data));
    }

    if (pkt.connStatus == INVALID) {
        bpf_log_err("Connessione INVALID\n");
        return XDP_DROP;
    }

    if (ctx->ingress_ifindex == conntrack_cfg.if_index_if1)
        return bpf_redirect(conntrack_cfg.if_index_if2, 0);
    if (ctx->ingress_ifindex == conntrack_cfg.if_index_if2)
        return bpf_redirect(conntrack_cfg.if_index_if1, 0);

    return XDP_DROP;
}

char __license[] SEC("license") = "Dual BSD/GPL";
