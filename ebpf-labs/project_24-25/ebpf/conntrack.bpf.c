#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>
#include <linux/if_ether.h>
#include <linux/if_packet.h>
#include <linux/ip.h>
#include <linux/ipv6.h>
#include <linux/in.h>
#include <linux/udp.h>
#include <linux/tcp.h>
#include <linux/types.h>
#include <linux/pkt_cls.h>
#include <linux/if_vlan.h>
#include <sys/socket.h>
#include <stdint.h>
#include <stdbool.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>

#include "conntrack_structs.h"
#include "conntrack_maps.h"
#include "conntrack_bpf_log.h"
#include "conntrack_parser.h"

int my_pid = 0;

SEC("xdp")
int xdp_conntrack_prog(struct xdp_md *ctx) {
    int rc;
    struct packetHeaders pkt;

    __builtin_memset(&pkt, 0, sizeof(pkt)); // Initialize the packetHeaders structure
    pkt.connStatus = INVALID; // Mark the packet as invalid by default (to avoid verifier errors)

    void *data = (void *)(long)ctx->data;
    void *data_end = (void *)(long)ctx->data_end;

    bpf_printk("Packet received from interface (ifindex) %d", ctx->ingress_ifindex);

    if (parse_packet(data, data_end, &pkt) < 0) {
        bpf_log_debug("Failed to parse packet\n");
        return XDP_DROP;
    }
    uint32_t seq = bpf_ntohl(pkt.seqN);
    uint32_t ack = bpf_ntohl(pkt.ackN);
    bpf_log_debug("Packet parsed, now starting the conntrack. The packet has flags: %x", pkt.flags);

    struct ct_k key;
    __builtin_memset(&key, 0, sizeof(key));
    uint8_t ipRev = 0;
    uint8_t portRev = 0;

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
        portRev = ipRev;
    }

    struct ct_v newEntry;
    __builtin_memset(&newEntry, 0, sizeof(newEntry));
    struct ct_v *value;

    uint64_t timestamp;
    timestamp = bpf_ktime_get_ns();

    /* == UDP == */
    if (pkt.l4proto == IPPROTO_UDP) {
        struct ct_v *value = bpf_map_lookup_elem(&connections, &key);
        if (value) {
            if (ipRev == value->ipRev && portRev == value->portRev) { // Determine flow direction
                bpf_log_debug("[FW_DIRERCTION]");
            } else {
                bpf_log_debug("[REV_DIRECTION]");
            }
            bpf_spin_lock(&value->lock);
            value->state = ESTABLISHED;
            value->ttl   = timestamp + UDP_ESTABLISHED_TIMEOUT;
            bpf_spin_unlock(&value->lock);
            bpf_log_debug("UDP flow already exists, updating state to ESTABLISHED. TTL = %llu\n", value->ttl);
            pkt.connStatus = ESTABLISHED;
        } else {
            struct ct_v newEntry = {};
            newEntry.state   = NEW;
            newEntry.ttl     = timestamp + UDP_NEW_TIMEOUT;
            newEntry.ipRev   = ipRev;
            newEntry.portRev = portRev;
            bpf_map_update_elem(&connections, &key, &newEntry, BPF_ANY);
            bpf_log_debug("[FW_DIRERCTION] UDP flow not found, creating new entry. TTL = %llu\n", newEntry.ttl);
            pkt.connStatus = NEW;
        }
        goto PASS_ACTION;
    }

    /* == TCP  == */
    if (pkt.l4proto == IPPROTO_TCP) {
        if ((pkt.flags & TCPHDR_RST) != 0) {
            value = bpf_map_lookup_elem(&connections, &key);
            if (value != NULL) {
                bpf_map_delete_elem(&connections, &key);
                bpf_log_debug("RST received on a existing connection, deleting connection entry.\n");
            } else {
                bpf_log_debug("RST received on a non-existing connection, nothing to delete.\n");
            }
            bpf_log_debug("RESETTING CONNECTION.\n");
            pkt.connStatus = RST; // Set the connStatus to RST
            goto PASS_ACTION;
        }
        value = bpf_map_lookup_elem(&connections, &key);
        if (value != NULL) {    // When a new packet arrives, value is NULL and we go to TCP_MISS
            bpf_spin_lock(&value->lock);    // We need to lock the value to prevent data races
            if (value->ttl < timestamp) {
                bpf_spin_unlock(&value->lock);
                bpf_map_delete_elem(&connections, &key); // If the entry has expired, we remove it
                bpf_log_debug("Connection expired. Removing entry.\n");
                goto TCP_MISS;
            }
            if ((value->ipRev == ipRev) && (value->portRev == portRev)) {
                goto TCP_FORWARD;
            } else if ((value->ipRev != ipRev) && (value->portRev != portRev)) {
                goto TCP_REVERSE;
            } else {
                bpf_spin_unlock(&value->lock);
                goto TCP_MISS;
            }

        TCP_FORWARD:;
            //Here SYN_SENT is not needed

            if (value->state == SYN_RECV) {
                if ((pkt.flags & TCPHDR_ACK) != 0 && (pkt.flags | TCPHDR_ACK) == TCPHDR_ACK &&
                    (pkt.ackN == value->sequence + HEX_BE_ONE)) {
                    value->state = ESTABLISHED;
                    value->ttl = timestamp + TCP_ESTABLISHED;

                    bpf_spin_unlock(&value->lock);
                    bpf_log_debug("[FW_DIRECTION] Changing "
                                  "state from "
                                  "SYN_RECV to ESTABLISHED\n");
                    pkt.connStatus = ESTABLISHED;

                    goto PASS_ACTION;
                } else {
                    pkt.connStatus = INVALID;
                    bpf_spin_unlock(&value->lock);
                    bpf_log_debug("[FW_DIRECTION] Failed ACK "
                                  "check in "
                                  "SYN_RECV state. Flags: %x\n",
                                  pkt.flags);
                    goto PASS_ACTION;
                }
            }

            if (value->state == ESTABLISHED) {
                if ((pkt.flags & TCPHDR_FIN) != 0) { // Initiating closing sequence
                    value->state = FIN_WAIT_1;
                    value->ttl = timestamp + TCP_FIN_WAIT;
                    value->sequence = pkt.seqN;

                    bpf_spin_unlock(&value->lock);
                    bpf_log_debug("[FW_DIRECTION] Changing "
                                  "state from "
                                  "ESTABLISHED to FIN_WAIT_1. Seq: %u"
                                  " SRC port: %u\n",
                                  value->sequence, bpf_ntohs(pkt.srcPort));
                    pkt.connStatus = FIN_WAIT_1;

                    goto PASS_ACTION;
                } else {
                    value->ttl = timestamp + TCP_ESTABLISHED;
                    bpf_spin_unlock(&value->lock);
                    bpf_log_debug("Connnection is ESTABLISHED\n");
                    pkt.connStatus = ESTABLISHED;
                    goto PASS_ACTION;
                }
            }

            if (value->state == FIN_WAIT_1) {
                bool ack_only = (pkt.flags & (TCPHDR_ACK | TCPHDR_FIN)) == TCPHDR_ACK; // Four-way close
                bool fin_ack  = (pkt.flags & (TCPHDR_ACK | TCPHDR_FIN)) // Four-way close with piggyback
                                == (TCPHDR_ACK  | TCPHDR_FIN);
                bool fin_only = (pkt.flags & (TCPHDR_ACK | TCPHDR_FIN)) == TCPHDR_FIN; // FIN/FIN (simultaneous) close

                if (ack_only && pkt.ackN == value->sequence + HEX_BE_ONE) {
                    value->state    = CLOSE_WAIT;
                    value->ttl      = timestamp + TCP_CLOSE_WAIT;
                    value->sequence = pkt.seqN;
                    bpf_spin_unlock(&value->lock);
                    bpf_log_debug("[FW_DIRECTION] Changing state from ESTABLISHED to CLOSE_WAIT\n");
                    bpf_log_debug("[REV_DIRECTION] Changing state (on ACK received) from "
                                  "FIN_WAIT_1 to FIN_WAIT_2\n");
                    pkt.connStatus = CLOSE_WAIT;
                    goto PASS_ACTION;

                } else if (fin_ack && pkt.ackN == value->sequence + HEX_BE_ONE) {
                    value->state = LAST_ACK;
                    value->ttl   = timestamp + TCP_LAST_ACK;
                    value->sequence = pkt.seqN;
                    bpf_spin_unlock(&value->lock);
                    bpf_log_debug("[FW_DIRECTION] Changing state from ESTABLISHED to LAST_ACK (piggyback)\n");
                    bpf_log_debug("[REV_DIRECTION] Will skip FIN_WAIT_2\n");
                    pkt.connStatus = LAST_ACK;
                    goto PASS_ACTION;

                } else if (fin_only || fin_ack) { 
                    value->state = CLOSING;
                    value->ttl = timestamp + TCP_CLOSING_TIMEOUT;
                    bpf_spin_unlock(&value->lock);
                    bpf_log_debug("[FW/REV_DIRECTION] Simultaneous close detected. FIN_WAIT_1 -> CLOSING\n");
                    pkt.connStatus = CLOSING;
                    goto PASS_ACTION;
                } else {
                    value->ttl      = timestamp + TCP_FIN_WAIT;
                    bpf_spin_unlock(&value->lock);
                    bpf_log_debug("[FW_DIRECTION] FIN_WAIT_1: invalid flag %x\n",
                                pkt.flags);
                    pkt.connStatus = INVALID;
                    goto PASS_ACTION;
                }
            }
            if (value->state == CLOSE_WAIT) {
                if ((pkt.flags & TCPHDR_FIN) != 0 && pkt.seqN == value->sequence) {
                    value->state = LAST_ACK;
                    value->ttl = timestamp + TCP_LAST_ACK;
                    value->sequence = pkt.seqN;
                    bpf_spin_unlock(&value->lock);
                    bpf_log_debug("[FW_DIRECTION] Changing "
                                  "state from "
                                  "CLOSE_WAIT to LAST_ACK\n");
                    pkt.connStatus = LAST_ACK;

                    goto PASS_ACTION;
                } else {
                    value->ttl = timestamp + TCP_CLOSE_WAIT;
                    bpf_spin_unlock(&value->lock);
                    pkt.connStatus = CLOSE_WAIT;
                    goto PASS_ACTION;
                }
            }

            if (value->state == FIN_WAIT_2) {
                if ((pkt.flags & TCPHDR_ACK) != 0 && pkt.seqN == value->sequence) {
                    value->state = LAST_ACK;
                    value->ttl = timestamp + TCP_LAST_ACK;
                    value->sequence = pkt.seqN;
                    bpf_spin_unlock(&value->lock);
                    bpf_log_debug("[FW_DIRECTION] Changing "
                                  "state from "
                                  "FIN_WAIT_2 to LAST_ACK\n");
                    pkt.connStatus = LAST_ACK;

                    goto PASS_ACTION;
                } else {
                    value->ttl = timestamp + TCP_FIN_WAIT;
                    bpf_spin_unlock(&value->lock);
                    bpf_log_debug("[FW_DIRECTION] Failed FIN "
                                  "check in "
                                  "FIN_WAIT_2 state. Flags: %d. Seq: %d\n",
                                  pkt.flags, value->sequence);
                    pkt.connStatus = FIN_WAIT_2;

                    goto PASS_ACTION;
                }
            }

            if (value->state == CLOSING) {
                if ((pkt.flags & TCPHDR_ACK) != 0) {
                    value->state = TIME_WAIT;
                    value->ttl = timestamp + TCP_TIME_WAIT;
                    bpf_spin_unlock(&value->lock);
                    
                    bpf_log_debug("Transition from CLOSING to TIME_WAIT.\n");
                    pkt.connStatus = TIME_WAIT;
                    goto PASS_ACTION;
                }
                bpf_spin_unlock(&value->lock);
                goto PASS_ACTION;
            }

            if (value->state == LAST_ACK) {
                if ((pkt.flags & TCPHDR_ACK) != 0 && pkt.ackN == value->sequence + HEX_BE_ONE) {
                    value->state = TIME_WAIT;
                    value->ttl = timestamp + TCP_LAST_ACK;

                    bpf_spin_unlock(&value->lock);
                    bpf_log_debug("[FW_DIRECTION] Changing "
                                  "state from "
                                  "FIN_WAIT_2 to TIME_WAIT\n");
                    pkt.connStatus = TIME_WAIT;
                    goto PASS_ACTION;
                }
                value->ttl = timestamp + TCP_LAST_ACK;
                bpf_spin_unlock(&value->lock);
                pkt.connStatus = LAST_ACK;
                goto PASS_ACTION;
            }

            if (value->state == TIME_WAIT) {
                bpf_spin_unlock(&value->lock);
                bpf_log_debug("[FW_DIRECTION] Packet received for connection in TIME_WAIT. Passing through.\n");
                pkt.connStatus = TIME_WAIT;
                goto PASS_ACTION;
            }

            bpf_spin_unlock(&value->lock);
            bpf_log_debug("[FW_DIRECTION] Should not get here. "
                          "Flags: %x. State: %d. \n",
                          pkt.flags, value->state);
            goto PASS_ACTION;

        TCP_REVERSE:;
            if (value->state == SYN_SENT) {
                if ((pkt.flags & TCPHDR_ACK) != 0 && (pkt.flags & TCPHDR_SYN) != 0 &&
                    (pkt.flags | (TCPHDR_SYN | TCPHDR_ACK)) == (TCPHDR_SYN | TCPHDR_ACK) &&
                    pkt.ackN == value->sequence + HEX_BE_ONE) { // Check if the packet is a SYN-ACK packet NB the ack number is incremented by 1 (BIG-ENDIAN)
                    value->state = SYN_RECV;
                    value->ttl = timestamp + TCP_SYN_RECV;
                    value->sequence = pkt.seqN;
                    bpf_spin_unlock(&value->lock);
                    bpf_log_debug("[REV_DIRECTION] Changing "
                                  "state from "
                                  "SYN_SENT to SYN_RECV\n");
                    pkt.connStatus = SYN_RECV;

                    goto PASS_ACTION;
                }
                pkt.connStatus = INVALID;
                bpf_spin_unlock(&value->lock);
                goto PASS_ACTION;
            }

            if (value->state == ESTABLISHED) {
                if ((pkt.flags & TCPHDR_FIN) != 0) { // Initiating closing sequence
                    value->state = FIN_WAIT_1;
                    value->ttl = timestamp + TCP_FIN_WAIT;
                    value->sequence = pkt.seqN;
                    bpf_spin_unlock(&value->lock);
                    bpf_log_debug("[REV_DIRECTION] Changing "
                                  "state from "
                                  "ESTABLISHED to FIN_WAIT_1. Seq: %x"
                                  " SRC port: %d\n",
                                  value->sequence, bpf_ntohs(pkt.dstPort));
                    pkt.connStatus = FIN_WAIT_1;
                    goto PASS_ACTION;
                } else {
                    value->ttl = timestamp + TCP_ESTABLISHED;
                    bpf_spin_unlock(&value->lock);
                    bpf_log_debug("Connnection is ESTABLISHED\n");
                    pkt.connStatus = ESTABLISHED;
                    goto PASS_ACTION;
                }
            }

            if (value->state == FIN_WAIT_1) { // See comments on FW branch
                bool ack_only = (pkt.flags & (TCPHDR_ACK | TCPHDR_FIN)) == TCPHDR_ACK;
                bool fin_ack  = (pkt.flags & (TCPHDR_ACK | TCPHDR_FIN))
                                == (TCPHDR_ACK  | TCPHDR_FIN);

                if (ack_only && pkt.ackN == value->sequence + HEX_BE_ONE) {
                    value->state    = CLOSE_WAIT;
                    value->ttl      = timestamp + TCP_CLOSE_WAIT;
                    value->sequence = pkt.seqN;
                    bpf_spin_unlock(&value->lock);
                    bpf_log_debug("[REV_DIRECTION] Changing state form ESTABLISHED to CLOSE_WAIT\n");
                    bpf_log_debug("[FW_DIRECTION] Changing state (on ACK received) from "
                                  "FIN_WAIT_1 to FIN_WAIT_2\n");
                    pkt.connStatus = CLOSE_WAIT;
                    goto PASS_ACTION;

                } else if (fin_ack && pkt.ackN == value->sequence + HEX_BE_ONE) {
                    value->state = LAST_ACK;
                    value->ttl   = timestamp + TCP_LAST_ACK;
                    value->sequence = pkt.seqN;
                    bpf_spin_unlock(&value->lock);
                    bpf_log_debug("[REV_DIRECTION] Changing state from ESTABLISHED to LAST_ACK (piggyback)\n");
                    bpf_log_debug("[FW_DIRECTION] Will skip FIN_WAIT_2\n");
                    pkt.connStatus = LAST_ACK;
                    goto PASS_ACTION;

                } else {
                    value->ttl      = timestamp + TCP_FIN_WAIT;
                    bpf_spin_unlock(&value->lock);
                    bpf_log_debug("[REV_DIRECTION] FIN_WAIT_1: invalid flag %x\n",
                                pkt.flags);
                    pkt.connStatus = INVALID;
                    goto PASS_ACTION;
                }
            }

            if (value->state == CLOSE_WAIT) {
                if ((pkt.flags & TCPHDR_FIN) != 0 && pkt.seqN == value->sequence) {
                    value->state = LAST_ACK;
                    value->ttl = timestamp + TCP_LAST_ACK;
                    value->sequence = pkt.seqN;
                    bpf_spin_unlock(&value->lock);
                    bpf_log_debug("[REV_DIRECTION] Changing "
                                  "state from "
                                  "CLOSE_WAIT to LAST_ACK\n");
                    pkt.connStatus = LAST_ACK;

                    goto PASS_ACTION;
                } else {
                    value->ttl = timestamp + TCP_CLOSE_WAIT;
                    bpf_spin_unlock(&value->lock);
                    pkt.connStatus = CLOSE_WAIT;
                    goto PASS_ACTION;
                }
            }

            if (value->state == FIN_WAIT_2) {
                if ((pkt.flags & TCPHDR_ACK) != 0 && pkt.seqN == value->sequence) { // Check the sequence number, not the ack number && pkt.seqN == value->sequence
                    value->state = LAST_ACK;
                    value->ttl = timestamp + TCP_LAST_ACK;
                    value->sequence = pkt.seqN;
                    bpf_spin_unlock(&value->lock);
                    bpf_log_debug("[REV_DIRECTION] Changing "
                                  "state from "
                                  "FIN_WAIT_2 to LAST_ACK\n");
                    pkt.connStatus = LAST_ACK;

                    goto PASS_ACTION;
                } else {
                    value->ttl = timestamp + TCP_FIN_WAIT;
                    bpf_spin_unlock(&value->lock);
                    bpf_log_debug("[REV_DIRECTION] Failed FIN "
                                  "check in "
                                  "FIN_WAIT_2 state. Flags: %d. Seq: %d\n",
                                  pkt.flags, value->sequence);
                    pkt.connStatus = FIN_WAIT_2;

                    goto PASS_ACTION;
                }
            }

            if (value->state == CLOSING) {
                // Nello stato CLOSING, stiamo aspettando l'ACK finale per il nostro FIN.
                if ((pkt.flags & TCPHDR_ACK) != 0) {
                    value->state = TIME_WAIT;
                    value->ttl = timestamp + TCP_TIME_WAIT; // Imposta il timeout finale
                    bpf_spin_unlock(&value->lock);
                    
                    bpf_log_debug("Transition from CLOSING to TIME_WAIT.\n");
                    pkt.connStatus = TIME_WAIT;
                    goto PASS_ACTION;
                }
                // Se non è un ACK, per ora ignoriamo e manteniamo lo stato.
                // Potremmo semplicemente estendere il TTL e uscire.
                bpf_spin_unlock(&value->lock);
                goto PASS_ACTION;
            }

            if (value->state == LAST_ACK) {
                if ((pkt.flags & TCPHDR_ACK) != 0 && pkt.ackN == value->sequence + HEX_BE_ONE) { // Check if the packet is an ACK packet and the ack number matches the sequence number
                    value->state = TIME_WAIT;
                    value->ttl = timestamp + TCP_LAST_ACK;
                    bpf_spin_unlock(&value->lock);
                    pkt.connStatus = TIME_WAIT;

                    bpf_log_debug("[REV_DIRECTION] Changing "
                                  "state from "
                                  "FIN_WAIT_2 to TIME_WAIT\n");

                    goto PASS_ACTION;
                }
                // Still receiving packets
                value->ttl = timestamp + TCP_LAST_ACK;
                bpf_spin_unlock(&value->lock);
                pkt.connStatus = LAST_ACK;
                goto PASS_ACTION;
            }

            if (value->state == TIME_WAIT) {
                bpf_spin_unlock(&value->lock);
                bpf_log_debug("[REV_DIRECTION] Packet received for connection in TIME_WAIT. Passing through.\n");
                pkt.connStatus = TIME_WAIT;
                goto PASS_ACTION;
            }
            bpf_spin_unlock(&value->lock);
            bpf_log_debug("[REV_DIRECTION] Should not get here. "
                          "Flags: %d. "
                          "State: %d. \n",
                          pkt.flags, value->state);
            goto PASS_ACTION;
        }

    TCP_MISS:;
        if ((pkt.flags & TCPHDR_SYN) != 0) { // Check if the packet is a SYN packet, in that case we create a new entry
            newEntry.state = SYN_SENT;
            newEntry.ttl = timestamp + TCP_SYN_SENT; // Set the TTL for the SYN_SENT state
            newEntry.sequence = pkt.seqN; // Set the sequence number for the SYN packet

            newEntry.ipRev = ipRev;
            newEntry.portRev = portRev;

            bpf_map_update_elem(&connections, &key, &newEntry, BPF_ANY);

            pkt.connStatus = SYN_SENT; // Set the connStatus to SYN_SENT
            bpf_log_debug("TCP_MISS: New connection created. State: SYN_SENT. Seq: %u\n",
                          bpf_ntohl(newEntry.sequence));
            goto PASS_ACTION;
        } else {
            // Validation failed
            bpf_log_debug("Validation failed. Non-SYN packet for expired/missing connection with flag:%d\n", pkt.flags);
            pkt.connStatus = INVALID; // Set the connStatus to INVALID
            goto PASS_ACTION;
        }
    }

PASS_ACTION:;

    // Use metadata map to store packet metadata (number of packets and bytes)
    // In the map there is only one element with key 0
    struct pkt_md *md;
    __u32 md_key = 0;
    md = bpf_map_lookup_elem(&metadata, &md_key);
    if (md == NULL) {
        bpf_log_err("No elements found in metadata map\n");
        goto DROP;
    }

    uint16_t pkt_len = (uint16_t)(data_end - data);

    __sync_fetch_and_add(&md->cnt, 1);
    __sync_fetch_and_add(&md->bytes_cnt, pkt_len);

    if (pkt.connStatus == INVALID) {
        bpf_log_err("Connection status is invalid\n");
        goto DROP;
    }

    // If all checks passed, we can redirect the packet to the other interface based on ifindex
    if (ctx->ingress_ifindex == conntrack_cfg.if_index_if1) {
        bpf_log_debug("Redirect pkt to IF2 iface with ifindex: %d\n", conntrack_cfg.if_index_if2);
        return bpf_redirect(conntrack_cfg.if_index_if2, 0);
    } else if (ctx->ingress_ifindex == conntrack_cfg.if_index_if2) {
        bpf_log_debug("Redirect pkt to IF1 iface with ifindex: %d\n", conntrack_cfg.if_index_if1);
        return bpf_redirect(conntrack_cfg.if_index_if1, 0);
    } else {
        bpf_log_err("Unknown interface. Dropping packet\n");
        goto DROP;
    }

DROP:;
    bpf_log_debug("Dropping packet!\n");
    return XDP_DROP;
}

char LICENSE[] SEC("license") = "Dual BSD/GPL";