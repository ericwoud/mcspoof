
/*
 * mcspoof - MAC spoofing for directly bridging wifi interface to lan
 *
 * Copyright (C) 2019      Eric Woudstra
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License v2
 * as published by the Free Software Foundation.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 */


#include <linux/module.h> 
#include <linux/moduleparam.h>
#include <linux/netfilter.h>
#include <linux/netfilter_bridge.h>
#include <net/tcp.h>
#include <net/udp.h>

MODULE_LICENSE("GPL");
MODULE_AUTHOR("Eric Woudstra");
MODULE_DESCRIPTION("McSpoof changes mac to accomodate wifi directly bridged AP on the local network.");

static const unsigned char mcastip4[] = {0x01,0x00,0x5e};
static const unsigned char mcastip6[] = {0x33,0x33};

static const unsigned char dhcpmagic[] = {0x63,0x82,0x53,0x63};

#define MODNAME "mcspoof"

#define UDP_DHCP_CHADDR_OFFSET 8+1+1+1+1+4+2+2+4+4+4+4
#define UDP_DHCP_MAGICC_OFFSET 8+1+1+1+1+4+2+2+4+4+4+4+16+64+128

#define DHCPOPT_PAD 0
#define DHCPOPT_END 0xff
#define DHCPOPT_CLIENTID 61
#define DHCPOPT_DISCSTRING 130

#define debugprintk if (debug==true) printk

struct arp_payload {
	u_int8_t src_hw[ETH_ALEN];
	__be32 src_ip;
	u_int8_t dst_hw[ETH_ALEN];
	__be32 dst_ip;
} __packed;

const char *hookdesc[] = {"PRE ","IN  ","FORW","OUT ","POST","BROU"};

static unsigned char add2mac[6];

static char *add = "00:00:00:00:00:01";
module_param(add, charp, 0000);
MODULE_PARM_DESC(add, "The bytes to add to mac address written as a mac address");

static char *interface = "";
module_param_named(if, interface, charp, 0000);
MODULE_PARM_DESC(if, "The name of the wireless interface, if omitted then all bridged wireless interfaces");

static bool debug = false;
module_param(debug, bool, 0000);
MODULE_PARM_DESC(debug, "Print debug information about the packets y/n");

bool ismac000000(char* buffer)
{
    char* p = (char*)buffer;
    char acc = *p;
    acc |= *++p;
    acc |= *++p;
    acc |= *++p;
    acc |= *++p;
    acc |= *++p;
    return acc == 0;
}
bool ismacFFFFFF(char* buffer)
{
    char* p = (char*)buffer;
    char acc = *p;
    acc &= *++p;
    acc &= *++p;
    acc &= *++p;
    acc &= *++p;
    acc &= *++p;
    return acc == 0xff;
}

static bool changemac(unsigned char *src, unsigned char *dst, bool add)
{
  unsigned char *mac;
  int i;
  if (add) mac=src; else mac=dst;
  if (ismacFFFFFF(mac)) return false;
  if (memcmp(mcastip4, mac, sizeof(mcastip4)) ==0) return false;
  if (memcmp(mcastip6, mac, sizeof(mcastip6)) ==0) return false;
  if (ismac000000(mac)) return false;
  if (add) {
    // debugprintk("CHANGE: %pM", mac); // should always print original, if not then we are doing something wrong
    for (i = 0; i < 6; ++i) mac[i] += add2mac[i];
  }
  else {
    for (i = 0; i < 6; ++i) mac[i] -= add2mac[i];
    // debugprintk("CHANGE: %pM", mac); // should always print original, if not then we are doing something wrong
  }
  return true;
}

static void debugprint_ethhdr(struct sk_buff *skb,const struct nf_hook_state *state) 
{
  struct ethhdr *eth_header = (struct ethhdr *)skb_mac_header(skb);
  debugprintk("%s: ETHHDR: %d %pM %pM %04x", hookdesc[state->hook], state->hook,
      eth_header->h_source, eth_header->h_dest, ntohs(eth_header->h_proto));
}

static unsigned int hook_func_pre_post(
	void *priv,
	struct sk_buff *skb,
	const struct nf_hook_state *state
) {
  struct ethhdr *eth_header;
  struct iphdr *ip_header;
  struct udphdr *udp_header;
  struct arphdr *arp;
  struct arp_payload *payload;
  bool addmac;

    addmac = state->hook == NF_BR_PRE_ROUTING;
    if (addmac) {
      if (!state->in) return NF_ACCEPT;
      if (interface[0]) {
        if (strcmp(state->in->name, interface)) return NF_ACCEPT;
      }
      else { 
        if (!state->in->ieee80211_ptr) return NF_ACCEPT;
      }
    } 
    else { 
      if (!state->out) return NF_ACCEPT;
      if (interface[0]) {
        if (strcmp(state->out->name, interface)) return NF_ACCEPT;
      }
      else { 
        if (!state->out->ieee80211_ptr) return NF_ACCEPT;
      }
    }
    eth_header = (struct ethhdr *)skb_mac_header(skb);
    switch (ntohs(eth_header->h_proto))
    {
      case ETH_P_IP:
        ip_header = (struct iphdr *)skb_network_header(skb);
        if (ip_header == 0) break; 
        if (ip_header->protocol==IPPROTO_UDP) {
          skb_set_transport_header(skb, ip_header->ihl * 4);
          udp_header = (struct udphdr *)skb_transport_header(skb);
          if ( (udp_header->source == htons(68) && udp_header->dest == htons(67) &&  addmac)   ||
               (udp_header->source == htons(67) && udp_header->dest == htons(68) && !addmac) ) {
            unsigned int src_ip = (unsigned int)ip_header->saddr;
            unsigned int dest_ip = (unsigned int)ip_header->daddr;
            unsigned int udplen;
            unsigned char *buff;
            int offs = UDP_DHCP_MAGICC_OFFSET+4;;
            skb_linearize(skb);
            udp_header = (struct udphdr *)skb_transport_header(skb);
            buff = (char *)udp_header;
            if (ntohs(udp_header->len) < (UDP_DHCP_MAGICC_OFFSET+4)) break; 
            if (memcmp(dhcpmagic, buff+UDP_DHCP_MAGICC_OFFSET, sizeof(dhcpmagic))!=0) break;
            debugprintk("%s: IP: src = %pI4  dest = %pI4\n", hookdesc[state->hook], &src_ip, &dest_ip);
            debugprint_ethhdr(skb, state);
            debugprintk("%s: UDP port: %d -> %d", hookdesc[state->hook], ntohs(udp_header->source), ntohs(udp_header->dest));
            debugprintk("%s: DHCP: %pM", hookdesc[state->hook], buff+UDP_DHCP_CHADDR_OFFSET);
            while ((buff[offs] != DHCPOPT_END) && (offs < ntohs(udp_header->len))) {
              if (buff[offs] == DHCPOPT_PAD) offs++;
              else {
                if (buff[offs] == DHCPOPT_CLIENTID) buff[offs] = DHCPOPT_DISCSTRING; // 'erase' client id
                offs+= 2 + buff[offs+1];
              }
            }
            changemac(buff+UDP_DHCP_CHADDR_OFFSET, buff+UDP_DHCP_CHADDR_OFFSET, addmac);
            skb->ip_summed = CHECKSUM_NONE;
            skb->csum_valid = 0;
            skb->csum =0;
            udplen = ntohs(ip_header->tot_len) - ip_header->ihl*4;
            udp_header->check = 0;
            udp_header->check = udp_v4_check(udplen,ip_header->saddr, ip_header->daddr,
                                         csum_partial((char *)udp_header, udplen, 0));
          } 
        }
        break;
      case ETH_P_ARP:
        skb_linearize(skb);
        arp = arp_hdr(skb);
        if (arp->ar_hrd != htons(ARPHRD_ETHER) || arp->ar_pro != htons(ETH_P_IP) ||
            arp->ar_pln != 4                   || arp->ar_hln != ETH_ALEN) break;
        payload = (void *)(arp+1);
        if (arp->ar_op == htons(ARPOP_REPLY)) {
          if ((payload->src_ip == payload->dst_ip) && (memcmp(payload->src_hw,payload->dst_hw,ETH_ALEN)==0)) {
            debugprintk("%s: ARP: GRATUITOUS REPLY", hookdesc[state->hook]);
          }
          else {
            debugprintk("%s: ARP: REPLY", hookdesc[state->hook]);
          }
        }
        else if (arp->ar_op == htons(ARPOP_REQUEST)) {
          if (payload->src_ip ==0) {
            debugprintk("%s: ARP: PROBE REQUEST", hookdesc[state->hook]);
          }
          else if ((payload->src_ip == payload->dst_ip) && ismac000000(payload->dst_hw)) {
            debugprintk("%s: ARP: GRATUITOUS REQUEST", hookdesc[state->hook]);
            changemac(payload->dst_hw, payload->src_hw, addmac); 
          }  // GRATUITOUS REQUEST swapped dst and src so changed all after the second changemac() call!
          else {
            debugprintk("%s: ARP: REQUEST", hookdesc[state->hook]);
          }
        }
        else debugprintk("%s: ARP: UNKNOWN", hookdesc[state->hook]);
        debugprint_ethhdr(skb, state);
        debugprintk("%s: PAYLOAD %pM %pM , %pI4 %pI4\n", hookdesc[state->hook], payload->src_hw,  payload->dst_hw, 
                                                                          &payload->src_ip, &payload->dst_ip);
        changemac(payload->src_hw, payload->dst_hw, addmac);
        break;
      case ETH_P_PAE:
        debugprintk("%s: PAE: Port Access Entity (IEEE 802.1X)", hookdesc[state->hook]);
        debugprint_ethhdr(skb, state);
        break;
      case ETH_P_IPV6:
        // debugprintk("%s: IPV6:", hookdesc[state->hook]);
        // debugprint_ethhdr(skb, state);
        break;
      case ETH_P_DDCMP:
        debugprintk("%s: DEC DDCMP: Internal only", hookdesc[state->hook]);
        debugprint_ethhdr(skb, state);
        break;
      default:
        debugprintk("%s: OTHER:", hookdesc[state->hook]);
        debugprint_ethhdr(skb, state);
    }
    changemac(eth_header->h_source, eth_header->h_dest, addmac);
    return NF_ACCEPT;
}

static unsigned int hook_func_in_out(
	void *priv,
	struct sk_buff *skb,
	const struct nf_hook_state *state
) {
  struct ethhdr *eth_header;
  bool addmac;

  eth_header = (struct ethhdr *)skb_mac_header(skb);
  if (ntohs(eth_header->h_proto) != ETH_P_PAE) return NF_ACCEPT;
  addmac = state->hook == NF_BR_LOCAL_OUT;
  if (addmac) {
    if (!state->out) return NF_ACCEPT;
    if (interface[0]) {
      if (strcmp(state->out->name, interface)) return NF_ACCEPT;
    }
    else {
      if (!state->out->ieee80211_ptr) return NF_ACCEPT;
    }
  } 
  else { 
    if (!state->in) return NF_ACCEPT;
    if (interface[0]) {
      if (strcmp(state->in->name, interface)) return NF_ACCEPT;
    }
    else {
      if (!state->in->ieee80211_ptr) return NF_ACCEPT;
    }
  }
  debugprintk("%s: PAE: Port Access Entity (IEEE 802.1X) %s %s", hookdesc[state->hook], state->in->name, state->out->name);
  debugprint_ethhdr(skb, state);
  changemac(eth_header->h_dest, eth_header->h_source, addmac);
    // restore original mac just before these packets reach hostap 
    // (or just after sent from hostap, however have not seen this happen)
  return NF_ACCEPT;
}


static const struct nf_hook_ops nfho[] = {
	{
		.hook		= hook_func_pre_post,
		.pf		= PF_BRIDGE,
		.hooknum	= NF_BR_PRE_ROUTING,
		.priority	= NF_BR_PRI_FIRST,
	},
	{
		.hook		= hook_func_pre_post,
		.pf		= PF_BRIDGE,
		.hooknum	= NF_BR_POST_ROUTING,
		.priority	= NF_BR_PRI_LAST,
	},
	{
		.hook		= hook_func_in_out,
		.pf		= PF_BRIDGE,
		.hooknum	= NF_BR_LOCAL_IN,
		.priority	= NF_BR_PRI_LAST,
	},
	{
		.hook		= hook_func_in_out,
		.pf		= PF_BRIDGE,
		.hooknum	= NF_BR_LOCAL_OUT,
		.priority	= NF_BR_PRI_FIRST,
	},
};

static int __init mcspoof_init(void)
{
  int err;
  if ((err=sscanf(add, "%hhx:%hhx:%hhx:%hhx:%hhx:%hhx", 
               &add2mac[0], &add2mac[1], &add2mac[2],
               &add2mac[3], &add2mac[4], &add2mac[5])) != ETH_ALEN) {
    printk(KERN_ERR MODNAME ": add=%s is not written as a correct mac address!\n", add);
    if (err<0) return err; else return -1;
  }
  if ((err=nf_register_net_hooks(&init_net, nfho, sizeof nfho / sizeof nfho[0])) < 0) {
    printk(KERN_ERR MODNAME ": failed to register hooks!\n");
    return err;
  }
  printk(KERN_INFO MODNAME ": started module.\n");
  return 0;
}

static void __exit mcspoof_cleanup(void)
{
  printk(KERN_INFO MODNAME ": cleaning up module.\n");
  nf_unregister_net_hooks(&init_net, nfho, sizeof nfho / sizeof nfho[0]);
}

module_init(mcspoof_init);
module_exit(mcspoof_cleanup);
