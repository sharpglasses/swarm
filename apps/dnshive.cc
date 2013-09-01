/*-
 * Copyright (c) 2013 Masayoshi Mizutani <mizutani@sfc.wide.ad.jp>
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
 * ``AS IS'' AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED
 * TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR
 * PURPOSE ARE DISCLAIMED.  IN NO EVENT SHALL THE FOUNDATION OR CONTRIBUTORS
 * BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
 * CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
 * SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
 * INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN
 * CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
 * ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
 * POSSIBILITY OF SUCH DAMAGE.
 */

#include <sys/types.h>
#include <pcap.h>

#include <swarm.h>

#include <map>


class DnsFwdDB : public swarm::Handler {
 private:
  std::map <u_int32_t, std::string> rev_map_;

 public:
  const std::string * lookup (u_int32_t v4addr) {
    return NULL;
  }
  void recv (swarm::ev_id eid, const  swarm::Property &p) {
    for (size_t i = 0; i < p.param ("dns.an_name")->size (); i++) {
      std::string name = p.param ("dns.an_name")->repr (i);
      u_int32_t type = p.param ("dns.an_type")->uint32 (i);
      std::string addr;

      if (type == 1) {
        addr = p.param ("dns.an_data")->ip4 (i);
        printf ("%s %s\n", name.c_str (), addr.c_str ());
      } else if (type == 28) {
        addr = p.param ("dns.an_data")->ip6 (i);
        printf ("%s %s\n", name.c_str (), addr.c_str ());
      }
    }
    return;
  }
};


void read_pcapfile (const std::string &fpath) {
  printf ("open: \"%s\"\n", fpath.c_str ());

  // ----------------------------------------------
  // setup pcap file
  pcap_t *pd;
  char errbuf[PCAP_ERRBUF_SIZE];

  pd = pcap_open_offline(fpath.c_str (), errbuf);
  if (pd == NULL) {
    printf ("error: %s\n", errbuf);
    return;
  }
  int dlt = pcap_datalink (pd);


  // ----------------------------------------------
  // setup NetDec
  swarm::NetDec *nd = new swarm::NetDec ();
  DnsFwdDB * dns_db = new DnsFwdDB ();
  nd->set_handler ("dns.an", dns_db);

  // ----------------------------------------------
  // processing packets from pcap file
  struct pcap_pkthdr *pkthdr;
  const u_char *pkt_data;
  while (0 < pcap_next_ex (pd, &pkthdr, &pkt_data)) {
    nd->input (pkt_data, pkthdr->len, pkthdr->caplen, pkthdr->ts, dlt);
  }

  return;
}

int main (int argc, char *argv[]) {
  for (int i = 1; i < argc; i++) {
    read_pcapfile (std::string (argv[i]));
  }
}