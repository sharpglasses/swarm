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

#include "./optparse.h"


class DnsFwdDB : public swarm::Handler {
 private:
  std::map <u_int32_t, std::string> rev_map_;

 public:
  const std::string * lookup (u_int32_t * v4addr) {
    auto it = this->rev_map_.find (*v4addr);
    if (it == this->rev_map_.end ()) {
      return NULL;
    } else {
      return &(it->second);
    }
  }

  void recv (swarm::ev_id eid, const  swarm::Property &p) {
    for (size_t i = 0; i < p.param ("dns.an_name")->size (); i++) {
      std::string name = p.param ("dns.an_name")->repr (i);
      std::string type = p.param ("dns.an_type")->repr (i);
      std::string addr;

      addr = p.param ("dns.an_data")->repr (i);
      printf ("%s (%s) %s\n", name.c_str (), type.c_str (), addr.c_str ());

      void * ptr = p.param ("dns.an_data")->get (NULL, i);
      if (ptr) {
        u_int32_t * a = static_cast<u_int32_t*> (ptr);
        this->rev_map_.insert (std::make_pair (*a, name));
      }
    }
    return;
  }
};

class IPFlow : public swarm::Handler {
 private:
  DnsFwdDB * db_;

 public:
  void set_db (DnsFwdDB *db) {
    this->db_ = db;
  }

  void recv (swarm::ev_id eid, const  swarm::Property &p) {
    std::string s_tmp, d_tmp;
    const std::string *src, *dst;
    void *s_addr = p.param ("ipv4.src")->get ();
    void *d_addr = p.param ("ipv4.dst")->get ();
    if (!s_addr || !d_addr) {
      return;
    }

    if (NULL == (src = this->db_->lookup (static_cast<u_int32_t*>(s_addr)))) {
      s_tmp = p.param("ipv4.src")->repr ();
      src = &s_tmp;
    }
    if (NULL == (dst = this->db_->lookup (static_cast<u_int32_t*>(d_addr)))) {
      d_tmp = p.param("ipv4.dst")->repr ();
      dst = &d_tmp;
    }

    printf ("%s -> %s\n", src->c_str (), dst->c_str ());
  }
};

void pcap_callback (u_char * user, const struct pcap_pkthdr *pkthdr,
                    const u_char *pkt) {
  swarm::NetDec * nd = reinterpret_cast<swarm::NetDec *> (user);
  nd->input (pkt, pkthdr->len, pkthdr->caplen, pkthdr->ts, DLT_EN10MB);
}

static const int PCAP_BUFSIZE_ = 0xffff;
static const int PCAP_TIMEOUT_ = 1;

void capture (const std::string &dev, const std::string &filter = "") {
  pcap_t * pd = NULL;
  char errbuf[PCAP_ERRBUF_SIZE];

  // ----------------------------------------------
  // setup NetDec
  swarm::NetDec *nd = new swarm::NetDec ();
  DnsFwdDB *dns_db = new DnsFwdDB ();
  IPFlow *ip4_flow = new IPFlow ();
  ip4_flow->set_db (dns_db);

  nd->set_handler ("dns.an", dns_db);
  nd->set_handler ("ipv4.packet", ip4_flow);

  // open interface
  if (NULL == (pd = pcap_open_live (dev.c_str (), PCAP_BUFSIZE_,
                                    1, PCAP_TIMEOUT_, errbuf))) {
    printf ("error: %s", errbuf);
    return;
  }

  // set filter
  if (filter.length () > 0) {
    struct bpf_program fp;
    bpf_u_int32 net  = 0;
    bpf_u_int32 mask = 0;

    if (pcap_lookupnet(dev.c_str (), &net, &mask, errbuf) == -1) {
      net = 0;
    }

    if (pcap_compile (pd, &fp, filter.c_str (), net, mask) < 0 ||
        pcap_setfilter (pd, &fp) == -1) {
      std::string msg = "filter compile/set error: ";
      msg += pcap_geterr (pd);
      msg += " \"" + filter + "\"";
      printf ("error: %s\n", msg.c_str ());
      return;
    }
  }

  if (0 > pcap_loop (pd, 0, pcap_callback,
                     reinterpret_cast<u_char*>(nd))) {
    printf ("error: %s\n", pcap_geterr (pd));
    return;
  }

  pcap_close (pd);
}

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
  IPFlow * ip4_flow = new IPFlow ();
  ip4_flow->set_db (dns_db);

  nd->set_handler ("dns.an", dns_db);
  nd->set_handler ("ipv4.packet", ip4_flow);

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
    // read_pcapfile (std::string (argv[i]));
    capture (std::string (argv[i]), "");
  }
}
