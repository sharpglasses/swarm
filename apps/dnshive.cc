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


static const int PCAP_BUFSIZE_ = 0xffff;
static const int PCAP_TIMEOUT_ = 1;

void capture (const std::string &dev, const std::string &filter = "") {
  // ----------------------------------------------
  // setup NetDec
  swarm::NetDec *nd = new swarm::NetDec ();
  DnsFwdDB *dns_db = new DnsFwdDB ();
  IPFlow *ip4_flow = new IPFlow ();
  ip4_flow->set_db (dns_db);

  nd->set_handler ("dns.an", dns_db);
  nd->set_handler ("ipv4.packet", ip4_flow);

  swarm::NetCap *nc = new swarm::CapPcapDev (dev);
  nc->connect (nd);
  if (!nc->ready ()) {
    printf ("error: %s\n", nc->errmsg ().c_str ());
  }

  if (!nc->start ()) {
    printf ("error: %s\n", nc->errmsg ().c_str ());
  }
}


void read_pcapfile (const std::string &fpath) {
  printf ("open: \"%s\"\n", fpath.c_str ());

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
  swarm::NetCap *nc = new swarm::CapPcapFile (fpath);
  nc->connect (nd);
  if (!nc->ready ()) {
    printf ("error: %s\n", nc->errmsg ().c_str ());
  }

  if (!nc->start ()) {
    printf ("error: %s\n", nc->errmsg ().c_str ());
  }
  return;
}

int main (int argc, char *argv[]) {
  for (int i = 1; i < argc; i++) {
    // read_pcapfile (std::string (argv[i]));
    capture (std::string (argv[i]), "");
  }
}
