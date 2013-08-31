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

#include <pcap.h>
#include <swarm.h>


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
