/**********************************************************************

Copyright (c) 2011 Masa Mizutani <mizutani@sfc.wide.ad.jp>
All rights reserved.

Redistribution and use in source and binary forms, with or without
modification, are permitted provided that the following conditions
are met:
1. Redistributions of source code must retain the above copyright
   notice, this list of conditions and the following disclaimer.
2. Redistributions in binary form must reproduce the above copyright
   notice, this list of conditions and the following disclaimer in the
   documentation and/or other materials provided with the distribution.

THIS SOFTWARE IS PROVIDED BY THE AUTHOR ``AS IS'' AND ANY EXPRESS OR
IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES
OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED.
IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR ANY DIRECT, INDIRECT,
INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT
NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
(INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF
THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.

***********************************************************************/

#include <string.h>

#include "decode.h"
#include "lru_hash.h"

namespace swarm {
    class TcpDecoder : public Decoder {
    private:
        struct tcp_header
        {
            u_int16_t src_port_;  // source port
            u_int16_t dst_port_;  // destination port
            u_int32_t seq_;       // tcp sequence number
            u_int32_t ack_;       // tcp ack number
#ifdef __SWARM_LITTLE_ENDIAN__
            u_int8_t x2_:4, offset_:4;
#endif
#ifdef __SWARM_BIG_ENDIAN__
            u_int8_t offset_:4, x2_:4;
#endif
            u_int8_t flags_;      // flags 
            u_int16_t window_;	  // window 
            u_int16_t chksum_;	  // checksum 
            u_int16_t urgptr_;	  // urgent pointer 
        } __attribute__((packed));

        static const u_int8_t FIN  = 0x01;
        static const u_int8_t SYN  = 0x02;
        static const u_int8_t RST  = 0x04;
        static const u_int8_t PUSH = 0x08;
        static const u_int8_t ACK  = 0x10;
        static const u_int8_t URG  = 0x20;
        static const u_int8_t ECE  = 0x40;
        static const u_int8_t CWR  = 0x80;

        static const bool DEBUG = false;

      key_t TCP_SRC_PORT;
      key_t TCP_DST_PORT;
      key_t TCP_DATA;
      key_t EV_TCP_PKT ;
      key_t EV_TCP_EST_SSN;
      key_t EV_TCP_EST_DATA;

        inline static u_int8_t stat_flags (u_int8_t f) {
            return ((f) & (FIN|SYN|RST|ACK));
        }


        enum TcpSide {
            CLIENT = 0,
            SERVER = 1,
        };
        enum TcpAct {
            SENDER = 0,
            RECVER = 1,
        };

        class TcpSession : public util::HashNode<TcpSession> {
        private:
            ssn_id_t id_;
            // prefix ``PRES_'' is PRESUMPTION. 
            enum TcpStatus {
                CLOSED = 0,
                LISTEN,
                SYN_SENT,
                SYN_RCVD,
                SYNACK_SENT,
                SYNACK_RCVD,
                ESTABLISHED,
                CLOSE_WAIT_1,
                CLOSE_WAIT_2,
                LAST_ACK,
                FIN_WAIT_1,
                FIN_WAIT_2,
                CLOSING_1,
                CLOSING_2,
                TIME_WAIT,
            } status_[2];

            void * addr_[2];
            size_t addr_len_;
            u_int16_t port_[2];
            u_int32_t base_[2];
            u_int32_t seq_[2];
            u_int32_t ack_[2];
            u_int32_t next_[2];
            bool data_enable_[2];

            static const bool DEBUG = true;

        public:
            TcpSession () {
                for (int i = 0; i < 2; i++) {
                    this->status_[i] = CLOSED;
                    this->addr_[i] = NULL;
                    this->port_[i] = 0;
                    this->data_enable_[i] = false;
                    this->next_[i] = 0;
                };
            }
            ~TcpSession () {
                for (int i = 0; i < 2; i++) {
                    if (this->addr_[i]) {
                        free (this->addr_[i]);
                    }
                }
            }
            static void flags_to_str (u_int8_t flags, std::string &s) {
                s += ((flags & FIN) > 0 ? 'F' : '*');
                s += ((flags & SYN) > 0 ? 'S' : '*');
                s += ((flags & RST) > 0 ? 'R' : '*');
                s += ((flags & PUSH) > 0 ? 'P' : '*');
                s += ((flags & ACK) > 0 ? 'A' : '*');
                s += ((flags & URG) > 0 ? 'U' : '*');
                s += ((flags & ECE) > 0 ? 'E' : '*');
                s += ((flags & CWR) > 0 ? 'C' : '*');
            }
            static void dump_session (TcpSession * ssn, TcpSide sender) {
                char c[128], s[128];
                if (ssn->addr_len_ == Property::IPV4_ADDR_LEN) {
                    inet_ntop (AF_INET, ssn->addr_[CLIENT], c, sizeof (c));
                    inet_ntop (AF_INET, ssn->addr_[SERVER], s, sizeof (s));
                }
                else if (ssn->addr_len_ == Property::IPV6_ADDR_LEN) {
                    inet_ntop (AF_INET6, ssn->addr_[CLIENT], c, sizeof (c));
                    inet_ntop (AF_INET6, ssn->addr_[SERVER], s, sizeof (s));
                }
                else {
                    debug (DEBUG, "[%lld] Not set property", ssn->id_);
                    return;
                }

                debug (DEBUG, "[%lld] %s:%d %s %s:%d", ssn->id_, 
                       c, ssn->port_[CLIENT], 
                       (sender == CLIENT ? "->" : "<-"), 
                       s, ssn->port_[SERVER]);
                return ;
            }   

            void set_id (ssn_id_t id) {
                this->id_ = id;
            }
            ssn_id_t id () {
                return this->id_;
            }
            void set_property (Property &prop, TcpSide sender) {
                TcpSide recver = (sender == CLIENT) ? SERVER : CLIENT;
                this->addr_len_ = prop.addr_len ();

                this->addr_[0] = malloc (this->addr_len_);
                this->addr_[1] = malloc (this->addr_len_);
                
                ::memcpy (this->addr_[sender], prop.src_addr (), 
                          this->addr_len_);
                ::memcpy (this->addr_[recver], prop.dst_addr (), 
                          this->addr_len_);
                this->port_[sender] = prop.src_port ();
                this->port_[recver] = prop.dst_port ();
            }
            TcpSide get_sender (Property &prop) {
                if (::memcmp (prop.src_addr (), this->addr_[CLIENT], 
                              this->addr_len_) == 0 &&
                    prop.src_port () == this->port_[CLIENT]) {
                    return CLIENT;
                }
                // NOTE:
                // following is redantant check, can be removed for performance
                else if (::memcmp (prop.src_addr (), this->addr_[SERVER],
                                   this->addr_len_) == 0 &&
                         prop.src_port () == this->port_[SERVER]) {
                    return SERVER;
                }
                else {
                    assert (0);
                }
            }
            bool update_callback () {
                // allow to call delete
                this->reset (TcpDecoder::TCP_TIMEOUT_);
                return false;
            }
            inline TcpSide get_inverse (TcpSide s) {
                return (s == CLIENT ? SERVER : CLIENT);
            }

            bool update_peer_status (u_int8_t flags, TcpSide p, TcpAct a,
                                     u_int32_t seq, u_int32_t ack, 
                                     size_t seg_len) {
                const bool DBG_STAT = true;
                const bool DBG_STAT_ERR = true;
                u_int8_t f = stat_flags (flags);
                std::string str_flags;
                flags_to_str (flags, str_flags);

                switch (this->status_[p]) {
                case CLOSED: 
                    if (a == SENDER && f == SYN) {
                        this->status_[p] = SYN_SENT;
                        this->base_[p] = seq;
                        this->seq_[p]  = seq + 1;
                        debug (DBG_STAT, "CLOSED -> SYN_SENT");
                    }
                    else if (a == RECVER && f == SYN) {
                        this->status_[p] = SYN_RCVD;
                        // this->next_[p] = seq + 1;
                        this->next_[p] = seq ;
                        debug (DBG_STAT, "CLOSED -> SYN_RCVD");
                    }
                    break;

                case LISTEN: 
                    break;

                case SYN_SENT:                     
                    if (a == RECVER && f == (SYN | ACK)) {
                        this->status_[p] = SYNACK_RCVD;
                        // this->next_[p] = seq + 1;
                        this->next_[p] = seq ;
                        debug (DBG_STAT, "SYN_SENT -> SYNACK_RCVD");
                    }
                    break;

                case SYN_RCVD: 
                    if (a == SENDER && f == (SYN | ACK)) {
                        this->status_[p] = SYNACK_SENT;
                        this->base_[p] = seq;
                        this->seq_[p]  = seq + 1;
                        debug (DBG_STAT, "SYN_RCVD -> SYNACK_SENT");
                    }
                    break;

                case SYNACK_SENT: 
                    if (a == RECVER && f == (ACK)) {
                        this->status_[p] = ESTABLISHED;
                        this->data_enable_[p] = true;
                        debug (DBG_STAT, "SYNACK_SENT -> ESTABLISHED");
                    }
                    break;

                case SYNACK_RCVD: 
                    if (a == SENDER && f == (ACK)) {
                        this->status_[p] = ESTABLISHED;
                        this->data_enable_[p] = true;
                        debug (DBG_STAT, "SYNACK_RCVD -> ESTABLISHED");
                    }
                    break;

                case ESTABLISHED: 
                    if (a == SENDER && (f & FIN) > 0) {
                        this->status_[p] = FIN_WAIT_1;
                        debug (DBG_STAT, "ESTABLISHED -> FIN_WAIT_1");
                    }
                    else if (a == RECVER && (f & FIN) > 0) {
                        this->status_[p] = CLOSE_WAIT_1;
                        debug (DBG_STAT, "ESTABLISHED -> CLOSE_WAIT_1");
                    }
                    break;

                case CLOSE_WAIT_1: 
                    if (a == SENDER && f == ACK) {
                        this->status_[p] = CLOSE_WAIT_2;
                        debug (DBG_STAT, "CLOSE_WAIT_1 -> CLOSE_WAIT_2");
                    }
                    else if (a == SENDER && f == (ACK|FIN)) {
                        this->status_[p] = LAST_ACK;
                        debug (DBG_STAT, "CLOSE_WAIT_1 -> LAST_ACK");
                    }
                    else {
                        debug (DBG_STAT_ERR, "CLOSE_WAIT_1, not match: %s (%d)",
                               str_flags.c_str (), a);
                    }
                    break;

                case CLOSE_WAIT_2: 
                    if (a == SENDER && (f & FIN) > 0) {
                        this->status_[p] = LAST_ACK;
                        debug (DBG_STAT, "CLOSE_WAIT_2 -> LAST_ACK");
                    }
                    else {
                        debug (DBG_STAT_ERR, "CLOSE_WAIT_2, not match: %s (%d)",
                               str_flags.c_str (), a);
                    }
                    break;

                case LAST_ACK: 
                    if (a == RECVER && f == (ACK)) {
                        this->status_[p] = CLOSED;
                        debug (DBG_STAT, "LAST_ACK -> CLOSED");
                    }
                    else {
                        debug (DBG_STAT_ERR, "LAST_ACK, not match: %s",
                               str_flags.c_str ());
                    }
                    break;

                case FIN_WAIT_1: 
                    if (a == RECVER && f == ACK) {
                        this->status_[p] = FIN_WAIT_2;
                        debug (DBG_STAT, "FIN_WAIT_1 -> FIN_WAIT_2");
                    }
                    else if (a == RECVER && f == FIN) {
                        this->status_[p] = CLOSING_1;
                        debug (DBG_STAT, "FIN_WAIT_1 -> CLOSING_1");
                    }
                    else if (a == RECVER && f == (FIN|ACK)) {
                        this->status_[p] = TIME_WAIT;
                        debug (DBG_STAT, "FIN_WAIT_1 -> TIME_WAIT");
                    }
                    else {
                        debug (DBG_STAT_ERR, "FIN_WAIT_1, not match: %s (%d)",
                               str_flags.c_str (), a);
                    }
                    break;

                case FIN_WAIT_2: 
                    if (a == RECVER && f == FIN) {
                        this->status_[p] = TIME_WAIT;
                        debug (DBG_STAT, "FIN_WAIT_2 -> TIME_WAIT");
                    }
                    else if (a == RECVER && f == (FIN | ACK)) {
                        // TODO:
                        // have to check if this flags procedure is correnct.
                        this->status_[p] = TIME_WAIT;
                        debug (DBG_STAT, "FIN_WAIT_2 -> TIME_WAIT");
                    }
                    else {
                        // dump_session (this, sender);
                        debug (DBG_STAT_ERR, "FIN_WAIT_2, not match: %s (%d)",
                               str_flags.c_str (), a);
                    }
                    break;

                case CLOSING_1:
                    if (a == SENDER && f == ACK) {
                        this->status_[p] = CLOSING_2;
                        debug (DBG_STAT, "CLOSING_1 -> CLOSING_2");
                    }
                    else {
                        debug (DBG_STAT_ERR, "CLOSING_1, not match: %s (%d)",
                               str_flags.c_str (), a);
                    }
                    break;

                case CLOSING_2: 
                    if (a == RECVER && f == ACK) {
                        this->status_[p] = TIME_WAIT;
                        debug (DBG_STAT, "CLOSING_2 -> TIME_WAIT");
                    }
                    else {
                        debug (DBG_STAT_ERR, "CLOSING_2, not match: %s (%d)",
                               str_flags.c_str (), a);
                    }
                    break;

                case TIME_WAIT: 
                    if (a == SENDER && f == ACK) {
                        debug (DBG_STAT, "TIME_WAIT ack");
                    }
                    else {
                        debug (DBG_STAT_ERR, "TIME_WAIT, not match: %s (%d)",
                               str_flags.c_str (), a);
                    }
                    break;

                default:
                    assert (0);
                }

                if ((f & FIN) > 0) {
                    this->data_enable_[p] = false;
                }

                return true;
            }

            bool update_status (const struct tcp_header * hdr, TcpSide sender,
                                size_t seg_len){
                // u_int8_t flags = (hdr->flags_ & (FIN | SYN | RST | ACK));
                TcpSide recver = this->get_inverse (sender);
                u_int32_t seq = ntohl (hdr->seq_);
                u_int32_t ack = ntohl (hdr->ack_);

                // handling RST packet
                if ((hdr->flags_ & RST) > 0) {
                    this->status_[CLIENT] = CLOSED;
                    this->status_[SERVER] = CLOSED;
                    this->data_enable_[CLIENT] = false;
                    this->data_enable_[SERVER] = false;
                    return true;
                }

                // normal sequence
                if (this->next_[sender] != ack) {
                    if (this->status_[sender] == CLOSED) {
                        // ignore
                    }
                    else {
                        if (this->status_[recver] == LAST_ACK || 
                            this->status_[recver] == TIME_WAIT) {
                            // ignore
                        }
                        else {
                            dump_session (this, sender);
                            debug (true, "seq mismatch: exp %u, ack:%u "
                                   "(recver status:%d)",
                                   this->next_[sender] - this->base_[recver],
                                   ack - this->base_[recver], 
                                   this->status_[recver]);
                        }
                    }
                }
                else {
                    this->update_peer_status (hdr->flags_, sender, SENDER, 
                                              seq, ack, seg_len);
                    this->update_peer_status (hdr->flags_, recver, RECVER,
                                              seq, ack, seg_len);
                    if (this->data_enable_[sender]) {
                        // TODO:
                        // sequence handling
                    }
                    else {
                        this->next_[recver] += 1;
                    }

                }

                return true;
            }
        };


        util::LruHash<TcpSession> * session_table_;
        ssn_id_t cur_ssn_id_;
        static const int TCP_TIMEOUT_ = 300;
        static const int LRU_MAX_ = 3600;
        static const int SESSION_TABLE_SIZE_ = 1237;

    public:
        TcpDecoder (Engine * e) : Decoder (e), session_table_(NULL), 
                                  cur_ssn_id_(0) {
            this->session_table_ = 
                new util::LruHash<TcpSession> (LRU_MAX_, SESSION_TABLE_SIZE_);
            this->TCP_SRC_PORT = e->assign_var_key ("tcp.src_port");
            this->TCP_DST_PORT = e->assign_var_key ("tcp.dst_port");
            this->TCP_DATA     = e->assign_var_key ("tcp.data");
            this->EV_TCP_PKT      = e->assign_event_key ("tcp.packet");
            this->EV_TCP_EST_SSN  = e->assign_event_key ("tcp.establish");
            this->EV_TCP_EST_DATA = e->assign_event_key ("tcp.est_data");
        }
        ~TcpDecoder () {
            delete this->session_table_;
        }

        TcpSession * get_session (Property &prop) {
            void * p = prop.keybuf ();
            size_t len = prop.keylen ();
            TcpSession * ssn;
            if (NULL == (ssn = this->session_table_->lookup (p, len))) {
                ssn = new TcpSession ();
                ssn->set_property (prop, CLIENT);
                ssn->set_id (++(this->cur_ssn_id_));
                this->session_table_->insert (p, len, ssn, TCP_TIMEOUT_);
            }

            return ssn;
        }

        void decode (Property * prop, Payload * p) {
            const size_t fixed_len = sizeof (struct tcp_header);
            const struct tcp_header * hdr =
                static_cast<const struct tcp_header*>(p->ptr());

            if (! p->seek (fixed_len)) {
                debug (DEBUG, "invalid header length");
                return ;
            }

            if (! p->seek ((hdr->offset_ << 2) - fixed_len)) {
                debug (DEBUG, "invalid offset length");
                return ;
            }

            prop->set_port (TCP, ntohs (hdr->src_port_), ntohs (hdr->dst_port_));
            debug (DEBUG, "offset = %d, x2 = %d, sport = %d, dport = %d",
                   hdr->offset_ << 2,
                   hdr->x2_ << 2,
                   ntohs (hdr->src_port_),
                   ntohs (hdr->dst_port_));

            // store to record
            Record * r = this->acquire_record ();
            r->set_var (this->TCP_SRC_PORT, &(hdr->src_port_), 
                        sizeof (hdr->src_port_));
            r->set_var (this->TCP_DST_PORT, &(hdr->dst_port_), 
                        sizeof (hdr->dst_port_));
            if (p->remain () > 0) {
                r->set_var (this->TCP_DATA, p->ptr (), p->remain (), p);
            }
            
            TcpSession * ssn = this->get_session (*prop);
            TcpSide sender = ssn->get_sender (*prop);
            ssn->update_status (hdr, sender, p->remain ());

            // dispatch event
            this->dispatch (this->EV_TCP_PKT, prop, r);
            r->release ();

            return ;
        }
    };
}

