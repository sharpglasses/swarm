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

#ifndef __DECODE_H__
#define __DECODE_H__

#include "swarm.h"
#include "debug.h"
#include "engine.h"

#include <arpa/inet.h>
#include <deque>

#include "io_dump.h"

namespace swarm {    
    typedef unsigned long long ssn_id_t ;

    class Engine;


    class Decoder {
    private:
        Engine * engine_;
        int emit_count_;
        Record rec_pool_;

        bool pcap_dump_ ;
        std::string pcap_dump_file_;

#ifdef __ENABLE_PROTOBUF__
        DecIODumper decio_dump;
#endif // __ENABLE_PROTOBUF__

        
    protected:
        // emit() is used to move process to other decoder and emit() must be 
        // called once in call() of each decoder class.
        void emit (Protocol next, Property * f, Payload * p) {
            p->retain ();
            this->emit_count_++;

#ifdef __ENABLE_PROTOBUF__
            decio_dump.save_emit (next, *f, *p);
#endif // __ENABLE_PROTOBUF__

            this->engine_->involve_decoder (next, f, p);
            p->release ();
        }
        // dispatch() is called in order to involve some events and wake up 
        // event handler based from swarm::Handler class written by users
        void dispatch (key_t ev, Property * f, Record * r) {
            f->retain ();
            r->retain ();

#ifdef __ENABLE_PROTOBUF__
            decio_dump.save_dispatch (ev, *f, *r);
#endif // __ENABLE_PROTOBUF__

            this->engine_->call_handler (ev, f, r);
            f->release ();
            r->release ();
        }

        Record * acquire_record () {
            Record * rec;
            if (this->rec_pool_.has_node ()) {
                rec = this->rec_pool_.list_next_;
                rec->detach ();
            }
            else {
                rec = new Record (this);
            }

            rec->retain ();
            return rec;
        }

        void enable_pcap_dump (std::string fname) {
            this->pcap_dump_ = true;
            this->pcap_dump_file_ = fname;
        }
        void dump_pcap (std::string fname, Property &prop, Payload &payload) {
            this->engine_->dump_packet (fname, prop, payload);
        }


    public:
        Decoder (Engine * engine) : 
        engine_(engine), emit_count_(0),  rec_pool_(this), pcap_dump_(false) {
        }
        virtual ~Decoder () {
            while (this->rec_pool_.has_node ()) {
                Record *rec = this->rec_pool_.list_next_;
                rec->detach ();
                delete rec;
            }
        }
        void restore_record (Record * rec) {
            this->rec_pool_.attach (rec);
        }
        void call (Property * prop, Payload * payload) {
            if (this->pcap_dump_) {
                this->dump_pcap (this->pcap_dump_file_, *prop, *payload);
            }

#ifdef __ENABLE_PROTOBUF__
            this->decio_dump.save_request (*prop, *payload);
#endif // __ENABLE_PROTOBUF__

            // emit_count_ may be incremented in emit ()
            this->emit_count_ = 0;

            // calling individualistic decoder
            prop->retain ();
            payload->retain ();

            this->decode (prop, payload);

            payload->release ();
            prop->release ();
        }

        void enable_io_dump (std::string & fname) {
#ifdef __ENABLE_PROTOBUF__
            decio_dump.set_dump_file (fname);
#endif // __ENABLE_PROTOBUF__
        }

        virtual void decode (Property * f, Payload * p) = 0;
    };
};

#endif

