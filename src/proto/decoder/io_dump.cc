/**********************************************************************
Copyright (c) 2012 Masa Mizutani <mizutani@sfc.wide.ad.jp>
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

#include <fstream>
#include "io_dump.h"
#include "debug.h"

namespace swarm {
#ifdef __ENABLE_PROTOBUF__

    DecIODumper::DecIODumper () {
    }
    DecIODumper::~DecIODumper () {
    }
    void DecIODumper::set_dump_file (std::string &fname) {
        /*
        assert (this->dump_file_name_.length () == 0);
        assert (fname.length () > 0);

        this->dump_file_name_ = fname;
        this->dump_orig_name_ = fname;
        */
    }
    void DecIODumper::save_request (Property &prop, Payload &p) {
        /*
        std::string serial;
        std::string s_payload (static_cast<char*> (const_cast<void*>(p.ptr ())), 
                               p.remain ());

        if (this->content_list_.content_size () >= this->save_limit_) {
            // prepare linked next file name
            char buf [BUFSIZ];
            snprintf (buf, BUFSIZ, "%s.%d", this->dump_orig_name_.c_str (), 
                      this->file_count_);

            this->content_list_.set_next_file (buf);
            printf ("next fname: %s\n", buf);
            // dump
            this->dump ();

            // tear drop
            this->file_count_++;
            this->dump_file_name_ = buf;
            this->save_count_ = 0;
        }


        this->content_ = this->content_list_.add_content ();

        PbRequest * req = this->content_->mutable_req ();
        req->set_payload (s_payload);
        req->set_tv_sec (prop.ts_sec ());
        req->set_tv_usec (prop.ts_usec ());
        req->set_frame_id (prop.frame_id ());

        if (prop.has_addr ()) {
            req->set_src_addr (std::string (static_cast<char*> (prop.src_addr ()),
                                            prop.addr_len ()));
            req->set_dst_addr (std::string (static_cast<char*> (prop.dst_addr ()),
                                            prop.addr_len ()));
        }
        if (prop.has_port ()) {
            req->set_proto (prop.proto ());
            req->set_src_port (prop.src_port ());
            req->set_dst_port (prop.dst_port ());
        }
        */
        return;
    }

    void DecIODumper::save_emit (Protocol next, Property &prop, Payload &p) {
        /*
        std::string s_payload (static_cast<char*> (const_cast<void*>(p.ptr ())), 
                               p.remain ());
        assert (this->content_);
        PbEmit * emit = this->content_->mutable_emit ();
        emit->set_next (next);
        emit->set_payload (s_payload);

        if (prop.has_addr ()) {
            emit->set_src_addr (std::string (static_cast<char*> (prop.src_addr ()),
                                             prop.addr_len ()));
            emit->set_dst_addr (std::string (static_cast<char*> (prop.dst_addr ()),
                                             prop.addr_len ()));
        }
        if (prop.has_port ()) {
            emit->set_proto (prop.proto ());
            emit->set_src_port (prop.src_port ());
            emit->set_dst_port (prop.dst_port ());
        }
        */
        return;
    }
    void DecIODumper::save_dispatch (Event ev, Property &prop, Record &r) {
        /*
        assert (this->content_);
        PbDispatch * disp = this->content_->add_disp ();
        disp->set_event (ev);

        void * data;
        size_t len;

        for (int k = 0; k < VAR_KEY_TERM; k++) {
            for (unsigned int i = 0; 
                 NULL != (data = const_cast<void*>
                          (r.var (static_cast<VarKey>(k), &len, i))); i++) {
                std::string v (static_cast<char *> (data), len);
                PbDispatch_PbVariable * pb_var = disp->add_var ();
                pb_var->set_key (k);
                pb_var->set_idx (i);
                pb_var->set_data (v);
            }
        }
        */
        return ;
    }

    void DecIODumper::dump () {
        /*
        if (this->dump_file_name_.length () > 0) {
            std::fstream out(this->dump_file_name_.c_str (), 
                             std::ios::app | std::ios::out | std::ios::binary);
                             
            this->content_list_.SerializeToOstream(&out);
            out.close();

            // deleting protocol buffer objects
            this->content_ = NULL;
            this->content_list_.clear_next_file ();
            this->content_list_.clear_content ();
            return ;
        }
        */
    }

#endif // __ENABLE_PROTOBUF__

}
