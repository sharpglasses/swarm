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

#ifndef __LRU_HASH_H__
#define __LRU_HASH_H__

#include <stdlib.h>
#include <limits.h>
#include <assert.h>

namespace util {
    template <typename T> class LruHash;

    template <typename T> class HashNode {
    private:
        void * key_;
        size_t len_;
        HashNode<T> * lru_link_, * hash_next_, * hash_prev_;
        LruHash<T> * parent_;

    protected:
        void reset (int timeout) {
            assert (this->parent_);
            this->parent_->insert (this->key_, this->len_, this, timeout);
        }

    public:
        HashNode () : key_(NULL), 
                      len_(0), 
                      lru_link_(NULL), 
                      hash_next_(this), 
                      hash_prev_(this) {
        }
        virtual ~HashNode () {
            if (this->key_) {
                free (this->key_);
            }

            if (this->lru_link_) {
                delete this->lru_link_;
            }
        }
        inline void set_key (const void * key, const size_t len) {
            if (this->key_) {
                free (this->key_);
            }
            this->len_ = len;
            this->key_ = malloc (len);
            memcpy (this->key_, key, len);
        }
        inline bool cmp_key (const void * key, const size_t len) {
            return (this->len_ == len && memcmp (this->key_, key, len) == 0);
        }
        virtual bool update_callback () {
            // if return true, this object will be deleted
            return true;

            // or return false, this object will not be deleted, remained
            // return false
        }
        inline void join (HashNode<T> * prev) {
            HashNode<T> * next = prev->hash_next_;
            prev->hash_next_ = this;
            next->hash_prev_ = this;
            this->hash_next_ = next;
            this->hash_prev_ = prev;
        }
        inline void leave () {
            HashNode<T> * next = this->hash_next_;
            HashNode<T> * prev = this->hash_prev_;
            next->hash_prev_ = prev;
            prev->hash_next_ = next;
            this->hash_next_ = this;
            this->hash_prev_ = this;
        }
        inline HashNode<T> * next () {
            return this->hash_next_;
        }
        inline HashNode<T> * prev () {
            return this->hash_prev_;
        }
        inline void push_link (HashNode<T> * node) {
            assert (node->lru_link_ == NULL);
            HashNode<T> * tmp = this->lru_link_;
            this->lru_link_ = node;
            node->lru_link_ = tmp;
        }
        inline HashNode<T> * pop_link () {
            if (this->lru_link_) {
                HashNode<T> * node = this->lru_link_;
                this->lru_link_ = node->lru_link_;
                node->lru_link_ = NULL;
                return node;                
            }
            else {
                return NULL;
            }
        }
        inline void set_parent (LruHash<T> * parent) {
            this->parent_ = parent;
        }
    };

    template <typename T> class LruHash {
    private:
        class HashBucket {
        public:
            HashNode<T> root_;
        };

        class LruBucket {
        public:
            HashNode<T> lru_link_;

        };
        
        size_t table_size_;
        size_t lru_size_;
        HashBucket * hash_table_;
        LruBucket * lru_table_;
        unsigned int cursol_;

        static const u_int32_t hash_seed_ = 0xaa;

        //---------------------------------------------------------
        // MurmurHash2, by Austin Appleby
        // https://sites.google.com/site/murmurhash/
        inline u_int32_t hash (const void * key, const size_t len) {

            // 'm' and 'r' are mixing constants generated offline.
            // They're not really 'magic', they just happen to work
            // well.
            const u_int32_t m = 0x5bd1e995;
            const int r = 24;

            // Initialize the hash to a 'random' value
            u_int32_t h = this->hash_seed_ ^ len;

            // Mix 4 bytes at a time into the hash
            const u_int8_t * data = (const u_int8_t *)key;
            size_t remain = len;
            for (u_int32_t k = *(u_int32_t *)data; 
                 remain >= 4; remain -= 4, data += 4) {
                k *= m; 
                k ^= k >> r; 
                k *= m; 
                h *= m; 
                h ^= k;
            }
	
            // Handle the last few bytes of the input array
            switch(remain) {
            case 3: h ^= data[2] << 16;
            case 2: h ^= data[1] << 8;
            case 1: h ^= data[0];
                h *= m;
            };

            // Do a few final mixes of the hash to ensure the last 
            // few bytes are well-incorporated.
            h ^= h >> 13;
            h *= m;
            h ^= h >> 15;

            return h % this->table_size_;
        }

        inline unsigned int lru_tick (unsigned int timeout) {
            return (this->cursol_ + timeout) % this->lru_size_;
        }

    public:        
        LruHash (size_t table_size, size_t lru_size) : 
            table_size_(table_size), lru_size_(lru_size), 
            hash_table_(NULL), lru_table_(NULL),
            cursol_(0)
        {
            assert (INT_MAX > table_size);
            assert (INT_MAX > lru_size);

            this->hash_table_ = new HashBucket [this->table_size_];
            this->lru_table_  = new LruBucket [this->lru_size_];
        }
        ~LruHash () {
            delete [] this->hash_table_;
            delete [] this->lru_table_;
        }
        
        bool insert (const void * key, const size_t len, HashNode<T> * obj, 
                     unsigned int timeout) {
            assert (timeout > 0);
            HashBucket * b = &(this->hash_table_[this->hash (key, len)]);

            for (HashNode<T> * node = b->root_.next ();
                 node != &(b->root_); node = node->next ()) {
                if (node->cmp_key (key, len)) {
                    // conflicted object
                    return false;
                }
            }

            obj->set_parent (this);
            obj->join (&(b->root_));

            LruBucket * lru = &(this->lru_table_[this->lru_tick (timeout - 1)]);
            lru->lru_link_.push_link (obj);

            obj->set_key (key, len);
            return true;
        }

        T * lookup (const void * key, const size_t len) {
            HashBucket * b = &(this->hash_table_[this->hash (key, len)]);
            for (HashNode<T> * node = b->root_.next ();
                 node != &(b->root_); node = node->next ()) {
                if (node->cmp_key (key, len)) {
                    return dynamic_cast<T*>(node);
                }
            }
            return NULL;
        }

        void update (size_t tick=1) {
            HashNode<T> * node;
            for (unsigned int i = 0 ; i < tick; i++) {
                int c = 0;
                LruBucket * lru = &(this->lru_table_[this->lru_tick (i)]);
                while (NULL != (node = lru->lru_link_.pop_link ())) {
                    c++;
                    node->leave ();
                    if (node->update_callback ()) {
                        delete node;
                    }
                }
            }
            this->cursol_++;
        }
    };
};

#endif // __LRU_HASH_H__
