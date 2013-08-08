#include <gtest/gtest.h>
#include "swarm.h"

TEST (Property, basic) {
  swarm::NetDec * nd = new swarm::NetDec ();
  swarm::Property * p = new swarm::Property (nd);
  char * a = const_cast <char *> (static_cast <const char *> ("0123456789"));

  struct timeval tv = {10, 20};
  p->init (reinterpret_cast <swarm::byte_t *> (a), sizeof (a), sizeof (a), tv);

  swarm::byte_t *b;

  b = p->payload (4);
  EXPECT_EQ (&a[0], reinterpret_cast<char*> (b));
  b = p->payload (4);
  EXPECT_EQ (&a[4], reinterpret_cast<char*> (b));
  b = p->payload (1);
  EXPECT_EQ (&a[8], reinterpret_cast<char*> (b));
  b = p->payload (5);
  EXPECT_EQ (NULL, reinterpret_cast<char*> (b));

  delete p;
  delete nd;
}


TEST (Property, length) {
  swarm::NetDec * nd = new swarm::NetDec ();
  swarm::Property * p = new swarm::Property (nd);
  char * a = const_cast <char *> (static_cast <const char *> ("0123456789"));
  struct timeval tv = {10, 20};
  p->init (reinterpret_cast <swarm::byte_t *> (a), sizeof (a), 5, tv);

  swarm::byte_t *b;

  b = p->payload (4);
  EXPECT_EQ (&a[0], reinterpret_cast<char*> (b));
  b = p->payload (4);
  EXPECT_EQ (NULL, reinterpret_cast<char*> (b)); 
  b = p->payload (4);
  EXPECT_EQ (NULL, reinterpret_cast<char*> (b));

  delete p;
  delete nd;
}
