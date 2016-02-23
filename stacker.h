#ifndef __STACKER_H__ 
#define __STACKER_H__

#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/security.h>
#include <linux/skbuff.h>
#include <linux/netlink.h>
#include <linux/capability.h>
#include <linux/rwsem.h>
#include <linux/list.h>
struct sec_module {
	struct hlist_node hlist;
	char *modname;
  atomic_t mod_ref;
  struct security_operations *ops;
};

static inline struct security_operations *get_mod(struct sec_module *secmod)
{
  if (secmod) {
	atomic_inc(&secmod->mod_ref);
	return secmod->ops;
  }
  return NULL;
}

static inline void put_mod(struct sec_module *secmod)
{
  if (secmod) {
	atomic_dec(&secmod->mod_ref);
  }
  return;
}


#endif
