#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/security.h>
#include <linux/skbuff.h>
#include <linux/netlink.h>
#include <linux/capability.h>
#include <linux/rwsem.h>

static int __init lsm_stacker_init (void)
{
	return 0;
}

static void __exit lsm_stacker_exit (void)
{
	return;
}


module_init (lsm_stacker_init);
module_exit (lsm_stacker_exit);

MODULE_DESCRIPTION("LSM Stacker - supports multiple simultaneous LSM modules");
MODULE_AUTHOR("Richard Chen");
MODULE_LICENSE("GPL v2");


