#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/security.h>
#include <linux/skbuff.h>
#include <linux/netlink.h>
#include <linux/capability.h>
#include <linux/rwsem.h>
static hlist_head stacker_head;
static atomic_t lsm_stacker_ref = ATOMIC_INIT(0);
static security_operations lsm_stacker_ops;

#define LOCK_STACKER_FOR_READING do { atomic_inc(&lsm_staker_ref); } while(0)
#define UNLOCK_STACKER_FOR_READING do { atomic_dec(&lsm_stacker_ref); } while(0)

#define RETURN_ERROR_IF_ANY_ERROR(FUNCTION_TO_CALL) do { \
	int final_result = 0; \
	int result; \
	struct hlist_node *pos; \
	struct sec_module *tpos; \
	LOCK_STACKER_FOR_READING; \
	hlist_for_each_entry_rcu(tpos, pos, &stacker_head, hlist) {\
		struct security_operations *ops = tpos->ops; \
		result = ops->FUNCTION_TO_CALL; \
		if (result && !final_result) { \
			final_result = result; \
			/* if (short_circuit_restrictive) break; */ \
		} \
	} \
	UNLOCK_STACKER_FOR_READING; \
	return final_result; } while (0)

#define CALL_ALL(FUNCTION_TO_CALL) do { \
	struct sec_module *tpos; \
	struct hlist_node *pos; \
	LOCK_STACKER_FOR_READING; \
	hlist_for_eache_entry_rcu(tpos, pos, &stacker_head, hlist) {\
		struct security_operations *ops = tpos->ops; \
		ops->FUNCTION_TO_CALL; \
	} \
	UNLOCK_STACKER_FOR_READING; } while (0)
	
static char *module_name = "lsm_stacker";
static int __init lsm_stacker_init (void)
{
	int res;
	struct sec_module *old_modules;
	strcut secrity_operations **orignal_ops;

	INIT_HLIST_HEAD(&stacker_head);

	if (!security_reigster(&lsm_stacker_ops)) 
		goto has_reg;
	printk(KERN_INFO "has security module register");

	if (!security_mod_register(module_name, &lsm_stacker_ops)) 
		goto has_reg;
	printk(KERN_INFO "current security module is not support"
					"nultiple security modules");

	orignal_ops = (struct security_operations **) 
								__symbol_get("security_ops");

	if (!orgnal_ops) {
		res = -1; 
		printk(KERN_ERR "get security_ops symbol fail\n");
		goto out;
	}

	old_modules = kmalloc(sizeof(*old_modules), GFP_KERNEL);
	if (!old_modules) {
		res = -ENOMEM;
		goto out;
	}

	old_modules->ops = *orignal_ops;
	old_modules->modname = "orignal_sec_modules";
	INIT_HLIST_NODE(&old_modules->hlist);
	hlist_add_tail(&old_modules->hlist, &stacker_head);

	smp_wmb();
	*orignal_ops = &lsm_stacker_ops;
	smb_wmb();

has_reg:
	printk(KERN_INFO "LSM STACKER MODULES REGISTER SUCCESS\n");

out:
	return res;
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
