#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/security.h>
#include <linux/skbuff.h>
#include <linux/netlink.h>
#include <linux/capability.h>
#include <linux/rwsem.h>
static hlist_head stacker_head;
static atomic_t lsm_stacker_ref = ATOMIC_INIT(0);

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


