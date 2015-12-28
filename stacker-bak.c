/* "Stacker" Linux security module (LSM), version 2002-09-04.
 * Load this module first as the primary LSM module,
 * and you can then stack (load) multiple additional LSM modules.
 *
 * Copyright (C) 2002 David A. Wheeler <dwheeler@dwheeler.com>.
 *  This program is free software; you can redistribute it and/or modify
 *  it under the terms of the GNU General Public License as published by
 *  the Free Software Foundation; either version 2 of the License, or
 *  (at your option) any later version.
 *
 * Below is administrator documentation, LSM module authoring documentation,
 * design documentation, and the code itself.
 */

/* WARNING!  THIS IS AN EARLY DRAFT.  IT IS _NOT_ INTENDED FOR USE YET.
 * PLEASE review the code and send me feedback, esp. on any "TODO" items.
 *  "The source loads into vim.  It probably doesn't compile.
 *   Run it only if you need to trash your hard drive."
 */

/* ADMINISTRATOR DOCUMENTATION
 *
 * This is the administrator documentation for the "Stacker" Linux
 * security module (LSM).  The "Stacker" module allows you to combine
 * multiple LSM modules; these other modules are called the "stacked" modules.
 *
 * For many purposes, you can simply install the stacker module first
 * (e.g., using "modprobe stacker"), and then insert the various LSM modules.
 * When started, Stacker has a single module stacked: the "capability" module,
 * which implements POSIX capabilities.  The order of the modules
 * is important; whenever a new stacked module is added,
 * by default it is added "just before the last module".  For example,
 * when Stacker starts up, the list of modules is simply {capability};
 * adding "A" would result in the list {A, capability}, and then
 * adding "B" would result in the list {A, B, capability}.
 * This ordering should be correct for many uses; see below for how to
 * control ordering if you need to do so.
 *
 * With one exception, by default Stacker takes each request for permission
 * (such as "inode_create") and then asks for permissions from ALL of the
 * stacked LSM modules in order. If ANY stacked module returns an error
 * (meaning "no, it's forbidden"), then Stacker returns the
 * forbidding error code of the first stacked module that says it's forbidden.
 * If you don't want the later modules called if an earlier module
 * determines that the permission shouldn't be granted, turn on
 * "short_circuit_restrictive" as described below.
 *
 * The exception is the hook capable().  In the case of capable(),
 * the stacked modules are examined in order, and special rules are used:
 * + If ANY stacked module returns 0 ("capability granted"), then the
 *   capability will be granted unless countermanded by a later module.
 *   Note that this is fundamentally the reverse of other hooks:
 *   "if any module grants the capability, it's granted".
 *   Thus, stacked modules should not grant capabilities unless they really
 *   mean to grant them.  Normally all the other modules are still consulted,
 *   but if you turn on "short_circuit_restrictive", a 0 will halt examining
 *   any more stacked modules.
 * + If any stacked module returns -EPERM ("capability not granted"), then the
 *   capability won't be granted unless some other module grants it.
 * + If a stacked module returns -EACCES, it undoes any previous
 *   permission (and resets the return value to be -EPERM unless a
 *   still-later module returns 0).
 * + If a stacked module returns -EPIPE, _no_ later stacked modules
 *   are consulted and -EPERM ("no capability granted") is returned.
 *   Note that this could cause trouble if later stacked modules manipulate
 *   their state in a call to capable().
 * In the end, stacker will return 0 if there is a capability granted
 * and -EPERM if not.  If there are no stacked modules, its
 * the result is -EPERM (which can be a serious problem unless the Stacker
 * module itself is stacked under something else).
 *
 * Some hooks don't return permission values; in that case
 * all of the corresponding hooks for each stacked module are called.
 * (An example is "stacker_inode_post_create").
 *
 * Note - except for the special case in the capable() hook
 * (where something returns -EPIPE), by default Stacker always calls all
 * of the stacked modules for every request.  This should help stacked
 * modules reliably manipulate their internal state (if any).
 *
 * Since the order of modules matters, you can set the "ordering policy"
 * of the Stacker module that will control exactly where a new
 * policy is added when inserted.  The possible ordering policies are:
 * + ORDER_BEFORE_FIRST: Add module before current first module
 * + ORDER_BEFORE_LAST: Add module before current last module
 * + ORDER_AFTER_LAST: Add module after current last module
 *                     (the new module it will become the last module)
 * + ORDER_REPLACE_FIRST: Add module as first, simultaneously making the
 *                        current first module inactive.
 * + ORDER_REPLACE_LAST: Add module as last module, simultaneously making the
 *                       current last module inactive.
 * + ORDER_SMART: If the module is named "dummy", "capable", or "selinux",
 *                treat as ORDER_REPLACE_LAST; otherwise, act as
 *                ORDER_BEFORE_LAST.  ORDER_SMART is the default.
 *
 * Stacker CANNOT stack itself, sorry.  Only one instance of Stacker
 * is supported in a kernel. You CAN stack Stacker under some other
 * LSM multiplexor.  Stacker does NOT use any of the security fields
 * in Linux kernel data structures.
 * Note that if you are using multiple multiplexors, your
 * security policy is probably too complicated.
 *
 * WARNING! Not all LSM modules can be combined with all other modules;
 * it's up to you, the administrator who is doing the stacking, to determine
 * if any specific stacking approach is appropriate.  For example, many kernel
 * structures have a (void *) security field that can be used by LSM modules;
 * if more than one LSM module is stacked that use the same field for the
 * same kernel structure, then those LSM modules MUST agree on the meaning of
 * the field and cooperate in its use or they'll violently conflict.
 * The loading order of modules matters; if an earlier module in the list
 * makes a change to the state of something, the later modules will see
 * the NEW state.  As a result, stacking is
 * more likely to be successful if you're combining several "small" LSM modules
 * that don't use any kernel structure security fields, optionally with
 * a "large" LSM module that uses one or more such fields.
 * Typically, the last module in the list will implement traditional
 * Linux security (e.g., be "capability", "dummy", or an LSM module that
 * includes an implementation of those modules).
 * "Small" modules that don't modify kernel state, don't return 0 at
 * all in their capable() authoritative hook when loaded as a stacked module,
 * and are designed to NOT perform dummy or capability actions when
 * loaded as a stacked (secondary) module are more likely to work.
 * Modules that are designed to work together (e.g., they store the
 * same information in a field) or are designed to heterogeneously stack 
 * (e.g., creating a linked list of different data) may also work.
 *
 * In particular, the dummy version of netlink_send manipulates other
 * data structures; if another stacked module ALSO manipulates netlink_send
 * data structures, you may want to double-check the order of their loading
 * to make sure the "right" module wins.
 *
 * In the default version of Stacker, once a module is loaded, 
 * it cannot be simply removed (e.g., using rmmod).
 * This limitation is intentionally added to gain greater
 * performance while keeping safety.
 * If you don't want a given LSM module to be used,
 * you must first deactivate the module by sending the
 * Stacker the "deactivate" command for that module;
 * the module will no longer be called for security decisions but
 * will still be loaded in the system.  You can reactivate deactivated
 * modules later; reactivated modules are inserted using the same rules
 * as a new module.  A deactivated module CAN be removed, but it would
 * be wise to NOT do so (at least for a while).  If you really
 * want to add/remove easily, consider recompiling the module and setting
 * CONSERVATIVE_STACKER_LOCKING; this will enable easy addition/removal
 * of modules, but is slower overall.
 *
 * Unloading modules is always a problem in kernels, of course.
 * However, in the default scheme, if the administrator actually removes
 * (not just deactivates) a security module, and there are malicious
 * local attackers, the attacker might be able to crash the system.
 * An attacker who knows about the Stacker AND that stacked modules
 * get removed could create a large number of tasks with very low priority,
 * and then have the tasks constantly do things that walk the linked list of
 * stacked modules (e.g., sys_security calls).
 * If the attacker gets "lucky", they could get a task to enter the
 * module-to-be-removed and hung there long enough to still be running inside
 * the module until after the module is removed.  The likely result would be a
 * sudden system crash.  Creating this situation would be very difficult
 * for a user who doesn't have local access,
 * the result is a one-time crash (not exploited data), and it's hard to
 * exploit, but this is a (remote) possibility.  Of course, if you
 * don't remove modules, this is not a problem.
 *
 * If you're worried about this and really want to completely unload
 * modules, you could use the conservative locking approach.
 * But the simpler approach is to simply not actually unload the
 * security module and its entry - we waste a small amount of memory
 * and trade it for reliability, which is a fair trade.
 * If you want the effect of removal, just deactivate the module.
 * This is likely to only affect experimental/teaching systems anyway -
 * if you're removing security modules, you're almost certainly
 * not running a production system.
 *
 * It's worth noting some general LSM terminology.
 * Technically, capable() is an "authoritative" hook, because it can
 * override the decisions of other access control mechanisms.
 * The other hooks that return access control values are merely
 * "restrictive" hooks; they can add additional restrictions, but can't
 * override the decision from the built-in DAC mechanisms in Linux.
 *
 *
 * LSM MODULE AUTHORING DOCUMENTATION
 *
 * This is documentation for LSM module authors who want to write
 * modules that will "stack" well.
 *
 * LSM module authors should write their modules so that they'll stack
 * more easily, if that's a possibility:
 *
 * 1. To stack at all, a module needs to call
 * mod_reg_security(); typically this is done if register_security()
 * fails (see capability.c for an example of how to do this).
 * Usually if an LSM module is loaded as a secondary module, it should
 * set a flag named "secondary". Modules should normally set
 * secondary to true and any other variable used by the LSM module BEFORE 
 * calling mod_reg_security() to avoid a race condition.
 * DO NOT call mod_reg_security() first, followed by secondary = 1;
 * if you do, there will be a period of time where the module is loaded
 * as a secondary module BUT the value of "secondary" will make the module
 * THINK that it's not a secondary module. This race may cause
 * various terrible effects.  So, be sure to set secondary before calling
 * mod_reg_security().
 *
 * 2. If you want your LSM module to have maximum flexibility when
 * stacked, you should NOT duplicate the nontrivial actions of the
 * "dummy" or "capability" module whenever your module is loaded as a stacked
 * module (e.g., its "secondary" flag is on); if you duplicate those actions,
 * this will limit the amount of control an administrator has over
 * a stacked system.
 * By nontrivial, I mean anything other than "return" or "return 0".
 * Instead, if "secondary" is on, the LSM module should do ONLY the checks
 * unique to the LSM module; then, if it's the override for capable(),
 * forbid it (by returning -EPERM), and if it's the override for anything
 * else, permit it by returning 0.
 * This is MOST important for the capable()
 * call; since capable() is an authoritative hook, anything it allows will be
 * allowed no matter what.  Unless your LSM module determines that a given
 * capability must be raised according to its own rules, in your LSM module's
 * hook for capable() return an error if "secondary" is on.  Also examine all
 * hooks which have nontrivial implementations in dummy.c or capability.c.
 * So, look carefully at the LSM module's implementation of the following
 * hooks: capable, netlink_send, netlink_recv, task_reparent_to_init, and
 * ip_decode_options (these are calls that have nontrivial implementations
 * in "dummy.c").  Also look carefully at these hooks:
 * ptrace, capget, capset_check, capset_set, bprm_set_security,
 * bprm_compute_creds, task_post_setuid, kmod_set_label, task_reparent_to_init,
 * ip_decode_options (these have nontrivial implementations in "capability.c").
 *
 * 3. The LSM module's implementation of sys_security should either
 * (a) always return -ENOSYS, or
 * (b) check for the id and if it doesn't match, return -ENOSYS.
 * Otherwise, sys_security calls won't stack correctly.
 *
 * 4. DOCUMENT CLEARLY for your LSM module any requirements/limitations
 * on stacking the module, to help administrators determine if they can
 * stack your module with other modules.
 * If the module uses or does not use any
 * of the (void*) security fields in the kernel structures
 * (if you use them, please document WHICH ones).  That way,
 * administrators can quickly detect certain kinds of conflicts between
 * stacked modules.  Document whether or not the module re-implements
 * the capability or dummy module when loaded as a secondary module.
 * And, if you know that certain modules WILL work
 * together (e.g., because they're designed to lock correctly and use
 * the same meaning for certain security fields), document that too.
 * Also document any deactivation requirements.
 *
 *
 * STACKER DESIGN DOCUMENTATION
 *
 * The fundamental data structure in Stacker is a "struct module_entry";
 * each instance represents a stacked LSM module.
 * A module entry points to the "next" active module entry,
 * the next inactive module entry, the module name, and the module operations.
 * The active list identifies which modules are currently consulted
 * by the stacker, and is a singly linked list of "struct module_entry"s;
 * the variable "stacked_modules" points to the head of the list, and
 * "penultimate_stacked_module" points to the next-to-last entry
 * in the list (or NULL if there are less than two entries).
 * The active list is also a singly-linked list;
 * "inactive_stacked_modules" points to the head of this list
 * (and is NULL if the list is empty).  Note that
 * struct module_entry has a "next" value that is used ONLY when on
 * the active list, and "next" MUST NOT BE REUSED for the inactive list.
 *
 * Stacker also has various other state values, such as the
 * "ordering_policy" that determines where newly-added or
 * reactivated LSM modules are placed.
 *
 * The stacking module's state, in particular the list of currently-stacked
 * modules, must support a massive number of reads (which should run
 * at high speed) and extremely rare writes (which can be slow).
 *
 * Therefore, the default implementation exploits the fact that
 * on all architectures supported by Linux, writes to aligned pointers
 * are atomic (this assumption is documented in Paul Rusty Russell's
 * "Unreliable Guide to Locking" which is part of the Linux kernel
 * documentation; it notes specifically that Alan Cox already assumes
 * atomic pointer writes for Linux kernel code.
 * James Morris and Greg KH also confirmed that they believe this is a
 * valid assumption in a Linux kernel module).
 * In this approach, to add a module to the active list,
 * it's prepared, wmb() is called (to ensure that out-of-order memory
 * writes won't create garbage values),
 * and then a single pointer is written to activate the module.
 * A similar process is used to deactivate a module.
 * This means that NO LOCKS are required for reading, including following the
 * stacked list. Locks are still required for writing (to prevent
 * simultaneous state changes from crashing the system), but writes
 * to the Stacker state is expected to be rare anyway so slower writes
 * aren't a problem.
 *
 * The big problem is removing an LSM module in the default implementation.
 * In this implementation, you MUST first "deactivate" an LSM module
 * before the LSM module can be removed from the system.
 * There will be a tiny memory leak whenever a module is removed
 * (of a module_entry); for most people, this is irrelevant.
 * It would be wise to wait a while between deactivating a module
 * and actually removing it, so that threads will have a chance to
 * complete executing the module if they've started.
 * There's no way to know "how long" you must wait between deactivating
 * and removing a module (though 60 seconds should be far more than enough in
 * most loads); if this bothers you, then you need to use
 * the CONSERVATIVE_STACKER_LOCKING alternative.
 *
 * Alternatively, you may compile the Stacker code with the
 * "CONSERVATIVE_STACKER_LOCKING" flag turned on (this is NOT the default).
 * Turning on this flag means that a reader/writer semaphore will be used,
 * and every access to the stacker's state will use a read or write lock.
 * With this approach, you can remove stacked
 * modules without disabling them first and without leaking memory.
 * Also, the conservative is easier to get right, so if you're worried
 * that there may be an error in the locking techniques used in the
 * default approach, turn on the CONSERVATIVE_STACKER_LOCKING flag and
 * accept the performance hit.  In particular, this helps for finding bugs
 * ("is the non-conservative approach the problem?"); the non-conservative
 * approach requires EXACTLY correct code in certain spots or game over.
 * It is also useful if your CPU architecture doesn't support atomic
 * writes of aligned pointers, though I doubt Linux itself would run on
 * such architectures.
 * However, this approach is MUCH slower, which is why it's not the default.
 *
 */


/* This version was based on patch-2.5.26-lsm1 */




#include <linux/config.h>
#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/security.h>
#include <linux/skbuff.h>
#include <linux/netlink.h>
#include <linux/capability.h>
#include <linux/rwsem.h>
#include <linux/semaphore.h>
#include <asm/system.h>

/* Magic number (id) for stacker - computed using
 * echo "stacker" | md5sum | cut -c -8
 */
#define STACKER_MAGIC 0xaf8d3836


#ifdef CONSERVATIVE_STACKER_LOCKING

/* Turn on "CONSERVATIVE_STACKER_LOCKING" to use an extremely conservative,
 * safe, and slow locking technique in the stacker.
 *
 * You MUST use this technique if you are dealing with a
 * (nasty and rare!) computer architecture where aligned pointer writes
 * are not atomic.
 *
 * This approach uses a multiple reader - one writer semaphor;
 * whenever using/changing stacker state (in particular the linked list
 * of modules, etc.), grab this lock.  Note that writing is VERY rare.
 * This could switch to big-reader locks (brlocks), but using them requires
 * an allocation of an id.  Besides, if you want speed, the default
 * approach is even faster.  In the future an RCU lock might be appropriate,
 * if they're ever added to Linux, but again, why bother since the
 * default implementation is faster still.  For more info on Linux locking,
 * see: http://www.linuxjournal.com/article.php?sid=5833
 *
 */
struct rw_semaphore stacker_rwsem = RW_LOCK_UNLOCKED;

#define INIT_STACKER_LOCKING
#define LOCK_STACKER_FOR_READING down_read(&stacker_rwsem)
#define UNLOCK_STACKER_FOR_READING up_read(&stacker_rwsem)
#define LOCK_STACKER_FOR_WRITING down_write(&stacker_rwsem)
#define UNLOCK_STACKER_FOR_WRITING up_write(&stacker_rwsem)

#else /* ! CONSERVATIVE_STACKER_LOCKING */

/* The default: non-conservative stacker locking.
 * This approach uses aligned pointer writes (presuming they are atomic)
 * to completely avoid the need for read locks.
 */

struct semaphore stacker_sem;

/* TODO: I'm using semaphore and down_interruptable. Are there
   any hooks that can be called inside an interrupt where it is NOT
   possible to sleep on a semaphore?
*/

#define INIT_STACKER_LOCKING  sema_init(&stacker_sem, 1)
#define LOCK_STACKER_FOR_READING
#define UNLOCK_STACKER_FOR_READING
#define LOCK_STACKER_FOR_WRITING down_interruptible(&stacker_sem)
#define UNLOCK_STACKER_FOR_WRITING up(&stacker_sem)
#endif /* CONSERVATIVE_STACKER_LOCKING */


/* Flag to keep track of how we were registered */
static int secondary; /* = 0; if set to 1, Stacker is itself stacked. */

static int ignore_stacker_sys_security; /* = 0; if 1, stacker ignores cmds */

static int short_circuit_restrictive;   /* = 0; if 1, short-circuit restrictive
					     hooks */
static int short_circuit_capable;       /* = 0; if 1, short-circuit capable() */

static int forbid_stacker_register;     /* = 0; if 1, can't register */

/* The ordering policy when adding a new module.
 * ORDER_BEFORE_FIRST adds new modules in front of all others.
 * ORDER_SMART adds "dummy" or "capable" as ORDER_REPLACE_LAST,
 * otherwise it acts as ORDER_BEFORE_LAST.
 * Thus, adding modules X, Y, Z will result in the order (X, Y, Z, Dummy).
 * TODO: Maybe add a policy for "add after named entry", and create
 * a way to search for a named entry and store its pointer.
 */

enum ordering_policy_options { ORDER_BEFORE_FIRST, ORDER_BEFORE_LAST,
       	ORDER_AFTER_LAST, ORDER_REPLACE_FIRST, ORDER_REPLACE_LAST,
       	ORDER_SMART };

enum ordering_policy_options ordering_policy = ORDER_SMART;



/* A "module entry" keeps track of one of the stacked modules
 * Note that module_operations is aggregated instead of being pointed to -
 * it's one less allocation and one less pointer to follow. */

struct module_entry;
struct module_entry {
	struct module_entry *next; /* MUST BE FIRST for alignment */
	struct module_entry *inactive_next; /* USE THIS for inactive list */
	char *module_name;
	struct security_operations module_operations;
};

/* If Stacker is the primary LSM module, it will initialize to have
   a single module_entry for the "capability" module; this is its value: */

struct module_entry capability_entry {
	.next = 		NULL,
	.inactive_next = 	NULL,
	.module_name = 		"capability",
	.module_operations = 	&capability_ops,
};


/* The set of LSM modules stacked by this "stacker" module
   is stored as a singly linked list of module_entries whose head is
   pointed to by stacked_modules. It's initially NULL (an empty list). */
static struct module_entry *stacked_modules;


/* penultimate_stacked_module points to the next-to-last
 * entry in the stacked list if there are 2+ entries, else it's NULL;
 * this pointer is used to make modifying the end a constant time operation.
 *
 * Here are a few invariants that may help you understand this:
 * len(list)==0: stacked_modules==penultimate_stacked_module==NULL.
 * len(list)==1: stacked_modules==x, x->next == NULL,
 *               penultimate_stacked_module==NULL.
 * len(list)==2: stacked_modules==penultimate_stacked_module==x,
 *               x->next == y, y->next == NULL.
 * len(list)==3: stacked_modules==x, x->next == y,
 *               y->next == z, z->next == NULL,
 *               penultimate_stacked_module==y.
 * */
static struct module_entry *penultimate_stacked_module;

/* List of "inactive" modules.  Follow the "inactive_next" pointer,
 * NOT the next pointer, to traverse this list. */
static struct module_entry *inactive_stacked_modules;


/* Maximum number of characters in a stacked LSM module name */
#define MAX_MODULE_NAME_LEN 128


/* Walk through the linked list of modules in stacked_modules
 * and ask each (in turn) for their results, then return the
 * results.  If more than one module reports an error, return
 * the FIRST error code.  Note that this ALWAYS calls ALL modules, since
 * some modules may change state when called.
 * This is wrapped in do { .. } while(0), see
 * http://www.kernelnewbies.org/faq/index.php3#dowhile for
 * why this is a good idea.  */

#define RETURN_ERROR_IF_ANY_ERROR(FUNCTION_TO_CALL) do { \
	int final_result = 0; \
	int result; \
	struct module_entry *m; \
	LOCK_STACKER_FOR_READING; \
	for (m = stacked_modules; m; m = m->next) { \
		result = m->module_operations.FUNCTION_TO_CALL; \
		if (result && !final_result) { \
			final_result = result; \
			if (short_circuit_restrictive) break; \
		} \
	} \
	UNLOCK_STACKER_FOR_READING; \
	return final_result; } while (0)



/* Call all modules in stacked_modules' FUNCTION_TO_CALL routine */
#define CALL_ALL(FUNCTION_TO_CALL) do { \
	struct module_entry *m; \
	LOCK_STACKER_FOR_READING; \
	for (m = stacked_modules; m; m = m->next) { \
		m->module_operations.FUNCTION_TO_CALL; \
	} \
	UNLOCK_STACKER_FOR_READING; } while (0)



static void add_module_entry(struct module_entry *new_module_entry)
{
	/* Add new_module_entry to the stacked_modules list. The caller MUST
	 * first grab the write lock before calling this function. */

	enum ordering_policy_options actual_policy = ordering_policy;

	/* Determine where to place the new module */
	/* TODO: Create separate list, and loop through it. */
	if (actual_policy == ORDER_SMART) {
		if (!strcmp(new_module_entry->name, "capability") ||
		    !strcmp(new_module_entry->name, "dummy") ||
		    !strcmp(new_module_entry->name, "selinux")) {
			actual_policy = ORDER_REPLACE_LAST;
		} else {
			actual_policy = ORDER_BEFORE_LAST;
		}
	}
	if (!stacked_modules) {
		actual_policy = ORDER_BEFORE_FIRST;
	}
	if (stacked_modules && !(stacked_modules->next) && /* only 1! */
	       (actual_policy == ORDER_BEFORE_LAST))
		actual_policy = ORDER_BEFORE_FIRST;


	/* Finally, add it.  This must be the very last step, since
	   once this code is executed the module will IMMEDIATELY go live.
	   Modifying the linked list pointed to by stacked_module must
	   ALWAYS be the last step, it must be preceded by a call to wmb()
	   (to ensure that memory order), and the "next" field of an entry
	   (once it goes live) must ALWAYS point to an entry that was on
	   the list at the time (that's why we don't reuse the "next"
	   field when dealing with inactive entry).
	   Note: if list is empty, only ORDER_BEFORE_FIRST is called. */

	switch (actual_policy) {
		ORDER_BEFORE_FIRST:
			if (stacked_modules && !(stacked_modules->next))
				penultimate_stacked_module = new_module_entry;
			new_module_entry->next = stacked_modules;
			wmb(); /* Make ready for insertion into list */
			stacked_modules = new_module_entry;
			break;
		ORDER_BEFORE_LAST:
			/* Can only get here if 2+ modules. */
			new_module_entry->next =
			       	penultimate_stacked_module->next;
			wmb();
			penultimate_stacked_module->next = new_module_entry;
			break;
		ORDER_AFTER_LAST:
			/* Can only get here if 1+ modules. */
			new_module_entry->next = NULL;
			if (!penultimate_stacked_module) { /* EXACTLY 1 */
				penultimate_stacked_module = stacked_modules;
			} else { /* > 1 module */
				penultimate_stacked_module =
					penultimate_stacked_module->next;
			}
			wmb();
			penultimate_stacked_module->next = new_module_entry;
			break;
		ORDER_REPLACE_FIRST:
			/* Can only get here if 1+ modules. */
			new_module_entry->next = stacked_modules->next;
			if (penultimate_stacked_module==stacked_modules) {
				/* EXACTLY 2 modules */
				penultimate_stacked_module = new_module_entry;
			}
			stacked_modules->next_inactive =
			       	inactive_stacked_modules;
			inactive_stacked_modules = stacked_modules;
			wmb();
			stacked_modules = new_module_entry;
			break;
		ORDER_REPLACE_LAST:
			/* Can only get here if 2+ modules. */
			new_module_entry->next = NULL;
			(penultimate_stacked_module->next)->next_inactive =
			       	inactive_stacked_modules;
			inactive_stacked_modules = 
				penultimate_stacked_module->next;
			wmb();
			penultimate_stacked_module->next = new_module_entry;
			break;

	};
	/* Do this here, just to make SURE that the state of all SMP
	   processors will now include the new active module */
	wmb();
}


static int stacker_sethostname (char *hostname)
{
	RETURN_ERROR_IF_ANY_ERROR(sethostname(hostname));
}

static int stacker_setdomainname (char *domainname)
{
	RETURN_ERROR_IF_ANY_ERROR(setdomainname(domainname));
}

static int stacker_reboot (unsigned int cmd)
{
	RETURN_ERROR_IF_ANY_ERROR(reboot(cmd));
}

static int stacker_ioperm (unsigned long from, unsigned long num, int turn_on)
{
	RETURN_ERROR_IF_ANY_ERROR(ioperm(from, num, turn_on));
}

static int stacker_iopl (unsigned int old, unsigned int level)
{
	RETURN_ERROR_IF_ANY_ERROR(iopl(old, level));
}

static int stacker_ptrace (struct task_struct *parent, struct task_struct *child)
{
	RETURN_ERROR_IF_ANY_ERROR(ptrace(parent, child));
}

static int stacker_capget (struct task_struct *target, kernel_cap_t * effective,
			 kernel_cap_t * inheritable, kernel_cap_t * permitted)
{
	RETURN_ERROR_IF_ANY_ERROR(capget(target, effective, inheritable, permitted));
}

static int stacker_capset_check (struct task_struct *target,
			       kernel_cap_t * effective,
			       kernel_cap_t * inheritable,
			       kernel_cap_t * permitted)
{
	RETURN_ERROR_IF_ANY_ERROR(capset_check(target, effective, inheritable, permitted));
}

static void stacker_capset_set (struct task_struct *target,
			      kernel_cap_t * effective,
			      kernel_cap_t * inheritable,
			      kernel_cap_t * permitted)
{
	CALL_ALL(capset_set(target, effective, inheritable, permitted));
}

static int stacker_acct (struct file *file)
{
	RETURN_ERROR_IF_ANY_ERROR(acct(file));
}

static int stacker_capable (struct task_struct *tsk, int cap)
{
	/* This is an AUTHORITATIVE hook, so it needs to be
	 * handled differently than the normal "restrictive" hooks.
	 * Instead of returning a failure if any module fails,
	 * we need to return a success if ANY module succeeds (returns 0).
	 *
	 * Unless short_circuit_capable is true, we'll call all of the
	 * modules (even if an earlier one replies with a success).
	 *
	 * Returns 0 if allowed, -EPERM if not.
	 * If a stacked module returns -EPIPE, _no_ later stacked modules
	 * are consulted and -EPERM is returned.
	 * If a stacked module returns -EACCES, it undoes any previous
	 * permission (and resets the interim return value to be -EPERM);
	 * only a still-later module can return 0.
	 */

	int final_result = -EPERM; 
	int result; 
	struct module_entry *m;

	LOCK_STACKER_FOR_READING; 
	for (m = stacked_modules; m; m = m->next) { 
		result = (m->module_operations).capable(tsk,cap); 
		if (result == -EPIPE) {
			final_result = -EPERM;
			break;
		} else if (result == -EACCES) {
			final_result = -EPERM;
		} else if (!result) {
			final_result = 0; 
			if (short_circuit_capable) break;
		}
	} 
	UNLOCK_STACKER_FOR_READING;

	return final_result;
}


static int stacker_sysctl (ctl_table * table, int op)
{
	RETURN_ERROR_IF_ANY_ERROR(sysctl(table, op));
}

static int deactivate_entry(char *name) {
	/* Deactivate "name"; stacker write lock must be held. */
	struct module_entry *m;
	struct module_entry *m_prev = NULL;

	for (m = stacked_modules; m; m_prev = m, m = m->next) {
		if (!strcmp(name, m->module_name)) { /* found */
			if (m_prev)
       				m_prev->next = m->next;
			else
       				stacked_modules = m->next;
			wmb();
			return 0;
		}
	}
	return -ENOENT;
}

static int reactivate_entry(char *name) {
	/* Reactivate "name";  stacker write lock must be held. */
	struct module_entry *m;
	struct module_entry *m_prev = NULL;

	for (m = inactive_stacked_modules; m;
		m_prev = m, m = m->inactive_next) {
		if (!strcmp(name, m->module_name)) { /* found */
			if (m_prev)
       				m_prev->inactive_next =
					m->inactive_next;
			else
       				inactive_stacked_modules =
					m->inactive_next;
			wmb();
			add_module_entry(m);
			return 0;
		}
	}
	return -ENOENT;
}

static int stacker_sys_security (unsigned int id, unsigned int call,
			       unsigned long *args)
{
	int result;
	if (id == STACKER_MAGIC) {
		if (current->euid) /* Only root can invoke stacker commands */
			return -EPERM;
		LOCK_STACKER_FOR_WRITING; 
		if (ignore_stacker_sys_security) {
			UNLOCK_STACKER_FOR_WRITING; 
			return -EPERM;
		}
		switch (call) {
			case 0: /* LOCKDOWN - don't allow future changes */
				forbid_stacker_register = 1;
				/* fall-through */
			case 1: /* Ignore future stacker commands.
				 * There is intentionally no interface for
				 * re-enabling commands. */
			       	ignore_stacker_sys_security = 1;
				goto sys_security_return_zero;
			case 4:
				short_circuit_restrictive = 0;
				goto sys_security_return_zero;
			case 5:
				short_circuit_restrictive = 1;
				goto sys_security_return_zero;
			case 6:
				short_circuit_capable = 0;
				goto sys_security_return_zero;
			case 7:
				short_circuit_capable = 1;
				goto sys_security_return_zero;
			case 9:
				forbid_stacker_register = 1;
				goto sys_security_return_zero;

			case 20:
				ordering_policy = ORDER_BEFORE_FIRST;
				goto sys_security_return_zero;
			case 21:
				ordering_policy = ORDER_BEFORE_LAST;
				goto sys_security_return_zero;
			case 22:
				ordering_policy = ORDER_AFTER_LAST;
				goto sys_security_return_zero;
			case 23:
				ordering_policy = ORDER_REPLACE_FIRST;
				goto sys_security_return_zero;
			case 24:
				ordering_policy = ORDER_REPLACE_LAST;
				goto sys_security_return_zero;
			case 25:
				ordering_policy = ORDER_SMART;
				goto sys_security_return_zero;


			case 30: /* Deactivate */
				/* TODO: How to get name safely? get_user()?
				 * copy_from_user()? */
				result = deactivate_entry("TODO");
				/* TODO: should we call its "exit" or
				   unregister_security entry?
				   maybe there should be options to
				   deactivate, or separate calls to do this? */
				UNLOCK_STACKER_FOR_WRITING; 
				return result;
			case 31: /* Reactivate */
				/* TODO: How to get name safely? get_user()?
				 * copy_from_user()? */
				result = reactivate_entry("TODO");
				UNLOCK_STACKER_FOR_WRITING; 
				return result;

			/* TODO: List LSM modules names in order. Not sure
			 * how to return such info.  Could create an entry
			 * in "/proc" instead.  */
		}
	} else {
		/* Call wasn't intended for the stacker itself.
		 * Call each module in turn until one returns something
		 * other than -ENOSYS.  If they ALL return -ENOSYS, then
		 * return that.  Note that, unlike the other calls, this
		 * does NOT call every module in all cases.
		 * This assumes that modules will check the id and, if
		 * it doesn't match, return -ENOSYS.  As long as they
		 * all do that (and have independent id's) this works
		 * even if a valid return value is -ENOSYS.. in that case,
		 * the return value will (correctly) be -ENOSYS.
		 */
		int result;
		struct module_entry *m;
		LOCK_STACKER_FOR_READING;
		for (m = stacked_modules; m; m = m->next) {
			result = m->module_operations.
				sys_security(id,call,args);
			if (result != -ENOSYS) {
				UNLOCK_STACKER_FOR_READING;
				return result;
			}
		}
	}
	UNLOCK_STACKER_FOR_READING;
	/* This is the fall-through return value, for different reasons.
	 * If it's for the stacker id, it's not a valid command; if it's
	 * for something else, no module returned something other than
	 * -ENOSYS. */
	return -ENOSYS;

sys_security_return_zero:
	wmb(); /* Just to MAKE SURE the word gets out; may be unnecessary */
	UNLOCK_STACKER_FOR_WRITING; 
	return 0;
}

static int stacker_swapon (struct swap_info_struct *swap)
{
	RETURN_ERROR_IF_ANY_ERROR(swapon(swap));
}

static int stacker_swapoff (struct swap_info_struct *swap)
{
	RETURN_ERROR_IF_ANY_ERROR(swapoff(swap));
}

static int stacker_quotactl (int cmds, int type, int id, struct super_block *sb)
{
	RETURN_ERROR_IF_ANY_ERROR(quotactl(cmds,type,id,sb));
}

static int stacker_quota_on (struct file *f)
{
	RETURN_ERROR_IF_ANY_ERROR(quota_on(f));
}

static int stacker_syslog (int type)
{
	RETURN_ERROR_IF_ANY_ERROR(syslog(type));
}

static int stacker_netlink_send (struct sk_buff *skb)
{
	/* NOTE: The dummy module does this:
		if (current->euid == 0)
			cap_raise (NETLINK_CB (skb).eff_cap, CAP_NET_ADMIN);
		else
			NETLINK_CB (skb).eff_cap = 0;
	 * if this would be a problem with your module, then tell
	 * your administrators what to do. */

	RETURN_ERROR_IF_ANY_ERROR(netlink_send(skb));
}


static int stacker_netlink_recv (struct sk_buff *skb)
{
	RETURN_ERROR_IF_ANY_ERROR(netlink_recv(skb));
}

static int stacker_bprm_alloc_security (struct linux_binprm *bprm)
{
	RETURN_ERROR_IF_ANY_ERROR(bprm_alloc_security(bprm));
}

static void stacker_bprm_free_security (struct linux_binprm *bprm)
{
	CALL_ALL(bprm_free_security(bprm));
}

static void stacker_bprm_compute_creds (struct linux_binprm *bprm)
{
	CALL_ALL(bprm_free_compute_creds(bprm));
}

static int stacker_bprm_set_security (struct linux_binprm *bprm)
{
	RETURN_ERROR_IF_ANY_ERROR(bprm_set_security(bprm));
}

static int stacker_bprm_check_security (struct linux_binprm *bprm)
{
	RETURN_ERROR_IF_ANY_ERROR(bprm_check_security(bprm));
}

static int stacker_sb_alloc_security (struct super_block *sb)
{
	RETURN_ERROR_IF_ANY_ERROR(sb_alloc_security(sb));
}

static void stacker_sb_free_security (struct super_block *sb)
{
	CALL_ALL(sb_free_security(sb));
}

static int stacker_sb_statfs (struct super_block *sb)
{
	RETURN_ERROR_IF_ANY_ERROR(sb_statfs(sb));
}

static int stacker_mount (char *dev_name, struct nameidata *nd, char *type,
			unsigned long flags, void *data)
{
	RETURN_ERROR_IF_ANY_ERROR(mount(dev_name, nd, type, flags, data));
}

static int stacker_check_sb (struct vfsmount *mnt, struct nameidata *nd)
{
	RETURN_ERROR_IF_ANY_ERROR(check_sb(mnt, nd));
}

static int stacker_umount (struct vfsmount *mnt, int flags)
{
	RETURN_ERROR_IF_ANY_ERROR(umount(mnt, flags));
}

static void stacker_umount_close (struct vfsmount *mnt)
{
	CALL_ALL(umount_close(mnt));
}

static void stacker_umount_busy (struct vfsmount *mnt)
{
	CALL_ALL(umount_busy(mnt));
}

static void stacker_post_remount (struct vfsmount *mnt, unsigned long flags,
				void *data)
{
	CALL_ALL(post_remount(mnt, flags, data));
}


static void stacker_post_mountroot (void)
{
	CALL_ALL(post_mountroot());
}

static void stacker_post_addmount (struct vfsmount *mnt, struct nameidata *nd)
{
	CALL_ALL(post_addmount(mnt, nd));
}

static int stacker_pivotroot (struct nameidata *old_nd, struct nameidata *new_nd)
{
	RETURN_ERROR_IF_ANY_ERROR(pivotroot(old_nd, new_nd));
}

static void stacker_post_pivotroot (struct nameidata *old_nd, struct nameidata *new_nd)
{
	CALL_ALL(post_pivotroot(old_nd, new_nd));
}

static int stacker_inode_alloc_security (struct inode *inode)
{
	RETURN_ERROR_IF_ANY_ERROR(inode_alloc_security(inode));
}

static void stacker_inode_free_security (struct inode *inode)
{
	CALL_ALL(inode_free_security(inode));
}

static int stacker_inode_create (struct inode *inode, struct dentry *dentry,
			       int mask)
{
	RETURN_ERROR_IF_ANY_ERROR(inode_create(inode, dentry, mask));
}

static void stacker_inode_post_create (struct inode *inode,
	    struct dentry *dentry, int mask)
{
	CALL_ALL(inode_post_create(inode, dentry, mask));
}

static int stacker_inode_link (struct dentry *old_dentry, struct inode *inode,
			     struct dentry *new_dentry)
{
	RETURN_ERROR_IF_ANY_ERROR(inode_link(old_dentry, inode, new_dentry));
}

static void stacker_inode_post_link (struct dentry *old_dentry,
				   struct inode *inode,
				   struct dentry *new_dentry)
{
	CALL_ALL(inode_post_link(old_dentry, inode, new_dentry));
}

static int stacker_inode_unlink (struct inode *inode, struct dentry *dentry)
{
	RETURN_ERROR_IF_ANY_ERROR(inode_unlink(inode, dentry));
}

static int stacker_inode_symlink (struct inode *inode, struct dentry *dentry,
				const char *name)
{
	RETURN_ERROR_IF_ANY_ERROR(inode_symlink(inode, denstry, name));
}

static void stacker_inode_post_symlink (struct inode *inode,
				      struct dentry *dentry, const char *name)
{
	CALL_ALL(inode_post_symlink(inode, dentry, name));
}

static int stacker_inode_mkdir (struct inode *inode, struct dentry *dentry,
			      int mask)
{
	RETURN_ERROR_IF_ANY_ERROR(inode_mkdir(inode, dentry, mask));
}

static void stacker_inode_post_mkdir (struct inode *inode,
	    	struct dentry *dentry, int mask)
{
	CALL_ALL(inode_post_mkdir(inode, dentry, mask));
}

static int stacker_inode_rmdir (struct inode *inode, struct dentry *dentry)
{
	RETURN_ERROR_IF_ANY_ERROR(inode_rmdir(inode, dentry));
}

static int stacker_inode_mknod (struct inode *inode, struct dentry *dentry,
			      int major, dev_t minor)
{
	RETURN_ERROR_IF_ANY_ERROR(inode_mknod(inode, dentry, major, minor));
}

static void stacker_inode_post_mknod (struct inode *inode,
	       	struct dentry *dentry, int major, dev_t minor)
{
	CALL_ALL(inode_post_mknod(inode, dentry, major, minor));
}

static int stacker_inode_rename (struct inode *old_inode,
			       struct dentry *old_dentry,
			       struct inode *new_inode,
			       struct dentry *new_dentry)
{
	RETURN_ERROR_IF_ANY_ERROR(inode_rename(old_inode, old_dentry,
				  new_inode, new_dentry));
}

static void stacker_inode_post_rename (struct inode *old_inode,
				     struct dentry *old_dentry,
				     struct inode *new_inode,
				     struct dentry *new_dentry)
{
	CALL_ALL(inode_post_rename(old_inode, old_dentry,
				  new_inode, new_dentry));
}

static int stacker_inode_readlink (struct dentry *dentry)
{
	RETURN_ERROR_IF_ANY_ERROR(inode_readlink(dentry));
}

static int stacker_inode_follow_link (struct dentry *dentry,
				    struct nameidata *nameidata)
{
	RETURN_ERROR_IF_ANY_ERROR(inode_follow_link(dentry, nameidata));
}

static int stacker_inode_permission (struct inode *inode, int mask)
{
	RETURN_ERROR_IF_ANY_ERROR(inode_permission(inode, mask));
}

static int stacker_inode_permission_lite (struct inode *inode, int mask)
{
	RETURN_ERROR_IF_ANY_ERROR(inode_permission_lite(inode, mask));
}

static int stacker_inode_setattr (struct dentry *dentry, struct iattr *iattr)
{
	RETURN_ERROR_IF_ANY_ERROR(inode_setattr(dentry, iattr));
}

static int stacker_inode_getattr (struct vfsmount *mnt, struct dentry *dentry)
{
	RETURN_ERROR_IF_ANY_ERROR(inode_getattr(mnt,dentry));
}

static void stacker_post_lookup (struct inode *ino, struct dentry *d)
{
	CALL_ALL(post_lookup(ino,d));
}

static void stacker_delete (struct inode *ino)
{
	CALL_ALL(delete(ino));
}

static int stacker_inode_setxattr (struct dentry *dentry, char *name,
	        	void *value, size_t size, int flags)
{
	RETURN_ERROR_IF_ANY_ERROR(inode_setxattr(dentry,name,value,size,flags));
}

static int stacker_inode_getxattr (struct dentry *dentry, char *name)
{
	RETURN_ERROR_IF_ANY_ERROR(inode_getxattr(dentry,name));
}

static int stacker_inode_listxattr (struct dentry *dentry)
{
	RETURN_ERROR_IF_ANY_ERROR(inode_listxattr(dentry));
}

static int stacker_inode_removexattr (struct dentry *dentry, char *name)
{
	RETURN_ERROR_IF_ANY_ERROR(inode_removexattr(dentry,name));
}

static int stacker_file_permission (struct file *file, int mask)
{
	RETURN_ERROR_IF_ANY_ERROR(file_permission(file,mask));
}

static int stacker_file_alloc_security (struct file *file)
{
	RETURN_ERROR_IF_ANY_ERROR(file_alloc_security(file));
}

static void stacker_file_free_security (struct file *file)
{
	CALL_ALL(file_free_security(file));
}

static int stacker_file_llseek (struct file *file)
{
	RETURN_ERROR_IF_ANY_ERROR(file_llseek(file));
}

static int stacker_file_ioctl (struct file *file, unsigned int command,
			     unsigned long arg)
{
	RETURN_ERROR_IF_ANY_ERROR(file_ioctl(file,command,arg));
}

static int stacker_file_mmap (struct file *file, unsigned long prot,
			    unsigned long flags)
{
	RETURN_ERROR_IF_ANY_ERROR(file_mmap(file, prot, flags));
}

static int stacker_file_mprotect (struct vm_area_struct *vma,
	       	unsigned long prot)
{
	RETURN_ERROR_IF_ANY_ERROR(file_mprotect(vma,prot));
}

static int stacker_file_lock (struct file *file, unsigned int cmd, int blocking)
{
	RETURN_ERROR_IF_ANY_ERROR(file_lock(file,cmd,blocking));
}

static int stacker_file_fcntl (struct file *file, unsigned int cmd,
			     unsigned long arg)
{
	RETURN_ERROR_IF_ANY_ERROR(file_fcntl(file,cmd,arg));
}

static int stacker_file_set_fowner (struct file *file)
{
	RETURN_ERROR_IF_ANY_ERROR(file_set_fowner(file));
}

static int stacker_file_send_sigiotask (struct task_struct *tsk,
				      struct fown_struct *fown, int fd,
				      int reason)
{
	RETURN_ERROR_IF_ANY_ERROR(file_send_sigiotask(tsk,fown,fd,reason));
}

static int stacker_file_receive (struct file *file)
{
	RETURN_ERROR_IF_ANY_ERROR(file_receive(file));
}

static int stacker_task_create (unsigned long clone_flags)
{
	RETURN_ERROR_IF_ANY_ERROR(task_create(clone_flags));
}

static int stacker_task_alloc_security (struct task_struct *p)
{
	RETURN_ERROR_IF_ANY_ERROR(task_alloc_security(p));
}

static void stacker_task_free_security (struct task_struct *p)
{
	CALL_ALL(task_free_security(p));
}

static int stacker_task_setuid (uid_t id0, uid_t id1, uid_t id2, int flags)
{
	RETURN_ERROR_IF_ANY_ERROR(task_setuid(id0,id1,id2,flags));
}

static int stacker_task_post_setuid (uid_t id0, uid_t id1, uid_t id2, int flags)
{
	RETURN_ERROR_IF_ANY_ERROR(task_post_setuid(id0,id1,id2,flags));
}

static int stacker_task_setgid (gid_t id0, gid_t id1, gid_t id2, int flags)
{
	RETURN_ERROR_IF_ANY_ERROR(task_setgid(id0,id1,id2,flags));
}

static int stacker_task_setpgid (struct task_struct *p, pid_t pgid)
{
	RETURN_ERROR_IF_ANY_ERROR(task_setpgid(p,pgid));
}

static int stacker_task_getpgid (struct task_struct *p)
{
	RETURN_ERROR_IF_ANY_ERROR(task_getpgid(p));
}

static int stacker_task_getsid (struct task_struct *p)
{
	RETURN_ERROR_IF_ANY_ERROR(task_getsid(p));
}

static int stacker_task_setgroups (int gidsetsize, gid_t * grouplist)
{
	RETURN_ERROR_IF_ANY_ERROR(task_setgroups(gidsetsize,grouplist));
}

static int stacker_task_setnice (struct task_struct *p, int nice)
{
	RETURN_ERROR_IF_ANY_ERROR(task_setnice(p,nice));
}

static int stacker_task_setrlimit (unsigned int resource, struct rlimit *new_rlim)
{
	RETURN_ERROR_IF_ANY_ERROR(task_setrlimit(resource,new_rlim));
}

static int stacker_task_setscheduler (struct task_struct *p, int policy,
				    struct sched_param *lp)
{
	RETURN_ERROR_IF_ANY_ERROR(task_setscheduler(p,policy,lp));
}

static int stacker_task_getscheduler (struct task_struct *p)
{
	RETURN_ERROR_IF_ANY_ERROR(task_getscheduler(p));
}

static int stacker_task_wait (struct task_struct *p)
{
	RETURN_ERROR_IF_ANY_ERROR(task_wait(p));
}

static int stacker_task_kill (struct task_struct *p, struct siginfo *info,
			    int sig)
{
	RETURN_ERROR_IF_ANY_ERROR(task_kill(p,info,sig));
}

static int stacker_task_prctl (int option, unsigned long arg2, unsigned long arg3,
			     unsigned long arg4, unsigned long arg5)
{
	RETURN_ERROR_IF_ANY_ERROR(task_prctl(option,arg2,arg3,arg4,arg5));
}

static void stacker_task_kmod_set_label (void)
{
	CALL_ALL(task_kmod_set_label());
}

static void stacker_task_reparent_to_init (struct task_struct *p)
{
	/* Note that the dummy version of this hook would call:
	 *	p->euid = p->fsuid = 0; */

	CALL_ALL(task_reparent_to_init(p));
}

static void stacker_ip_fragment (struct sk_buff *newskb,
			       const struct sk_buff *oldskb)
{
	CALL_ALL(ip_fragment(newskb,oldskb));
}

static int stacker_ip_defragment (struct sk_buff *skb)
{
	RETURN_ERROR_IF_ANY_ERROR(ip_defragment(skb));
}

static void stacker_ip_decapsulate (struct sk_buff *skb)
{
	CALL_ALL(ip_decapsulate(skb));
}

static void stacker_ip_encapsulate (struct sk_buff *skb)
{
	CALL_ALL(ip_encapsulate(skb));
}

static int stacker_ip_decode_options (struct sk_buff *skb, const char *optptr,
				    unsigned char **pp_ptr)
{
	/* Note - dummy module does special things on this hook */

	RETURN_ERROR_IF_ANY_ERROR(ip_decode_options(skb, optptr, pp_ptr));
}

static void stacker_netdev_unregister (struct net_device *dev)
{
	CALL_ALL(netdev_unregister(dev));
}

static int stacker_socket_create (int family, int type, int protocol)
{
	RETURN_ERROR_IF_ANY_ERROR(socket_create(family,type,protocol));
}

static void stacker_socket_post_create (struct socket *sock, int family,
	       			int type, int protocol)
{
	CALL_ALL(socket_post_create(sock,family,type,protocol));
}

static int stacker_socket_bind (struct socket *sock, struct sockaddr *address,
			      int addrlen)
{
	RETURN_ERROR_IF_ANY_ERROR(socket_bind(sock,address,addrlen));
}

static int stacker_socket_connect (struct socket *sock,
	       	struct sockaddr *address, int addrlen)
{
	RETURN_ERROR_IF_ANY_ERROR(socket_connect(sock,address,addrlen));
}

static int stacker_socket_listen (struct socket *sock, int backlog)
{
	RETURN_ERROR_IF_ANY_ERROR(socket_listen(sock,backlog));
}

static int stacker_socket_accept (struct socket *sock, struct socket *newsock)
{
	RETURN_ERROR_IF_ANY_ERROR(socket_accept(sock,newsock));
}

static void stacker_socket_post_accept (struct socket *sock, 
				      struct socket *newsock)
{
	CALL_ALL(socket_post_accept(sock,newsock));
}

static int stacker_socket_sendmsg (struct socket *sock, struct msghdr *msg,
				 int size)
{
	RETURN_ERROR_IF_ANY_ERROR(socket_sendmsg(sock,msg,size));
}

static int stacker_socket_recvmsg (struct socket *sock, struct msghdr *msg,
				 int size, int flags)
{
	RETURN_ERROR_IF_ANY_ERROR(socket_recvmsg(sock,msg,size,flags));
}

static int stacker_socket_getsockname (struct socket *sock)
{
	RETURN_ERROR_IF_ANY_ERROR(socket_getsockname(sock));
}

static int stacker_socket_getpeername (struct socket *sock)
{
	RETURN_ERROR_IF_ANY_ERROR(socket_getpeername(sock));
}

static int stacker_socket_setsockopt (struct socket *sock, int level, int optname)
{
	RETURN_ERROR_IF_ANY_ERROR(socket_setsockopt(sock,level,optname));
}

static int stacker_socket_getsockopt (struct socket *sock, int level, int optname)
{
	RETURN_ERROR_IF_ANY_ERROR(socket_getsockopt(sock,level,optname));
}

static int stacker_socket_shutdown (struct socket *sock, int how)
{
	RETURN_ERROR_IF_ANY_ERROR(socket_shutdown(sock,how));
}

static int stacker_socket_sock_rcv_skb (struct sock *sk, struct sk_buff *skb)
{
	RETURN_ERROR_IF_ANY_ERROR(socket_sock_rcv_skb(sk,skb));
}

static int stacker_socket_unix_stream_connect (struct socket *sock,
					     struct socket *other)
{
	RETURN_ERROR_IF_ANY_ERROR(socket_unix_stream_connect(sock,other));
}

static int stacker_socket_unix_may_send (struct socket *sock,
				       struct socket *other)
{
	RETURN_ERROR_IF_ANY_ERROR(socket_unix_may_send(sock,other));
}

static int stacker_module_create (const char *name_user, size_t size)
{
	RETURN_ERROR_IF_ANY_ERROR(module_create(name_user,size));
}

static int stacker_module_initialize (struct module *mod_user)
{
	RETURN_ERROR_IF_ANY_ERROR(module_initialize(mod_user));
}

static int stacker_module_delete (const struct module *mod)
{
#ifndef CONSERVATIVE_STACKER_LOCKING
	/* Safety test: unless we're using the conservative locking approach,
	 * don't remove LSM module if it's currently in Stacker's active list.
	 * Instead, you have to deactivate the LSM module before removing it.
	 * This code assumes that the name in "mod" is constant,
	 * and that LSM modules don't play funny games with names
	 * (e.g., name of module here == registration name).
	 * If a module DOES play funny games, then this safety test won't
	 * work and administrators had better not remove LSM modules before
	 * deactivating them (trouble is likely to happen if this
	 * safety test is intentionally sidestepped by administrators or
	 * LSM module writers!).
	 */
	struct module_entry *m;
	LOCK_STACKER_FOR_READING;
	for (m = stacked_modules; m; m = m->next) {
		if (!strcmp(mod->name, m->name)) { /* Found! */
			UNLOCK_STACKER_FOR_READING;
			return -EBUSY; /* Module must not be removed! */
		}
	}
	UNLOCK_STACKER_FOR_READING;
#endif
	RETURN_ERROR_IF_ANY_ERROR(module_delete(mod));

}

static int stacker_ipc_permission (struct kern_ipc_perm *ipcp, short flag)
{
	RETURN_ERROR_IF_ANY_ERROR(ipc_permission(ipcp,flag));
}

static int stacker_ipc_getinfo (int id, int cmd)
{
	RETURN_ERROR_IF_ANY_ERROR(ipc_getinfo(id,cmd));
}

static int stacker_msg_msg_alloc_security (struct msg_msg *msg)
{
	RETURN_ERROR_IF_ANY_ERROR(msg_msg_alloc_security(msg));
}

static void stacker_msg_msg_free_security (struct msg_msg *msg)
{
	CALL_ALL(msg_msg_free_security(msg));
}

static int stacker_msg_queue_alloc_security (struct msg_queue *msq)
{
	RETURN_ERROR_IF_ANY_ERROR(msg_queue_alloc_security(msq));
}

static void stacker_msg_queue_free_security (struct msg_queue *msq)
{
	CALL_ALL(msg_queue_free_security(msq));
}

static int stacker_msg_queue_associate (struct msg_queue *msq, int msqid,
				      int msqflg)
{
	RETURN_ERROR_IF_ANY_ERROR(msg_queue_associate(msq,msqid,msqflg));
}

static int stacker_msg_queue_msgctl (struct msg_queue *msq, int msqid, int cmd)
{
	RETURN_ERROR_IF_ANY_ERROR(msg_queue_msgctl(msq,msqid,cmd));
}

static int stacker_msg_queue_msgsnd (struct msg_queue *msq, struct msg_msg *msg,
				   int msqid, int msgflg)
{
	RETURN_ERROR_IF_ANY_ERROR(msg_queue_msgsnd(msq,msg,msqid,msgflg));
}

static int stacker_msg_queue_msgrcv (struct msg_queue *msq, struct msg_msg *msg,
				   struct task_struct *target, long type,
				   int mode)
{
	RETURN_ERROR_IF_ANY_ERROR(msg_queue_msgrcv(msq,msg,target,type,mode));
}

static int stacker_shm_alloc_security (struct shmid_kernel *shp)
{
	RETURN_ERROR_IF_ANY_ERROR(shm_alloc_security(shp));
}

static void stacker_shm_free_security (struct shmid_kernel *shp)
{
	CALL_ALL(shm_free_security(shp));
}

static int stacker_shm_associate (struct shmid_kernel *shp, int shmid, int shmflg)
{
	RETURN_ERROR_IF_ANY_ERROR(shm_associate(shp,shmid,shmflg));
}

static int stacker_shm_shmctl (struct shmid_kernel *shp, int shmid, int cmd)
{
	RETURN_ERROR_IF_ANY_ERROR(shm_shmctl(shp,shmid,cmd));
}

static int stacker_shm_shmat (struct shmid_kernel *shp, int shmid, char *shmaddr,
			    int shmflg)
{
	RETURN_ERROR_IF_ANY_ERROR(shm_shmat(shp,shmid,shmaddr,shmflg));
}

static int stacker_sem_alloc_security (struct sem_array *sma)
{
	RETURN_ERROR_IF_ANY_ERROR(sem_alloc_security(sma));
}

static void stacker_sem_free_security (struct sem_array *sma)
{
	CALL_ALL(sem_free_security(sma));
}

static int stacker_sem_associate (struct sem_array *sma, int semid, int semflg)
{
	RETURN_ERROR_IF_ANY_ERROR(sem_associate(sma,semid,semflg));
}

static int stacker_sem_semctl (struct sem_array *sma, int semid, int cmd)
{
	RETURN_ERROR_IF_ANY_ERROR(sem_semctl(sma,semid,cmd));
}

static int stacker_sem_semop (struct sem_array *sma, int semid,
			    struct sembuf *sops, unsigned nsops, int alter)
{
	RETURN_ERROR_IF_ANY_ERROR(sem_semop(sma,semid,sops,nsops,alter));
}

static int stacker_skb_alloc_security (struct sk_buff *skb)
{
	RETURN_ERROR_IF_ANY_ERROR(skb_alloc_security(skb));
}

static int stacker_skb_clone (struct sk_buff *newskb,
			     const struct sk_buff *oldskb)
{
	RETURN_ERROR_IF_ANY_ERROR(skb_clone(newskb,oldskb));
}

static void stacker_skb_copy (struct sk_buff *newskb,
			    const struct sk_buff *oldskb)
{
	CALL_ALL(skb_copy(newskb,oldskb));

}

static void stacker_skb_set_owner_w (struct sk_buff *skb, struct sock *sk)
{
	CALL_ALL(skb_set_owner_w(skb,sk));

}

static void stacker_skb_recv_datagram (struct sk_buff *skb, struct sock *sk,
				     unsigned flags)
{
	CALL_ALL(skb_recv_datagram(skb,sk,flags));
}

static void stacker_skb_free_security (struct sk_buff *skb)
{
	CALL_ALL(skb_free_security(skb));
}


static int stacker_register (const char *name, struct security_operations *ops)
{
	/* This function is the primary reason for the stacker module.
	   Add the stacked module (as specified by name and ops)
	   according to the current ordering policy. */

	char *new_module_name;
	struct module_entry *new_module_entry;
	struct module_entry *temp_old;
	struct module_entry *p; /* Used to walk stacked_modules */

	LOCK_STACKER_FOR_WRITING;
	if (forbid_stacker_register) {
		UNLOCK_STACKER_FOR_WRITING;
		return -EINVAL;
	}
	/* TODO: What should I check on re: security?  Should I check
	   for euid == 0? Has that already been checked? */
	/* Note that we do NOT call the stacker_register entries of
	   any currently installed modules, since we aren't installing
	   a stacked module under them.  */

	/* Allocate memory */
	/* TODO: is GFP_KERNEL appropriate here? */
	/* TODO: need strnlen */
	new_module_name = kmalloc(strnlen(name, MAX_MODULE_NAME_LEN)+1, GFP_KERNEL);
	new_module_entry = kmalloc(sizeof(struct module_entry), GFP_KERNEL);
	if (!new_module_name || !!new_module_entry) {
		UNLOCK_STACKER_FOR_WRITING;
		printk (KERN_INFO
			"Failure registering module - out of memory\n");
		return -EINVAL;
	}

	/* Copy the data into the allocated memory. */
	strncpy(new_module_name, name, MAX_MODULE_NAME_LEN);
	new_module_name[MAX_MODULE_NAME_LEN-1] = '\0';
	*(new_module_entry->module_operations) = *ops;
	new_module_entry->module_name = new_module_name;
	new_module_entry->next = NULL;

	add_module_entry(new_module_entry);

	/* One more write barrier; this one is to _ensure_ that the
	 * inactive list is valid before releasing the locking. */
	wmb();
	UNLOCK_STACKER_FOR_WRITING;
	return 0;
}

static int stacker_unregister (const char *name, struct security_operations *ops)
{

/* This simply "unregisters" a module, so that it's no
 * longer in the queue of modules to call for security issues.
 *
 */

	struct module_entry *m;
	struct module_entry *m_prev = NULL;


	LOCK_STACKER_FOR_WRITING;

	/* Search for the module to unregister, and unregister it. */
	for (m = inactive_stacked_modules; m; m_prev = m, m = m->next) {
		if (!strcmp(name, m->module_name) &&
		    (*(m->ops) == *ops)) {
			/* We found it! Delete it. */
			if (m_prev)
			       	m_prev->next = m->next;
			else
			       	stacked_modules = m->next;
			wmb();
#ifdef CONSERVATIVE_STACKER_LOCKING
			kfree(m->module_name);
			kfree(m);
#else
			/* We'll intentionally leak memory if not conservative*/
#endif
			goto exit_unreg_successfully;
		}
	}

#ifdef CONSERVATIVE_STACKER_LOCKING
	/* If conservative, we can remove items from the list directly,
	 * confident that no other thread can be partway through it. So, we'll
	 * look directly at the stacked list for removal candidates. */
	for (m = stacked_modules; m; m_prev = m, m = m->next) {
		if (!strcmp(name, m->module_name) &&
		    (*(m->ops) == *ops)) {
			/* We found it! Delete it. */
			if (m_prev)
			       	m_prev->next = m->next;
			else
			       	stacked_modules = m->next;
			wmb();
			/* NO ONE ELSE can be calling through stacker,
			 * which means no one can get to the module's
			 * hooks.  Thus, we can safely free it. */
			kfree(m->module_name);
			kfree(m);
			goto exit_unreg_successfully;
		}
	}
#endif

	UNLOCK_STACKER_FOR_WRITING;
	return -EINVAL;

exit_unreg_successfully:
	UNLOCK_STACKER_FOR_WRITING;
	return 0; /* We did it! */
}


struct security_operations stacker_ops = {
	.sethostname =			stacker_sethostname,
	.setdomainname =		stacker_setdomainname,
	.reboot =			stacker_reboot,
	.ioperm =			stacker_ioperm,
	.iopl =				stacker_iopl,
	.ptrace =			stacker_ptrace,
	.capget =			stacker_capget,
	.capset_check =			stacker_capset_check,
	.capset_set =			stacker_capset_set,
	.acct =				stacker_acct,
	.capable =			stacker_capable,
	.sysctl =			stacker_sysctl,
	.sys_security =			stacker_sys_security,
	.swapon =			stacker_swapon,
	.swapoff =			stacker_swapoff,
	.quotactl =			stacker_quotactl,
	.quota_on =			stacker_quota_on,
	.syslog =			stacker_syslog,

	.netlink_send =			stacker_netlink_send,
	.netlink_recv =			stacker_netlink_recv,

	.unix_stream_connect =		stacker_socket_unix_stream_connect,
	.unix_may_send =		stacker_socket_unix_may_send,

	.bprm_alloc_security =		stacker_bprm_alloc_security,
	.bprm_free_security =		stacker_bprm_free_security,
	.bprm_compute_creds =		stacker_bprm_compute_creds,
	.bprm_set_security =		stacker_bprm_set_security,
	.bprm_check_security =		stacker_bprm_check_security,

	.sb_alloc_security =		stacker_sb_alloc_security,
	.sb_free_security =		stacker_sb_free_security,
	.sb_statfs =			stacker_sb_statfs,
	.sb_mount =			stacker_mount,
	.sb_check_sb =			stacker_check_sb,
	.sb_umount =			stacker_umount,
	.sb_umount_close =		stacker_umount_close,
	.sb_umount_busy =		stacker_umount_busy,
	.sb_post_remount =		stacker_post_remount,
	.sb_post_mountroot =		stacker_post_mountroot,
	.sb_post_addmount =		stacker_post_addmount,
	.sb_pivotroot =			stacker_pivotroot,
	.sb_post_pivotroot =		stacker_post_pivotroot,

	.inode_alloc_security =		stacker_inode_alloc_security,
	.inode_free_security =		stacker_inode_free_security,
	.inode_create =			stacker_inode_create,
	.inode_post_create =		stacker_inode_post_create,
	.inode_link =			stacker_inode_link,
	.inode_post_link =		stacker_inode_post_link,
	.inode_unlink =			stacker_inode_unlink,
	.inode_symlink =		stacker_inode_symlink,
	.inode_post_symlink =		stacker_inode_post_symlink,
	.inode_mkdir =			stacker_inode_mkdir,
	.inode_post_mkdir =		stacker_inode_post_mkdir,
	.inode_rmdir =			stacker_inode_rmdir,
	.inode_mknod =			stacker_inode_mknod,
	.inode_post_mknod =		stacker_inode_post_mknod,
	.inode_rename =			stacker_inode_rename,
	.inode_post_rename =		stacker_inode_post_rename,
	.inode_readlink =		stacker_inode_readlink,
	.inode_follow_link =		stacker_inode_follow_link,
	.inode_permission =		stacker_inode_permission,
	.inode_permission_lite =	stacker_inode_permission_lite,
	.inode_setattr =		stacker_inode_setattr,
	.inode_getattr =		stacker_inode_getattr,
	.inode_post_lookup =		stacker_post_lookup,
	.inode_delete =			stacker_delete,
	.inode_setxattr =		stacker_inode_setxattr,
	.inode_getxattr =		stacker_inode_getxattr,
	.inode_listxattr =		stacker_inode_listxattr,
	.inode_removexattr =		stacker_inode_removexattr,

	.file_permission =		stacker_file_permission,
	.file_alloc_security =		stacker_file_alloc_security,
	.file_free_security =		stacker_file_free_security,
	.file_llseek =			stacker_file_llseek,
	.file_ioctl =			stacker_file_ioctl,
	.file_mmap =			stacker_file_mmap,
	.file_mprotect =		stacker_file_mprotect,
	.file_lock =			stacker_file_lock,
	.file_fcntl =			stacker_file_fcntl,
	.file_set_fowner =		stacker_file_set_fowner,
	.file_send_sigiotask =		stacker_file_send_sigiotask,
	.file_receive =			stacker_file_receive,

	.task_create =			stacker_task_create,
	.task_alloc_security =		stacker_task_alloc_security,
	.task_free_security =		stacker_task_free_security,
	.task_setuid =			stacker_task_setuid,
	.task_post_setuid =		stacker_task_post_setuid,
	.task_setgid =			stacker_task_setgid,
	.task_setpgid =			stacker_task_setpgid,
	.task_getpgid =			stacker_task_getpgid,
	.task_getsid =			stacker_task_getsid,
	.task_setgroups =		stacker_task_setgroups,
	.task_setnice =			stacker_task_setnice,
	.task_setrlimit =		stacker_task_setrlimit,
	.task_setscheduler =		stacker_task_setscheduler,
	.task_getscheduler =		stacker_task_getscheduler,
	.task_wait =			stacker_task_wait,
	.task_kill =			stacker_task_kill,
	.task_prctl =			stacker_task_prctl,
	.task_kmod_set_label =		stacker_task_kmod_set_label,
	.task_reparent_to_init =	stacker_task_reparent_to_init,

	.socket_create =		stacker_socket_create,
	.socket_post_create =		stacker_socket_post_create,
	.socket_bind =			stacker_socket_bind,
	.socket_connect =		stacker_socket_connect,
	.socket_listen =		stacker_socket_listen,
	.socket_accept =		stacker_socket_accept,
	.socket_post_accept =		stacker_socket_post_accept,
	.socket_sendmsg =		stacker_socket_sendmsg,
	.socket_recvmsg =		stacker_socket_recvmsg,
	.socket_getsockname =		stacker_socket_getsockname,
	.socket_getpeername =		stacker_socket_getpeername,
	.socket_getsockopt =		stacker_socket_getsockopt,
	.socket_setsockopt =		stacker_socket_setsockopt,
	.socket_shutdown =		stacker_socket_shutdown,
	.socket_sock_rcv_skb =		stacker_socket_sock_rcv_skb,

	.skb_alloc_security =		stacker_skb_alloc_security,
	.skb_clone =			stacker_skb_clone,
	.skb_copy =			stacker_skb_copy,
	.skb_set_owner_w =		stacker_skb_set_owner_w,
	.skb_recv_datagram =		stacker_skb_recv_datagram,
	.skb_free_security =		stacker_skb_free_security,

	.ip_fragment =			stacker_ip_fragment,
	.ip_defragment =		stacker_ip_defragment,
	.ip_encapsulate =		stacker_ip_encapsulate,
	.ip_decapsulate =		stacker_ip_decapsulate,
	.ip_decode_options =		stacker_ip_decode_options,

	.ipc_permission =		stacker_ipc_permission,
	.ipc_getinfo =			stacker_ipc_getinfo,

	.netdev_unregister =		stacker_netdev_unregister,

	.module_create =		stacker_module_create,
	.module_initialize =		stacker_module_initialize,
	.module_delete =		stacker_module_delete,

	.msg_msg_alloc_security =	stacker_msg_msg_alloc_security,
	.msg_msg_free_security =	stacker_msg_msg_free_security,

	.msg_queue_alloc_security =	stacker_msg_queue_alloc_security,
	.msg_queue_free_security =	stacker_msg_queue_free_security,
	.msg_queue_associate =		stacker_msg_queue_associate,
	.msg_queue_msgctl =		stacker_msg_queue_msgctl,
	.msg_queue_msgsnd =		stacker_msg_queue_msgsnd,
	.msg_queue_msgrcv =		stacker_msg_queue_msgrcv,

	.shm_alloc_security =		stacker_shm_alloc_security,
	.shm_free_security =		stacker_shm_free_security,
	.shm_associate =		stacker_shm_associate,
	.shm_shmctl =			stacker_shm_shmctl,
	.shm_shmat =			stacker_shm_shmat,

	.sem_alloc_security =		stacker_sem_alloc_security,
	.sem_free_security =		stacker_sem_free_security,
	.sem_associate =		stacker_sem_associate,
	.sem_semctl =			stacker_sem_semctl,
	.sem_semop =			stacker_sem_semop,

	.register_security =		stacker_register,
	.unregister_security =		stacker_unregister,
};


#if defined(CONFIG_SECURITY_stacker_MODULE)
# define MYNAME THIS_MODULE->name
#else
# define MYNAME "stacker"
#endif


static int __init stacker_init (void)
{
	/* Attempt to register ourselves with the security framework.
	 * Note that the stacker module allows itself to be stacked!
	 * Currently stacker assumes it's only loaded once and thus
	 * doesn't support stacking ITSELF, but it _is_ designed
	 * so it can be stacked under another (different) module.
	 * Of course, anybody who needs multiple levels of stacking
	 * has a security policy I wouldn't want to analyze...! */

	/* By default, start up with the capability as the one & only module */
	stacked_modules = &capability_entry;
	INIT_STACKER_LOCKING;

	if (register_security (&stacker_ops)) {
		printk (KERN_INFO 
			"Failure registering stacker module with the kernel\n");
		/* If we're a secondary, do NOT do anything by default.
		 * This allows the "stacker" module ITSELF to be stacked
		 * under some other primary module, and still be a
		 * "good citizen" by not overriding anything. */
		secondary = 1;
		stacked_modules = NULL;
		/* try registering with primary module. */
		if (mod_reg_security (MY_NAME, &stacker_ops)) {
			printk (KERN_INFO "Failure registering stacker module "
				"with primary security module.\n");
			return -EINVAL;
		}
	}
	printk(KERN_INFO "Stacker LSM initialized\n");
	return 0;
}

static void __exit stacker_exit (void)
{
	/* remove ourselves from the security framework */
	if (secondary) {
		if (mod_unreg_security (MY_NAME, &stacker_ops))
			printk (KERN_INFO "Failure unregistering stacker module "
				"with primary module.\n");
		return;
	}
 
	if (unregister_security (&stacker_ops)) {
		printk (KERN_INFO
			"Failure unregistering stacker module with the kernel\n");
	}
}


module_init (stacker_init);
module_exit (stacker_exit);

MODULE_DESCRIPTION("LSM Stacker - supports multiple simultaneous LSM modules");
MODULE_AUTHOR("David A. Wheeler");
MODULE_LICENSE("GPL");


