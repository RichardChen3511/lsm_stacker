struct sec_module {
	hlist_node hlist;
	char *modname;
	struct security_operations *ops;
}
