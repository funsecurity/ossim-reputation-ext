About ossim-reputation-ext
-----------------------

Extensión desarrollada en C para ossim-server para la detección de URLS y dominios.
Para habilitarla modificar la función "sim_reputation_class_init" situada en el archivo "sim-reputation.c":

```
static void
sim_reputation_class_init (SimReputationClass * class)
{
  GObjectClass *object_class = G_OBJECT_CLASS (class);

  parent_class = g_type_class_peek_parent (class);

  object_class->dispose = sim_reputation_impl_dispose;
  object_class->finalize = sim_reputation_impl_finalize;
  
	/**
	 * PATCH sim-reputation-ext
	 */
	void *lib_handle;
	char *error;

	lib_handle = dlopen("libossim-reputation-ext.so", RTLD_LAZY);
	if(!lib_handle){
		fprintf(stderr, "dlopen -> %s", dlerror());
	}else{
		sim_reputation_match_event_ext = dlsym(lib_handle, "sim_reputation_match_event_ext");
		if((error = dlerror()) != NULL){
			fprintf(stderr, "dlsym -> %s", dlerror());
		}
	}
	/**
	 * END PATCH
	 */
}
```

También modificar la función "sim_reputation_match_event" situada en el archivo "sim-reputation.c":

```
	/**
	 * PATCH sim-reputation-ext
	 */
	//SimReputationData *data_dst = sim_reputation_search_best_inet (reputation, event->dst_ia);
	SimReputationData *data_dst = (*sim_reputation_match_event_ext)(reputation, event);
	/**
	 * END PATCH
	 */
```
 
Igualmente, hace uso del archivo "reputation.data" para cotejar las URLS, dominios e IPS.
Para las urls hacer uso de urlencode.

Credits
-------

* Adrián Ruiz
* w: funsecurity.net
* t: @funsecurity.net
* e: adrian_adrianruiz.net
* GPG ID: 0x586270E8