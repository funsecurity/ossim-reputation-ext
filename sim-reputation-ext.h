/*
 * sim-reputation-ext.h
 *
 *  Created on: 05/02/2014
 *      Author: aruiz
 */


#include "sim-reputation.h"
//#include "sim-reputation.c"
//#include "sim-debug.h"

#include <glib.h>
#include <glib-object.h>
#include <gio/gio.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <regex.h>
#include <gregex.h>
#include <ctype.h>
#include <unistd.h>

#define DEBUG

SimReputationData 			*sim_reputation_match_event_ext								(SimReputation *, SimEvent *);
static SimReputationData 			*sim_reputation_search_best_url								(SimReputation *, gchar *);
static SimReputationData 			*sim_reputation_search_best_domain							(SimReputation *, gchar *);
static void						sim_reputation_load_file_ext								(SimReputation *);
static void 						sim_reputation_init_ext										(SimReputation *reputation);
static void 				_sim_reputation_change_data_ext 							(GFileMonitor * monitor, GFile *, GFile *, GFileMonitorEvent, gpointer);
static int 						decodeURIComponent 											(char *, char *);

#define implodeURIComponent(url) decodeURIComponent(url, url)

struct _SimReputationPrivate {
	GFile        * file;
	GFileMonitor * monitor;

	SimRadix *ipv4tree;
	SimRadix *ipv6tree;

	GStaticRWLock update_lock;

	GHashTable  *db_activities; // Activities stored in db ordered by name

	GRegex      *rep_file_entry;
	GRegex      *rep_file_comment;
};

typedef union
{
  guint8  addr8[16];
  guint16 addr16[8];
  guint32 addr32[4];
  guint64 addr64[2];
  gchar   str[GNET_INETADDR_MAX_LEN];

} sim_inet_ip;

struct _SimInetPrivate
{
  GInetAddr   *address;
  guint        mask;
  sim_inet_ip  bytes;

  SimNet      *parent_sim_net;

  gchar       *db_str;
  SimRadixKey *radix_key;

  gboolean     is_none;

  gboolean     is_in_homenet;
  gboolean     homenet_checked;
};
