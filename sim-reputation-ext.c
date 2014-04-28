/*
 * sim-reputation-ext.c
 *
 *  Created on: 05/02/2014
 *      Author: aruiz
 */

/**
 * TODO
 * - Expresion regular compatible con dominios internacionales idn.
 */

/**
 * - Las urls del fichero de reputacion deben de estar debidamente codificadas, al menos el caracter almohadilla # por su equivalante %23 tal que:
 * 			http://unaurl.com/path/1/2/url/?var=1#2#3&var=2&var3=23! -> http%3A%2f%2funaurl.com%2fpath%2f1%2f2%2furl%2f%3Fvar%3D1%232%233%26var%3D2%26var3%3D23%21
 * - El campo userdata7 del evento es usado para indicar, en caso de "matcheo" de que tipo ha sido (url, domain o ip)
 * - El campo userdata8 del evento es usado para los dominios
 * - El campo userdata9 del evento es usado para las urls
 */

#include "sim-reputation-ext.h"
#ifdef DEBUG
#include <time.h>
#endif

/**
 * url 			((?:http|ftp)s?://.*)
 * dominio	([a-zA-Z0-9]([a-zA-Z0-9\\-]{0,61}[a-zA-Z0-9])?\\.)+[a-zA-Z]{2,}
 */
#define REP_FILE_ENTRY_URLS			"^((?:http|ftp)s?://.*)#(\\d{1,2})#(\\d{1,2})#([^;]+)(;([^;]+))*#(.*)#(.*)#(.*)#([\\d]+)(;([\\d]+))*$"
#define REP_FILE_ENTRY_DOMAINS	"^([a-zA-Z0-9]([a-zA-Z0-9\\-]{0,61}[a-zA-Z0-9])?\\.)+[a-zA-Z]{2,}#(\\d{1,2})#(\\d{1,2})#([^;]+)(;([^;]+))*#(.*)#(.*)#(.*)#([\\d]+)(;([\\d]+))*$"

#define URL_REPUTATION					"URL_REPUTATION"
#define DOMAIN_REPUTATION			"DOMAIN_REPUTATION"
#define IP_REPUTATION						"IP_REPUTATION"
#define DELIM									"#"

typedef struct _reputation_data_url_domains{
	gchar data[256];
	gchar reliability[2];
	gchar priority[2];
	gchar activities[256];
	gchar act_ids[32];
} reputation_data_url_domains;

static reputation_data_url_domains *reputation_data_url = NULL;
static reputation_data_url_domains *reputation_data_domain = NULL;

static unsigned int reputation_data_url_total = 0;
static unsigned int reputation_data_domain_total = 0;

static short REPUTATION_FILE_UPDATING = 0;

static GRegex *regex_url = NULL;
static GRegex *regex_domain = NULL;

static int EXEC = 0;

static void sim_reputation_init_ext(SimReputation *reputation){

#ifdef DEBUG
	printf("Inicializando sim_repututation ext\n");
#endif

	//Definimos expresiones regulares para urls y dominios
	regex_url = g_regex_new(REP_FILE_ENTRY_URLS, 0, 0, NULL);
	regex_domain = g_regex_new(REP_FILE_ENTRY_DOMAINS, 0, 0, NULL);

	//Cargamos urls y dominios del archivo de reputacion por primera vez
	sim_reputation_load_file_ext(reputation);

	/**
	 * La primera vez que entramos en la función establecemos el monitor del archivo de reputación para cargar
	 * las nuevas urls y dominios cada vez que cambie el archivo.
	 */
	//	reputation->_priv->monitor = g_file_monitor_file (reputation->_priv->file, 0, NULL, NULL);
	g_signal_connect (reputation->_priv->monitor, "changed", G_CALLBACK (_sim_reputation_change_data_ext), reputation);

	EXEC = 1;
}

SimReputationData *sim_reputation_match_event_ext(SimReputation *reputation, SimEvent *event){

	SimReputationData *data_dst = NULL;
	gchar *url = NULL;
	gchar *domain = NULL;

	/**
	 * La primera vez que entramos, inicializamos variables.
	 */
	if(EXEC != 1){
		sim_reputation_init_ext(reputation);
	}

	url = event->userdata9;
	domain = event->userdata8;

	/**
	 * URLs
	 */
	if(url != NULL){
#ifdef DEBUG
		printf("URL a comprobar %s\n", url);
#endif
		data_dst = sim_reputation_search_best_url(reputation, url);

		if(data_dst != NULL){
#ifdef DEBUG
			printf("URL_REPUTATION\n");
#endif
			event->userdata7 = g_strdup(URL_REPUTATION);
			return data_dst;
		}
	}

	/**
	 * Dominios
	 */
	if(domain != NULL){
#ifdef DEBUG
		printf("DOMAIN a comprobar %s\n", domain);
#endif
		data_dst = sim_reputation_search_best_domain(reputation, domain);

		if(data_dst != NULL){
#ifdef DEBUG
			printf("DOMAIN_REPUTATION\n");
#endif
			event->userdata7 = g_strdup(DOMAIN_REPUTATION);
			return data_dst;
		}
	}

	/**
	 * IPs
	 */
#ifdef DEBUG
	printf("Comprobando IP %s\n", event->dst_ia->priv->bytes.str);
#endif
	data_dst = sim_reputation_search_best_inet(reputation, event->dst_ia);
	if(data_dst != NULL){
#ifdef DEBUG
		printf("IP_REPUTATION\n");
#endif
		event->userdata7 = g_strdup(IP_REPUTATION);
	}

	return data_dst;
}

 SimReputationData *sim_reputation_search_best_url(SimReputation *reputation, gchar *url){

	SimReputationData *data = NULL;
	int x;

	//En el caso de que el fichero se este actualizando, dormimos 1 segundo.
	while(REPUTATION_FILE_UPDATING == 1) sleep(1);

	for(x=0;x<reputation_data_url_total;x++){
#ifdef DEBUG
		printf("Comparando %s -> %s\n", url, reputation_data_url[x].data);
#endif
		if(strcmp(url, reputation_data_url[x].data) == 0){
#ifdef DEBUG
			printf("**** Match URL\n");
#endif
			data = sim_reputation_data_create(
					reputation_data_url[x].reliability,
					reputation_data_url[x].priority,
					reputation_data_url[x].activities,
					reputation_data_url[x].act_ids,
					reputation->_priv->db_activities);
#ifdef DEBUG
			printf("r: %d\np: %d\ns: %s\n",
					data->reliability,
					data->priority,
					data->str_activities);
#endif
			break;
		}
	}

#ifdef DEBUG
	printf("URLS comprobadas %d\n", x);
#endif

	return data;
}

 SimReputationData *sim_reputation_search_best_domain(SimReputation *reputation, gchar *domain){

	SimReputationData *data = NULL;
	int x;

	//En el caso de que el fichero se este actualizando, dormimos 1 segundo.
	while(REPUTATION_FILE_UPDATING == 1) sleep(1);

	for(x=0;x<reputation_data_domain_total;x++){
#ifdef DEBUG
		printf("Comparando %s -> %s\n", domain, reputation_data_domain[x].data);
#endif
		if(strcmp(domain, reputation_data_domain[x].data) == 0){
#ifdef DEBUG
			printf("**** Match DOMAIN\n");
#endif
			data = sim_reputation_data_create(
					reputation_data_domain[x].reliability,
					reputation_data_domain[x].priority,
					reputation_data_domain[x].activities,
					reputation_data_domain[x].act_ids,
					reputation->_priv->db_activities);
#ifdef DEBUG
			printf("r: %d\np: %d\ns: %s\n",
					data->reliability,
					data->priority,
					data->str_activities);
#endif
			break;
		}
	}

#ifdef DEBUG
	printf("DOMAINS comprobadas %d\n", x);
#endif

	return data;
}

 void sim_reputation_load_file_ext(SimReputation *reputation){

	/**
	 * "g_regex_match" producia fugas de memoria a causa del puntero "match_info"
	 * Se le pasa NULL.
	 */

#ifdef DEBUG
	clock_t tic = clock();
#endif
	gchar *file_path;
	gchar **tokens;
	gchar *buf = NULL;
	gsize len = 0;
	gsize pos = 0;
	GError *err = NULL;
	GIOStatus status = G_IO_STATUS_NORMAL;
	gint  line = 0;

	file_path = g_file_get_path (reputation->_priv->file);
	if (!file_path)
	{
#ifdef DEBUG
		printf ("Error opening reputation data file\n");
#endif
		return;
	}

	GIOChannel *rep_file = g_io_channel_new_file (file_path, "r", NULL);
	if (rep_file == NULL)
	{
#ifdef DEBUG
		printf ("%s: Problems with file \"%s\"\n", __func__, file_path);
#endif
		g_free (file_path);
		return;
	}

	g_free (file_path);

	//Obtenemos el numero total de lineas del archivo de rep. para reservar espacio para las estructuras de datos
	while (status != G_IO_STATUS_ERROR && status != G_IO_STATUS_EOF){
		status = g_io_channel_read_line(rep_file, &buf, &len, &pos, &err);
		g_free(buf);
		line++;
	}
#ifdef DEBUG
	printf("Tamanio lista rep. %lu\n", sizeof(reputation_data_url_domains));
	printf("Lineas totales archivo rep. %d\n", line);
	printf("Tamanio total reserva lista rep. %lu\n", sizeof(reputation_data_url_domains) * line);
#endif

	//Reservamos espacio en las estructuras.
	if(reputation_data_url != NULL) g_free(reputation_data_url);
	reputation_data_url = (reputation_data_url_domains *)calloc(line, sizeof(reputation_data_url_domains));

	if(reputation_data_domain != NULL) g_free(reputation_data_domain);
	reputation_data_domain = (reputation_data_url_domains *)calloc(line, sizeof(reputation_data_url_domains));

	//Reiniciamos contadores
	reputation_data_url_total = 0;
	reputation_data_domain_total = 0;

	line = 0;
	status = G_IO_STATUS_NORMAL;
	g_free(buf);
	len = 0;
	err = NULL;
	g_io_channel_seek_position(rep_file, 0, G_SEEK_SET, NULL);

	while (status != G_IO_STATUS_ERROR && status != G_IO_STATUS_EOF) {
		tokens = NULL;
		status = g_io_channel_read_line(rep_file, &buf, &len, &pos, &err);
		if (buf != NULL) {
			line++;

			//URL decode
			implodeURIComponent(buf);
#ifdef DEBUG
			//			printf("Decode -> %s\n", buf);
#endif

			// Skip comment
			if(g_regex_match (reputation->_priv->rep_file_comment, buf, 0, NULL))
			{
#ifdef DEBUG
				printf ("Skipped comment at line %d\n", line);
#endif
			}

			/**
			 * tokens
			 * [0]	url/domain
			 * [1]	fiabilidad
			 * [2]	prioridad
			 * [3]	act. string
			 * [4]	codigo pais
			 * [5]	pais
			 * [6]	coordenadas
			 * [7]	act. ids
			 */
			//Buscamos urls
			if(g_regex_match (regex_url, buf, 0, NULL))
			{
				tokens = g_strsplit((const gchar *)buf, (const gchar *)DELIM, 100);
				strncpy(reputation_data_url[reputation_data_url_total].activities, tokens[3], sizeof(reputation_data_url->activities));
				strncpy(reputation_data_url[reputation_data_url_total].act_ids, tokens[7], sizeof(reputation_data_url->act_ids));
				strncpy(reputation_data_url[reputation_data_url_total].data, tokens[0], sizeof(reputation_data_url->data));
				strncpy(reputation_data_url[reputation_data_url_total].priority, tokens[2], 1);
				strncpy(reputation_data_url[reputation_data_url_total].reliability, tokens[1], 1);
#ifdef DEBUG
				printf("URL -> %s\n", reputation_data_url[reputation_data_url_total].data);
#endif
				reputation_data_url_total++;
			}
			//Buscamos dominios
			else if(g_regex_match (regex_domain, buf, 0, NULL))
			{
				tokens = g_strsplit((const gchar *)buf, (const gchar *)DELIM, 100);
				strncpy(reputation_data_domain[reputation_data_domain_total].activities, tokens[3], sizeof(reputation_data_domain->activities));
				strncpy(reputation_data_domain[reputation_data_domain_total].act_ids, tokens[7], sizeof(reputation_data_domain->act_ids));
				strncpy(reputation_data_domain[reputation_data_domain_total].data, tokens[0], sizeof(reputation_data_domain->data));
				strncpy(reputation_data_domain[reputation_data_domain_total].priority, tokens[2], 1);
				strncpy(reputation_data_domain[reputation_data_domain_total].reliability, tokens[1], 1);
#ifdef DEBUG
				printf("Domain -> %s\n", reputation_data_domain[reputation_data_domain_total].data);
#endif
				reputation_data_domain_total++;
			}
			else{
#ifdef DEBUG
				//				tokens = g_strsplit((const gchar *)buf, (const gchar *)delim, 100);
				//				printf("Formato no compatible en linea %d: %s\n", line, tokens[0]);
#endif
			}

			if (tokens != NULL) g_strfreev(tokens);

			g_free(buf);
		} //end if
	} //end while

	//Ajustamos y copiamos solo los datos necesarios y liberamos la memoria innecesaria
	if(reputation_data_url != NULL){
		reputation_data_url = (reputation_data_url_domains *)realloc(reputation_data_url, sizeof(reputation_data_url_domains) * reputation_data_url_total);
	}

	if(reputation_data_domain != NULL){
		reputation_data_domain = (reputation_data_url_domains *)realloc(reputation_data_domain, sizeof(reputation_data_url_domains) * reputation_data_domain_total);
	}

#ifdef DEBUG
	printf("%d urls encontradas\n", reputation_data_url_total);
	printf("%d dominios encontrados\n", reputation_data_domain_total);
	printf("%d formatos incompatibles\n", line-(reputation_data_url_total+reputation_data_domain_total));
	printf("%d lineas totales leidas\n", line);
#endif

	printf("%d bytes reservados URLS\n", sizeof(reputation_data_url_domains) * reputation_data_url_total);
	printf("%d bytes reservados DOMAINS\n", sizeof(reputation_data_url_domains) * reputation_data_domain_total);

	g_io_channel_unref(rep_file);

#ifdef DEBUG
	clock_t toc = clock();
	printf("Elapsed: %f seconds\n", (double)(toc - tic) / CLOCKS_PER_SEC);
#endif
}

 void _sim_reputation_change_data_ext (GFileMonitor * monitor,
		GFile * file1,
		GFile * file2,
		GFileMonitorEvent event,
		gpointer data){

	//params sin uso
	(void) monitor;
	(void) file1;
	(void) file2;

	//Si el evento de entrada no es por cambios en el fichero, salimos.
	if(event != G_FILE_MONITOR_EVENT_CHANGES_DONE_HINT)
		return;

	//Indicamos que el archivo de reputacion se esta actualizando
	REPUTATION_FILE_UPDATING = 1;

	SimReputation *reputation = (SimReputation*)data;
#ifdef DEBUG
	printf("Callback _sim_reputation_change_data_ext\n");
#endif
	g_static_rw_lock_writer_unlock (&reputation->_priv->update_lock);
	//Cargamos urls y dominios de nuevo
	sim_reputation_load_file_ext(reputation);
	g_static_rw_lock_writer_unlock (&reputation->_priv->update_lock);

	REPUTATION_FILE_UPDATING = 0;

	return;
}

 int decodeURIComponent (char *sSource, char *sDest) {

	int nLength;

	for (nLength = 0; *sSource; nLength++) {
		if (*sSource == '%' && sSource[1] && sSource[2] && isxdigit(sSource[1]) && isxdigit(sSource[2])) {
			sSource[1] -= sSource[1] < 58 ? 48 : sSource[1] < 71 ? 55 : 87;
			sSource[2] -= sSource[2] < 58 ? 48 : sSource[2] < 71 ? 55 : 87;
			sDest[nLength] = 16 * sSource[1] + sSource[2];
			sSource += 3;
			continue;
		}
		sDest[nLength] = *sSource++;
	}

	sDest[nLength] = '\0';

	return nLength;
}
