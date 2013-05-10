#include <string.h>
#include <stdio.h>
#include <malloc.h> 
#include <mosquitto.h>
#include <mosquitto_plugin.h>
#include <openssl/md5.h>

int md5_server_user_prefix_size = 0;
char *md5_server_user_prefix;
int md5_client_user_prefix_size = 0;
char *md5_client_user_prefix;
int md5_server_hashseed_size = 0;
char *md5_server_hashseed;
int md5_client_hashseed_size = 0;
char *md5_client_hashseed;
int md5_topic_prefix_size = 0;
char *md5_topic_prefix;
int md5_topic_suffix_size = 0;
char *md5_topic_suffix;

int md5_is_client(const char* username) 
{
	if (username == NULL) {
		return 0;
	}
	if (strncmp(username, md5_client_user_prefix, md5_client_user_prefix_size) == 0) {
		return 1;
	} else {
		return 0;
	}
}

int md5_is_server(const char* username) 
{
	if (username == NULL) {
		return 0;
	}
	if (strncmp(username, md5_server_user_prefix, md5_server_user_prefix_size) == 0) {
		return 1;
	} else {
		return 0;
	}
}

int md5_is_valid_client_topic(const char* username, const char* topic)
{
	if (!md5_is_client(username)) {
		return 0;
	}
	int ulen = strlen(username);
	int tsize = md5_topic_prefix_size + ulen - md5_client_user_prefix_size + md5_topic_suffix_size + 1;
	char *topic_p = malloc(tsize);
	memset(topic_p, 0, tsize);
	strcat(topic_p, md5_topic_prefix);
	strcat(topic_p, username + md5_client_user_prefix_size);
	strcat(topic_p, md5_topic_suffix);
#ifdef MQAP_DEBUG
	fprintf(stderr, "md5_is_valid_client_topic: topic=%s, predefined topic=%s\n", topic, topic_p);
#endif
	if (strncmp(topic, topic_p, tsize - 1) == 0) {
		return 1;
	} else {
		return 0;
	}
}

int mosquitto_auth_plugin_version(void)
{
	return MOSQ_AUTH_PLUGIN_VERSION;
}

int mosquitto_auth_plugin_init(void **user_data, struct mosquitto_auth_opt *auth_opts, int auth_opt_count)
{
	int i=0;
	for (; i<auth_opt_count; i++) {
#ifdef MQAP_DEBUG
		fprintf(stderr, "AuthOptions: key=%s, val=%s\n", auth_opts[i].key, auth_opts[i].value);
#endif
		if (!strncmp(auth_opts[i].key, "md5_topic_prefix", 16)) {
			md5_topic_prefix = auth_opts[i].value;
			md5_topic_prefix_size = strlen(auth_opts[i].value);
		} else if (!strncmp(auth_opts[i].key, "md5_topic_suffix", 16)) {
			md5_topic_suffix = auth_opts[i].value;
			md5_topic_suffix_size = strlen(auth_opts[i].value);
		} else if (!strncmp(auth_opts[i].key, "md5_client_user_prefix", 22)) {
			md5_client_user_prefix = auth_opts[i].value;
			md5_client_user_prefix_size = strlen(auth_opts[i].value);
		} else if (!strncmp(auth_opts[i].key, "md5_server_user_prefix", 22)) {
			md5_server_user_prefix = auth_opts[i].value;
			md5_server_user_prefix_size = strlen(auth_opts[i].value);
		} else if (!strncmp(auth_opts[i].key, "md5_server_hashseed", 19)) {
			md5_server_hashseed = auth_opts[i].value;
			md5_server_hashseed_size = strlen(auth_opts[i].value);
		} else if (!strncmp(auth_opts[i].key, "md5_client_hashseed", 19)) {
			md5_client_hashseed = auth_opts[i].value;
			md5_client_hashseed_size = strlen(auth_opts[i].value);
		} else {
		}
	}
	return MOSQ_ERR_SUCCESS;
}

int mosquitto_auth_plugin_cleanup(void **user_data, struct mosquitto_auth_opt *auth_opts, int auth_opt_count)
{
	return MOSQ_ERR_SUCCESS;
}

int mosquitto_auth_security_init(void **user_data, struct mosquitto_auth_opt *auth_opts, int auth_opt_count, bool reload)
{
	return MOSQ_ERR_SUCCESS;
}

int mosquitto_auth_security_cleanup(void **user_data, struct mosquitto_auth_opt *auth_opts, int auth_opt_count, bool reload)
{
	return MOSQ_ERR_SUCCESS;
}

int mosquitto_auth_acl_check(void **user_data, const char *username, const char *topic, int access)
{
	if (md5_is_client(username) && access == MOSQ_ACL_READ && md5_is_valid_client_topic(username, topic)) {
		return MOSQ_ERR_SUCCESS;
	} else if (md5_is_server(username)) {
		return MOSQ_ERR_SUCCESS;
	}
	return MOSQ_ERR_ACL_DENIED;
}

int mosquitto_auth_unpwd_check(void **user_data, const char *username, const char *password)
{
	if (username == NULL || password == NULL) {
		return MOSQ_ERR_AUTH;
	}
#ifdef MQAP_DEBUG
	fprintf(stderr, "mosquitto_auth_unpwd_check: username=%s, password=%s\n", username, password);
#endif
	
	int flag_hash = 0;
	char *hash_seed;

	int ulen = strlen(username);
	int plen = strlen(password);
	int hlen = 0;
	// write access
	if (md5_is_server(username)) {
		flag_hash = 1;
		hash_seed = md5_server_hashseed;
		hlen = md5_server_hashseed_size;
	}	
	// client read access
	if (md5_is_client(username)) {
		flag_hash = 2;
		hash_seed = md5_client_hashseed;
		hlen = md5_client_hashseed_size;
	}
	if (flag_hash && plen == 32) {
#ifdef MQAP_DEBUG
		fprintf(stderr, "mosquitto_auth_unpwd_check: hash_seed=%s, len=%d, plen=%d, flag=%d\n", hash_seed, hlen, plen, flag_hash);
#endif
		unsigned char hash_ret[16];
		// Username + HashSeed
		char *plain = malloc(ulen+hlen+1);
		memset(plain, 0, ulen+hlen+1);
		strcat(plain, username);
		strncat(plain, hash_seed, hlen);

		// DO MD5()
		MD5_CTX ctx;
		MD5_Init(&ctx);
		MD5_Update(&ctx, plain, ulen+hlen);
		MD5_Final(hash_ret, &ctx);
		
		char tmp[3]={'\0'};
		char hash[33]={'\0'};
		int i=0;
		for (; i<16; i++) {
			sprintf(tmp, "%2.2x", hash_ret[i]);
			strcat(hash, tmp);
		}

#ifdef MQAP_DEBUG
		fprintf(stderr, "mosquitto_auth_unpwd_check: plain=%s, hash=%s\n", plain, hash);
#endif
		if (!strncmp(hash, password, 32)) {
			return MOSQ_ERR_SUCCESS;
		}
	}

	return MOSQ_ERR_AUTH;
}

int mosquitto_auth_psk_key_get(void **user_data, const char *hint, const char *identity, char *key, int max_key_len)
{
	return MOSQ_ERR_AUTH;
}


