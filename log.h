extern enum verbosity_level
{
	V_ERR = 0,
	V_WARN,
	V_INFO,
	V_DBG
} verbosity;

#define LOG(verb, fmt, ...) do{if(verbosity>=verb){printf(fmt "\n", ##__VA_ARGS__);}}while(0)
#define INFO(fmt, ...) LOG(V_INFO, "[INFO] " fmt, ##__VA_ARGS__)
#define WARN(fmt, ...) LOG(V_WARN, "[WARN] " fmt, ##__VA_ARGS__)
#define ERR(fmt, ...) LOG(V_ERR, "[ERR ] " fmt, ##__VA_ARGS__)

#ifdef DEBUG
#define DBG(fmt, ...) LOG(V_DBG, "[DEBG] " fmt, ##__VA_ARGS__)
#else
#define DBG(fmt, ...)
#endif
