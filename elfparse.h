void *elfparse_createhandle(const char *procpath);
bool elfparse_needs_reloc(void *handle);
char *elfparse_getfuncaddr(void *handle, const char *funcname);
void elfparse_destroyhandle(void *handle);
