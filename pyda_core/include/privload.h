
#include "dr_api.h"
#include "dr_tools.h"
#include "drmgr.h"
app_pc locate_and_load_private_library(const char *name, bool reachable);
app_pc get_private_library_address(void *handle, const char *symbol);

// duplicated from dynamorio
typedef struct _privmod_t {
    app_pc base;
    size_t size;
    const char *name;
    char path[MAXIMUM_PATH];
    uint ref_count;
    bool externally_loaded;
    bool is_client; /* or Extension */
    bool called_proc_entry;
    bool called_proc_exit;
    struct _privmod_t *next;
    struct _privmod_t *prev;
    void *os_privmod_data;
} privmod_t;
privmod_t *privload_lookup_by_pc_takelock(app_pc pc);
void privload_relocate_mod_takelock(privmod_t *mod);

typedef struct _redirect_import_t {
    const char *name;
    app_pc func;
    app_pc app_func; /* Used only for dl_iterate_phdr over app libs, so far. */
} redirect_import_t;

extern redirect_import_t *client_redirect_imports;
extern int client_redirect_imports_count;
