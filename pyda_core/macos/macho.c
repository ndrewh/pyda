#include "pyda_core.h"
#include "pyda_util.h"
/* Courtesy of Claude */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <mach-o/loader.h>
#include <mach-o/nlist.h>
#include <mach-o/dyld.h>
#include <mach-o/reloc.h>
#include <fcntl.h>
#include <sys/stat.h>
#include <sys/mman.h>
#include <unistd.h>

#include <mach/mach.h>

#include "privload.h"

// Structure to store section information
struct section_info {
    uint64_t addr;
    uint64_t offset;
    uint64_t size;
    uint32_t reserved1;  // indirect symbol table index
    uint32_t reserved2;  // number of entries
};

void patch_macho(char *path, void *aslr_slide, redirect_import_t *redirects, int num_redirects) {

    int fd = open(path, O_RDONLY);
    if (fd < 0) {
        printf("Failed to open file");
        return;
    }

    struct stat sb;
    if (fstat(fd, &sb) < 0) {
        printf("Failed to get file size");
        close(fd);
        return;
    }

    void *file_data = mmap(NULL, sb.st_size, PROT_READ, MAP_PRIVATE, fd, 0);
    if (file_data == MAP_FAILED) {
        printf("Failed to map file");
        close(fd);
        return;
    }

    struct mach_header_64 *header = (struct mach_header_64 *)file_data;
    
    if (header->magic != MH_MAGIC_64) {
        printf("Not a 64-bit Mach-O file\n");
        munmap(file_data, sb.st_size);
        close(fd);
        return;
    }


    struct load_command *cmd = (struct load_command *)(header + 1);
    struct symtab_command *symtab = NULL;
    struct section_info la_ptr_section = {0};
    struct dysymtab_command *dysymtab = NULL;

    // First pass: find required commands and sections
    for (uint32_t i = 0; i < header->ncmds; i++) {
        if (cmd->cmd == LC_SYMTAB) {
            symtab = (struct symtab_command *)cmd;
        } 
        else if (cmd->cmd == LC_DYSYMTAB) {
            dysymtab = (struct dysymtab_command *)cmd;
        }
        else if (cmd->cmd == LC_SEGMENT_64) {
            struct segment_command_64 *seg = (struct segment_command_64 *)cmd;
            struct section_64 *sect = (struct section_64 *)((char *)seg + sizeof(struct segment_command_64));
            
            // Look for __la_symbol_ptr section
            for (uint32_t j = 0; j < seg->nsects; j++) {
                if (strcmp(sect[j].sectname, "__la_symbol_ptr") == 0 &&
                    strcmp(sect[j].segname, "__DATA") == 0) {
                    la_ptr_section.addr = sect[j].addr;
                    la_ptr_section.offset = sect[j].offset;
                    la_ptr_section.size = sect[j].size;
                    la_ptr_section.reserved1 = sect[j].reserved1;
                    la_ptr_section.reserved2 = sect[j].size / sizeof(void*);
                    break;
                }
            }
        }
        cmd = (struct load_command *)((char *)cmd + cmd->cmdsize);
    }

    if (!symtab || !dysymtab || !la_ptr_section.size) {
        printf("Required tables not found\n");
        munmap(file_data, sb.st_size);
        close(fd);
        return;
    }

    // Get symbol and string tables
    struct nlist_64 *symtab_start = (struct nlist_64 *)((char *)file_data + symtab->symoff);
    char *strtab = (char *)file_data + symtab->stroff;
    uint32_t *indirect_symtab = (uint32_t *)((char *)file_data + dysymtab->indirectsymoff);

    // Print imported symbols with their lazy pointer addresses
    
    // Iterate through the indirect symbol table entries for the lazy pointer section
    for (uint32_t i = 0; i < la_ptr_section.reserved2; i++) {
        uint32_t indirect_idx = indirect_symtab[la_ptr_section.reserved1 + i];
        
        // Skip special indirect symbol table entries
        if (indirect_idx == INDIRECT_SYMBOL_ABS || 
            indirect_idx == INDIRECT_SYMBOL_LOCAL ||
            indirect_idx == INDIRECT_SYMBOL_ABS) {
            continue;
        }

        struct nlist_64 *sym = &symtab_start[indirect_idx];
        const char *sym_name = strtab + sym->n_un.n_strx;
        uint64_t la_ptr_addr = la_ptr_section.addr + (i * sizeof(void*));
        
        for (int j = 0; j < num_redirects; j++) {
            if (strcmp(&sym_name[1], redirects[j].name) == 0) {
                DEBUG_PRINTF("Redirecting %s\n", sym_name);

                void* table_addr = (void*)(la_ptr_addr + aslr_slide);

                byte *base_pc;
                size_t size;
                uint old_prot;

                if (!dr_query_memory(table_addr, &base_pc, &size, &old_prot)) {
                    printf("Failed to query memory\n");
                    goto done;
                }

                if (!dr_memory_protect((void*)table_addr, sizeof(void*), DR_MEMPROT_READ | DR_MEMPROT_WRITE)) {
                    printf("Failed to change protection\n");
                    goto done;
                }

                *(void**)(la_ptr_addr + aslr_slide) = redirects[j].func;

                if (!dr_memory_protect((void*)table_addr, sizeof(void*), old_prot)) {
                    printf("Failed to change protection\n");
                    goto done;
                }
            }
        }
    }
done:
    munmap(file_data, sb.st_size);
    close(fd);
}