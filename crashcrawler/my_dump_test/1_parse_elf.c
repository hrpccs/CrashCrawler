#include <elf.h>
#include <gelf.h>
#include <libelf.h>
#include <stdio.h>
#include <stdlib.h>

unsigned int dump_elf_for_offset(const char *filename) {
  if (elf_version(EV_CURRENT) == EV_NONE) {
    fprintf(stderr, "Failed to initialize libelf\n");
    exit(1);
  }

  FILE *file = fopen(filename, "rb");
  if (file == NULL) {
    fprintf(stderr, "Failed to open ELF file\n");
    exit(1);
  }

  Elf *elf = elf_begin(fileno(file), ELF_C_READ, NULL);
  if (elf == NULL) {
    fprintf(stderr, "Failed to open ELF file\n");
    exit(1);
  }

  Elf_Scn *scn = NULL;
  GElf_Shdr shdr;

#if defined(__x86_64__) || defined(__aarch64__)
  Elf64_Word entry_offset;
#else
  Elf32_Word entry_offset;
#endif
  while ((scn = elf_nextscn(elf, scn)) != NULL) {
    if (gelf_getshdr(scn, &shdr) != &shdr) {
      fprintf(stderr, "Failed to read ELF header\n");
      exit(1);
    }

    if (shdr.sh_type == SHT_PROGBITS && shdr.sh_flags == 6) {
      entry_offset = shdr.sh_offset;
#ifdef DEBUG
      printf("dump_elf_for_offset: %x, %016lx: 0x%016lx\n", shdr.sh_type,
             shdr.sh_offset, shdr.sh_addr);
#endif
      break;
    }
  }
  elf_end(elf);
  return entry_offset;
}

void dump_elf_for_func_symbols(char *filename, int is_dynamic) {
  int symbol_filter = is_dynamic ? SHT_DYNSYM : SHT_SYMTAB;
  if (elf_version(EV_CURRENT) == EV_NONE) {
    fprintf(stderr, "Failed to initialize libelf\n");
    exit(1);
  }

  FILE *file = fopen(filename, "rb");
  if (file == NULL) {
    fprintf(stderr, "Failed to open ELF file\n");
    exit(1);
  }

  Elf *elf = elf_begin(fileno(file), ELF_C_READ, NULL);
  if (elf == NULL) {
    fprintf(stderr, "Failed to open ELF file\n");
    exit(1);
  }

  GElf_Shdr shdr;
  Elf_Scn *scn = NULL;
  Elf_Scn *symtab_scn_array[2] = {NULL};
  int symtab_scn_array_size = 0;
  Elf_Scn *symtab_scn = NULL;

  int cnt = 0;
  while ((scn = elf_nextscn(elf, scn)) != NULL) {
    if (gelf_getshdr(scn, &shdr) != &shdr) {
      fprintf(stderr, "Failed to read ELF header\n");
      exit(1);
    }
    // Critical filter: Look for the dynamic symbol table.
    if (shdr.sh_type == SHT_DYNSYM || shdr.sh_type == SHT_SYMTAB) {
      // printf("%d, Count: %d\n", shdr.sh_type, ++cnt);
      // symtab_scn = scn;
      symtab_scn_array[symtab_scn_array_size++] = scn;
    }
  }

  if (!symtab_scn_array_size) {
    fprintf(stderr, "Symbol table section not found");
    exit(1);
  }
  for (int idx = 0; idx < symtab_scn_array_size; ++idx) {
    symtab_scn = symtab_scn_array[idx];

    if (gelf_getshdr(symtab_scn, &shdr) != &shdr) {
      fprintf(stderr, "Failed to read ELF header\n");
      exit(1);
    }

    // Get & Traverse the symbol table.
    Elf_Data *symtab_data = elf_getdata(symtab_scn, NULL);
    if (!symtab_data) {
      fprintf(stderr, "Failed to read symbol table data");
      exit(1);
    }

    int num_symbols = symtab_data->d_size / sizeof(GElf_Sym);
    GElf_Sym *symbols = (GElf_Sym *)symtab_data->d_buf;

    for (int i = 0; i < num_symbols; i++) {
      GElf_Sym *symbol = &symbols[i];

      // Critical filter for determined functions.
      if (GELF_ST_TYPE(symbol->st_info) == STT_FUNC && symbol->st_value != 0) {
        const char *symbol_name =
            elf_strptr(elf, shdr.sh_link, symbol->st_name);
        printf("0x%016lx %s\n", (unsigned long)symbol->st_value, symbol_name);
      }
    }
  }
  elf_end(elf);
}

int main(int argc, char *argv[]) {
  if (argc < 2) {
    fprintf(stderr, "Usage: %s <filename>\n", argv[0]);
    exit(1);
  }

  // dump_elf_for_offset(argv[1]);
  dump_elf_for_func_symbols(argv[1], 0);
  return 0;
}