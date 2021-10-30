#ifndef ELF_LOADER_H
#define ELF_LOADER_H

void init_exec_elf(char *argv[]);
void exec_elf(const char *file, const char *interp, int argc, char *argv[]);
void elf_interp(char *buf, size_t sz, const char *file);

#endif /* ELF_LOADER_H */
