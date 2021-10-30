#ifndef ELF_LOADER_H
#define ELF_LOADER_H

void elf_init(char *argv[]);
void elf_exec(const char *file, const char *interp, int argc, char *argv[]);
void elf_interp(char *buf, size_t sz, const char *file);

#endif /* ELF_LOADER_H */
