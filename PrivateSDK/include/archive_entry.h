#ifndef ARCHIVE_ENTRY_H_INCLUDED
#define ARCHIVE_ENTRY_H_INCLUDED

#include <sys/types.h>
#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

struct archive_entry;

const char *archive_entry_pathname(struct archive_entry *);
void archive_entry_set_pathname(struct archive_entry *, const char *);
int64_t archive_entry_size(struct archive_entry *);

#ifdef __cplusplus
}
#endif

#endif
