#ifndef ARCHIVE_H_INCLUDED
#define ARCHIVE_H_INCLUDED

#include <sys/types.h>
#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

typedef int64_t la_int64_t;
typedef ssize_t la_ssize_t;

struct archive;
struct archive_entry;

#define ARCHIVE_EOF       1
#define ARCHIVE_OK        0
#define ARCHIVE_RETRY   (-10)
#define ARCHIVE_WARN    (-20)
#define ARCHIVE_FAILED  (-25)
#define ARCHIVE_FATAL   (-30)

#define ARCHIVE_EXTRACT_OWNER           (0x0001)
#define ARCHIVE_EXTRACT_PERM            (0x0002)
#define ARCHIVE_EXTRACT_TIME            (0x0004)
#define ARCHIVE_EXTRACT_NO_OVERWRITE    (0x0008)
#define ARCHIVE_EXTRACT_UNLINK          (0x0010)
#define ARCHIVE_EXTRACT_ACL             (0x0020)
#define ARCHIVE_EXTRACT_FFLAGS          (0x0040)
#define ARCHIVE_EXTRACT_XATTR           (0x0080)
#define ARCHIVE_EXTRACT_SECURE_SYMLINKS (0x0100)
#define ARCHIVE_EXTRACT_SECURE_NODOTDOT (0x0200)

struct archive *archive_read_new(void);
int archive_read_support_format_all(struct archive *);
int archive_read_support_format_zip(struct archive *);
int archive_read_support_filter_all(struct archive *);
int archive_read_open_filename(struct archive *, const char *_filename, size_t _block_size);
int archive_read_next_header(struct archive *, struct archive_entry **);
la_ssize_t archive_read_data(struct archive *, void *, size_t);
int archive_read_data_block(struct archive *a, const void **buff, size_t *size, la_int64_t *offset);
int archive_read_data_skip(struct archive *);
int archive_read_extract(struct archive *, struct archive_entry *, int flags);
int archive_read_close(struct archive *);
int archive_read_free(struct archive *);

struct archive *archive_write_disk_new(void);
int archive_write_disk_set_options(struct archive *, int flags);
int archive_write_disk_set_standard_lookup(struct archive *);
int archive_write_header(struct archive *, struct archive_entry *);
int archive_write_data_block(struct archive *, const void *, size_t, la_int64_t);
int archive_write_finish_entry(struct archive *);
int archive_write_close(struct archive *);
int archive_write_free(struct archive *);

const char *archive_error_string(struct archive *);

#ifdef __cplusplus
}
#endif

#endif
