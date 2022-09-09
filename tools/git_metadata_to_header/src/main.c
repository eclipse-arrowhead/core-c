// SPDX-License-Identifier: EPL-2.0

#include <ctype.h>
#include <errno.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#if defined(__APPLE__) || defined(__linux__)

# include <sys/stat.h>

# define S_CREATE_DIRS
# define S_PATH_SEP_CH '/'

#elif defined(_WIN32)

# include <direct.h>

# define S_CREATE_DIRS
# define S_PATH_SEP_CH '\\'

# pragma warning(disable : 4996)

# define mkdir(PATH, MODE) _mkdir((PATH))
# define popen  _popen
# define pclose _pclose

#endif

#ifdef S_CREATE_DIRS
static void s_create_parent_dirs(const char* path);
#endif

int main(const int argc, const char** argv)
{
    int status = EXIT_FAILURE;

    if (argc != 3) {
        puts("usage: get_metadata_to_header <path-to-created-header.h> <macro-prefix>");
        goto end;
    }

    const char* path_to_created_header = argv[1];
    const char* macro_prefix = argv[2];

#ifdef S_CREATE_DIRS
    s_create_parent_dirs(path_to_created_header);
#endif

    FILE* out = fopen(path_to_created_header, "w+");
    if (out == NULL) {
        printf("failed to open %s; %s\n", path_to_created_header, strerror(errno));
        goto end;
    }

    FILE* pipe = popen("git describe --always", "r");
    if (pipe == NULL) {
        printf("`git describe --always` failed; %s; is git installed?\n", strerror(errno));
        goto end_close_out;
    }

    char buffer[4096];
    size_t n_bytes_left = sizeof(buffer);
    size_t n_bytes_read = 0;

    for (;;) {
        const size_t n = fread(buffer, 1, n_bytes_left, pipe);
        if (n != 0) {
            n_bytes_left -= n;
            n_bytes_read += n;
            continue;
        }
        if (ferror(pipe)) {
            printf("failed to read `git describe --always` stdout; %s\n", strerror(errno));
            goto end_close_out_pipe;
        }
        break;
    }

    char* buffer_ptr = &buffer[n_bytes_read];
    while (isspace(buffer_ptr[-1])) {
        buffer_ptr = &buffer_ptr[-1];
    }
    *buffer_ptr = '\0';

    buffer_ptr = buffer;
    while (isspace(buffer_ptr[0])) {
        buffer_ptr = &buffer_ptr[1];
    }

    fprintf(out, "#define %sGIT_DESCRIBE_ALWAYS \"%s\"\n", macro_prefix, buffer_ptr);
    status = EXIT_SUCCESS;

end_close_out_pipe:
    pclose(pipe);

end_close_out:
    fclose(out);

end:
    exit(status);
}

#ifdef S_CREATE_DIRS
static void s_create_parent_dirs(const char* path)
{
    char buffer[512u];

    size_t path_length = strlen(path);

    // Remove trailing filename or directory name from path.
    for (;;) {
        if (path_length == 0u) {
            return;
        }
        path_length -= 1u;
        if (path[path_length] == S_PATH_SEP_CH) {
            break;
        }
    }

    if (path_length > (sizeof(buffer) - 1u)) {
        printf("Path length (%zu) exceeds limit (%zu): %s\n", path_length, sizeof(buffer) - 1u, path);
        exit(EXIT_FAILURE);
    }

    memcpy(buffer, path, path_length);
    buffer[path_length] = '\0';

    bool has_created_parents = false;

    for (;;) {
        int res = mkdir(buffer, 0755);
        if (res == 0) {
            return;
        }

        if (!has_created_parents) {
            switch (errno) {
            case ENOENT:
                s_create_parent_dirs(buffer);
                has_created_parents = true;
                continue;

            case EEXIST:
                return;

            default:
                break;
            }
        }

        printf("Failed to create directory; %s; path: %s\n", strerror(errno), buffer);
        exit(EXIT_FAILURE);
    }
}
#endif
