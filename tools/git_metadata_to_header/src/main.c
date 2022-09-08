// SPDX-License-Identifier: EPL-2.0

#include <ctype.h>
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#ifdef _MSC_VER
# pragma warning(disable : 4996)
# define popen  _popen
# define pclose _pclose
#endif

int main(const int argc, const char** argv)
{
    int status = EXIT_FAILURE;

    if (argc != 3) {
        puts("usage: get_metadata_to_header <path-to-created-header.h> <macro-prefix>");
        goto end;
    }

    FILE* out = fopen(argv[1], "w+");
    if (out == NULL) {
        printf("failed to open %s; %s\n", argv[1], strerror(errno));
        goto end;
    }

    FILE* pipe = popen("git describe --always", "r");
    if (pipe == NULL) {
        printf("`git describe --always` failed; %s; is git installed?\n", strerror(errno));
        goto end_close_out;
    }

    char buffer[256];
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

    fprintf(out, "#define %sGIT_DESCRIBE_ALWAYS \"%s\"\n", argv[2], buffer_ptr);
    status = EXIT_SUCCESS;

end_close_out_pipe:
    pclose(pipe);

end_close_out:
    fclose(out);

end:
    exit(status);
}
