#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

typedef struct {
    char extension[160];
    char principal[96];
    char action[96];
    char payload[256];
    uint64_t input_seed;
    int has_input_seed;
} seed_input;

static FILE *trace_file(void) {
    static FILE *file = NULL;
    static int attempted = 0;
    if (!attempted) {
        attempted = 1;
        const char *path = getenv("SEED_AUDIT_TRACE");
        if (path && *path) {
            file = fopen(path, "a");
        }
    }
    return file;
}

static void json_string(FILE *out, const char *value) {
    fputc('"', out);
    for (const unsigned char *cursor = (const unsigned char *)value; *cursor; cursor++) {
        switch (*cursor) {
        case '"': fputs("\\\"", out); break;
        case '\\': fputs("\\\\", out); break;
        case '\b': fputs("\\b", out); break;
        case '\f': fputs("\\f", out); break;
        case '\n': fputs("\\n", out); break;
        case '\r': fputs("\\r", out); break;
        case '\t': fputs("\\t", out); break;
        default:
            if (*cursor < 0x20 || *cursor > 0x7e) {
                fprintf(out, "\\u%04x", (unsigned)*cursor);
            } else {
                fputc(*cursor, out);
            }
        }
    }
    fputc('"', out);
}

static void trace_start(const seed_input *input, uint64_t restored,
                        uint64_t effective, int known) {
    FILE *out = trace_file();
    if (!out) {
        return;
    }
    fprintf(out, "{\"event\":\"start\",\"restored_seed\":\"%llu\",",
            (unsigned long long)restored);
    fprintf(out, "\"input_seed\":\"%llu\",\"effective_seed\":\"%llu\",",
            (unsigned long long)input->input_seed,
            (unsigned long long)effective);
    fputs("\"extension\":", out);
    json_string(out, input->extension);
    fprintf(out, ",\"known_extension\":%s,\"principal\":",
            known ? "true" : "false");
    json_string(out, input->principal);
    fputs(",\"action\":", out);
    json_string(out, input->action);
    fputs("}\n", out);
    fflush(out);
}

static void trace_permission(const seed_input *input, const char *expected,
                             const char *actual, const char *policy,
                             const char *reason) {
    FILE *out = trace_file();
    if (!out) {
        return;
    }
    fputs("{\"event\":\"permission\",\"extension\":", out);
    json_string(out, input->extension);
    fputs(",\"principal\":", out);
    json_string(out, input->principal);
    fputs(",\"action\":", out);
    json_string(out, input->action);
    fputs(",\"expected\":", out);
    json_string(out, expected);
    fputs(",\"actual\":", out);
    json_string(out, actual);
    fputs(",\"policy\":", out);
    json_string(out, policy);
    fputs(",\"reason\":", out);
    json_string(out, reason);
    fputs("}\n", out);
    fflush(out);
}

static void trace_trigger(const seed_input *input, int line, const char *kind) {
    FILE *out = trace_file();
    if (!out) {
        return;
    }
    fputs("{\"event\":\"trigger\",\"extension\":", out);
    json_string(out, input->extension);
    fprintf(out, ",\"file\":\"%s\",\"line\":%d,\"function\":\"evaluate_permission\",\"kind\":",
            __FILE__, line);
    json_string(out, kind);
    fputs("}\n", out);
    fflush(out);
}

static void trace_log(const char *level, const char *message) {
    FILE *out = trace_file();
    if (out) {
        fputs("{\"event\":\"log\",\"source\":\"seed_target\",\"level\":", out);
        json_string(out, level);
        fputs(",\"message\":", out);
        json_string(out, message);
        fputs("}\n", out);
        fflush(out);
    }
    fprintf(stderr, "[seed-audit] level=%s source=seed_target message=%s\n",
            level, message);
    fflush(stderr);
}

static void copy_value(char *destination, size_t capacity,
                       const unsigned char *start, size_t length) {
    if (length >= capacity) {
        length = capacity - 1;
    }
    memcpy(destination, start, length);
    destination[length] = '\0';
}

static int parse_line(seed_input *input, const unsigned char *line, size_t length) {
    while (length > 0 && (line[length - 1] == '\r' || line[length - 1] == '\n')) {
        length--;
    }
    const unsigned char *equals = memchr(line, '=', length);
    if (!equals) {
        return 0;
    }
    size_t key_length = (size_t)(equals - line);
    const unsigned char *value = equals + 1;
    size_t value_length = length - key_length - 1;
    if (key_length == 3 && memcmp(line, "ext", 3) == 0) {
        copy_value(input->extension, sizeof(input->extension), value, value_length);
    } else if (key_length == 9 && memcmp(line, "principal", 9) == 0) {
        copy_value(input->principal, sizeof(input->principal), value, value_length);
    } else if (key_length == 6 && memcmp(line, "action", 6) == 0) {
        copy_value(input->action, sizeof(input->action), value, value_length);
    } else if (key_length == 7 && memcmp(line, "payload", 7) == 0) {
        copy_value(input->payload, sizeof(input->payload), value, value_length);
    } else if (key_length == 4 && memcmp(line, "seed", 4) == 0) {
        char number[32];
        copy_value(number, sizeof(number), value, value_length);
        input->input_seed = strtoull(number, NULL, 10);
        input->has_input_seed = 1;
    }
    return 1;
}

static int parse_input(seed_input *input, const uint8_t *data, size_t size) {
    static const unsigned char magic[] = "SEEDAUDIT1\n";
    memset(input, 0, sizeof(*input));
    strcpy(input->principal, "guest");
    strcpy(input->action, "inspect");
    if (size < sizeof(magic) - 1 || memcmp(data, magic, sizeof(magic) - 1) != 0) {
        return 0;
    }
    size_t offset = sizeof(magic) - 1;
    while (offset < size) {
        size_t end = offset;
        while (end < size && data[end] != '\n') {
            end++;
        }
        parse_line(input, data + offset, end - offset);
        offset = end + 1;
    }
    return 1;
}

static int known_extension(const char *name) {
    return strcmp(name, "telemetry") == 0 || strcmp(name, "snapshot") == 0;
}

static int evaluate_permission(const seed_input *input) {
    if (!known_extension(input->extension)) {
        int trigger_line = __LINE__;
        trace_permission(input, "deny", "deny", "unknown-extension-deny",
                         "unknown extension is denied by default");
        trace_trigger(input, trigger_line, "permission_gate");
        trace_log("warn", "unknown_extension_denied");
        return -1;
    }
    if (strcmp(input->action, "execute") == 0 &&
        strcmp(input->principal, "admin") != 0) {
        int trigger_line = __LINE__;
        trace_permission(input, "deny", "deny", "capability-required",
                         "execute requires admin principal");
        trace_trigger(input, trigger_line, "capability_gate");
        trace_log("warn", "capability_denied");
        return -1;
    }
    trace_permission(input, "allow", "allow", "known-extension-policy",
                     "known extension passed policy");
    trace_log("info", "permission_allowed");
    return 0;
}

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    static int replay_seen = 0;
    if (getenv("SEED_AUDIT_SINGLE_REPLAY")) {
        if (replay_seen) {
            return 0;
        }
        replay_seen = 1;
    }
    seed_input input;
    if (!parse_input(&input, data, size)) {
        trace_log("warn", "invalid_input_magic");
        return 0;
    }
    const char *seed_text = getenv("SEED_AUDIT_RECOVERY_SEED");
    if (!seed_text) {
        seed_text = "0";
    }
    uint64_t restored = strtoull(seed_text, NULL, 10);
    if (!input.has_input_seed) {
        input.input_seed = restored;
    }
    uint64_t effective = input.input_seed ^ restored;
    int known = known_extension(input.extension);
    trace_start(&input, restored, effective, known);
    if (restored == 0) {
        trace_log("warn", "zero_seed_after_recovery");
    }
    evaluate_permission(&input);
    if (strcmp(input.payload, "crash") == 0) {
        trace_log("error", "requested_crash_probe");
        fflush(NULL);
        abort();
    }
    return 0;
}
