#include <stdint.h>
#include <stddef.h>
#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <ctype.h>

/*
 * Cookie attribute audit target for libFuzzer.
 *
 * The fuzz input is a single raw Set-Cookie header value:
 *   name=value; Attr1; Attr2=val2; ...
 *
 * Two execution modes:
 *   1. Fuzz mode (LLVMFuzzerTestOneInput): parse + audit every input.
 *      No stdout output; libFuzzer + sanitizers own the process.
 *   2. Standalone rerun mode (main): read a saved sample file and print
 *      machine-readable audit lines when CK_AUDIT_DUMP=1.
 */

#define MAX_ATTRS 32
#define MAX_AGE_DIGITS 24

typedef struct {
    const char *key;
    size_t key_len;
    const char *val;
    size_t val_len;
    int has_value;
} Attr;

typedef struct {
    const char *name;
    size_t name_len;
    const char *value;
    size_t value_len;
    int has_pair;
    Attr attrs[MAX_ATTRS];
    size_t attr_count;
} Cookie;

static void trim_ws(const char **p, size_t *n) {
    while (*n > 0 && (*p)[0] == ' ') { (*p)++; (*n)--; }
    while (*n > 0 && (*p)[*n - 1] == ' ') { (*n)--; }
}

static int ci_eq(const char *a, size_t an, const char *b) {
    size_t bn = strlen(b);
    if (an != bn) return 0;
    for (size_t i = 0; i < an; i++) {
        if (tolower((unsigned char)a[i]) != tolower((unsigned char)b[i]))
            return 0;
    }
    return 1;
}

static int ci_has_prefix(const char *s, size_t n, const char *pre) {
    size_t pn = strlen(pre);
    if (n < pn) return 0;
    for (size_t i = 0; i < pn; i++) {
        if (tolower((unsigned char)s[i]) != tolower((unsigned char)pre[i]))
            return 0;
    }
    return 1;
}

static const Attr *find_attr(const Cookie *c, const char *key) {
    for (size_t i = 0; i < c->attr_count; i++) {
        if (ci_eq(c->attrs[i].key, c->attrs[i].key_len, key))
            return &c->attrs[i];
    }
    return NULL;
}

static void parse_cookie(const uint8_t *data, size_t size, Cookie *c) {
    memset(c, 0, sizeof(*c));
    const char *p = (const char *)data;
    size_t n = size;

    size_t first = 0;
    while (first < n && p[first] != ';') first++;

    const char *seg = p;
    size_t seg_len = first;
    trim_ws(&seg, &seg_len);

    size_t eq = 0;
    while (eq < seg_len && seg[eq] != '=') eq++;
    if (eq < seg_len) {
        c->has_pair = 1;
        c->name = seg;
        c->name_len = eq;
        c->value = seg + eq + 1;
        c->value_len = seg_len - eq - 1;
        trim_ws((const char **)&c->name, &c->name_len);
        trim_ws(&c->value, &c->value_len);
    } else {
        c->has_pair = 0;
        c->name = seg;
        c->name_len = seg_len;
        c->value = NULL;
        c->value_len = 0;
    }

    size_t pos = (first < n) ? first + 1 : n;
    while (pos < n && c->attr_count < MAX_ATTRS) {
        size_t end = pos;
        while (end < n && p[end] != ';') end++;
        const char *a = p + pos;
        size_t an = end - pos;
        trim_ws(&a, &an);
        if (an > 0) {
            Attr *at = &c->attrs[c->attr_count];
            size_t aeq = 0;
            while (aeq < an && a[aeq] != '=') aeq++;
            at->key = a;
            at->key_len = aeq;
            trim_ws(&at->key, &at->key_len);
            if (aeq < an) {
                at->has_value = 1;
                at->val = a + aeq + 1;
                at->val_len = an - aeq - 1;
                trim_ws(&at->val, &at->val_len);
            }
            if (at->key_len > 0) c->attr_count++;
        }
        pos = (end < n) ? end + 1 : n;
    }
}

static int parse_ll(const char *s, size_t n, long long *out) {
    if (n == 0 || n > MAX_AGE_DIGITS) return 0;
    size_t i = 0;
    int neg = 0;
    if (s[0] == '+' || s[0] == '-') { neg = (s[0] == '-'); i = 1; }
    if (i == n) return 0;
    long long v = 0;
    for (; i < n; i++) {
        if (s[i] < '0' || s[i] > '9') return 0;
        v = v * 10 + (s[i] - '0');
    }
    *out = neg ? -v : v;
    return 1;
}

static int attr_is_true(const Attr *a) {
    if (!a->has_value) return 1;
    return ci_eq(a->val, a->val_len, "true") ||
           ci_eq(a->val, a->val_len, "1") ||
           ci_eq(a->val, a->val_len, "yes");
}

#define SEV_INFO 0
#define SEV_WARN 1
#define SEV_CRIT 2

typedef struct {
    int count;
    int crit;
    int warn;
    int info;
} AuditResult;

static void emit(AuditResult *r, int sev, const char *code, const char *msg) {
    r->count++;
    if (sev == SEV_CRIT) r->crit++;
    else if (sev == SEV_WARN) r->warn++;
    else r->info++;
    if (getenv("CK_AUDIT_DUMP") != NULL) {
        const char *sname = sev == SEV_CRIT ? "CRIT" :
                            sev == SEV_WARN ? "WARN" : "INFO";
        fprintf(stderr, "CKA|%s|%s|%s\n", sname, code, msg);
    }
}

static void audit_cookie(const Cookie *c, AuditResult *r) {
    memset(r, 0, sizeof(*r));

    if (!c->has_pair || c->name_len == 0)
        emit(r, SEV_WARN, "MALFORMED_NAME", "cookie name=value pair missing or empty");

    const Attr *secure = find_attr(c, "Secure");
    const Attr *httponly = find_attr(c, "HttpOnly");
    const Attr *samesite = find_attr(c, "SameSite");
    const Attr *domain = find_attr(c, "Domain");
    const Attr *path = find_attr(c, "Path");
    const Attr *maxage = find_attr(c, "Max-Age");
    const Attr *expires = find_attr(c, "Expires");

    if (!secure) emit(r, SEV_CRIT, "MISSING_SECURE", "Secure attribute absent");
    if (!httponly) emit(r, SEV_WARN, "MISSING_HTTPONLY", "HttpOnly attribute absent");

    if (!samesite) {
        emit(r, SEV_WARN, "MISSING_SAMESITE", "SameSite attribute absent, defaults to Lax");
    } else if (!samesite->has_value) {
        emit(r, SEV_WARN, "SAMESITE_EMPTY", "SameSite has no value");
    } else if (!(ci_eq(samesite->val, samesite->val_len, "Strict") ||
                 ci_eq(samesite->val, samesite->val_len, "Lax") ||
                 ci_eq(samesite->val, samesite->val_len, "None"))) {
        emit(r, SEV_WARN, "SAMESITE_UNKNOWN", "SameSite value is not Strict/Lax/None");
    } else if (ci_eq(samesite->val, samesite->val_len, "None") && !secure) {
        emit(r, SEV_CRIT, "SAMESITE_NONE_INSECURE",
             "SameSite=None requires Secure on modern browsers");
    }

    if (domain) {
        if (!domain->has_value || domain->val_len == 0) {
            emit(r, SEV_WARN, "DOMAIN_EMPTY", "Domain attribute has no value");
        } else if (domain->val[0] == '.') {
            emit(r, SEV_INFO, "DOMAIN_LEADING_DOT",
                 "leading dot in Domain is obsolete but accepted");
        }
    }
    if (path && (!path->has_value || path->val_len == 0))
        emit(r, SEV_WARN, "PATH_EMPTY", "Path attribute has no value");

    if (maxage) {
        long long ma = 0;
        if (!maxage->has_value || !parse_ll(maxage->val, maxage->val_len, &ma)) {
            emit(r, SEV_WARN, "MAXAGE_BAD", "Max-Age is not a valid integer");
        } else if (ma <= 0) {
            emit(r, SEV_INFO, "MAXAGE_EXPIRE", "non-positive Max-Age deletes the cookie");
        }
    }
    if (!maxage && !expires)
        emit(r, SEV_INFO, "NO_LIFETIME", "session cookie: no Max-Age or Expires");
    if (maxage && expires)
        emit(r, SEV_INFO, "LIFETIME_REDUNDANT", "both Max-Age and Expires present");

    if (c->name_len >= 7 && (ci_has_prefix(c->name, c->name_len, "__Secure-") ||
                             ci_has_prefix(c->name, c->name_len, "__Host-"))) {
        int host = ci_has_prefix(c->name, c->name_len, "__Host-");
        if (!secure)
            emit(r, SEV_CRIT, "PREFIX_NO_SECURE", "__Host-/__Secure- prefix needs Secure");
        if (host && domain)
            emit(r, SEV_CRIT, "HOSTPREFIX_DOMAIN", "__Host- cookies must not set Domain");
        if (host && (!path || !path->has_value ||
                     !(path->val_len == 1 && path->val[0] == '/')))
            emit(r, SEV_CRIT, "HOSTPREFIX_PATH", "__Host- cookies need Path=/");
    }
}

static void run_one(const uint8_t *data, size_t size) {
    Cookie c;
    AuditResult r;
    parse_cookie(data, size, &c);
    audit_cookie(&c, &r);
    if (getenv("CK_AUDIT_DUMP") != NULL)
        fprintf(stderr, "CKA|SUMMARY|%d|%d|%d|%d\n",
                r.count, r.crit, r.warn, r.info);
}

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    if (size == 0) return 0;
    run_one(data, size);
    return 0;
}

#ifndef CK_NO_MAIN
int main(int argc, char **argv) {
    if (argc < 2) {
        fprintf(stderr, "usage: %s <sample-file>\n", argv[0]);
        return 2;
    }
    FILE *f = fopen(argv[1], "rb");
    if (!f) {
        fprintf(stderr, "cannot open %s\n", argv[1]);
        return 2;
    }
    if (fseek(f, 0, SEEK_END) != 0) { fclose(f); return 2; }
    long sz = ftell(f);
    if (sz < 0) { fclose(f); return 2; }
    rewind(f);
    uint8_t *buf = (uint8_t *)malloc((size_t)sz + 1);
    if (!buf) { fclose(f); return 2; }
    size_t rd = fread(buf, 1, (size_t)sz, f);
    fclose(f);
    run_one(buf, rd);
    free(buf);
    return 0;
}
#endif
