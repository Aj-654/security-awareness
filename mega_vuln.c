// mega_vuln.c
// Intentionally insecure demo program to trigger many CodeQL rules.

#define _GNU_SOURCE

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <curl/curl.h>
#include <sqlite3.h>
#include <openssl/md5.h>
#include <openssl/sha.h>
#include <libxml/parser.h>
#include <libxml/tree.h>
#include <alloca.h>

/* ===========================================================
 *  Double free / use-after-free / return stack address
 * =========================================================== */

void double_free_example(void) {
    char *p = (char *)malloc(16);
    if (!p) return;
    strcpy(p, "test");
    free(p);
    /* ❌ Double free (DoubleFree.ql) */
    free(p);
}

char *return_stack_address_example(void) {
    char buf[32];
    strcpy(buf, "secret");
    /* ❌ Returning pointer to stack (ReturnStackAllocatedMemory.ql / UsingExpiredStackAddress.ql) */
    return buf;
}

void use_after_free_example(void) {
    char *p = (char *)malloc(32);
    if (!p) return;
    strcpy(p, "hello");
    free(p);
    /* ❌ Use-after-free (UseAfterFree.ql) */
    printf("UAF: %s\n", p);
}

/* ===========================================================
 *  Incorrect scanf check
 * =========================================================== */

void incorrect_scanf_example(void) {
    int x;
    /* ❌ Incorrect check: ignores EOF properly (IncorrectCheckScanf.ql) */
    if (scanf("%d", &x) == 0) {
        printf("Input error (but this check is wrong)\n");
    }
}

/* ===========================================================
 *  Static buffer overflow / badly bounded write / strncat misuse
 * =========================================================== */

void overflow_static_example(const char *s) {
    char buf[20];

    /* ❌ No space for terminator and too large size (NoSpaceForZeroTerminator.ql / OverflowStatic.ql) */
    strncpy(buf, s, 20);
    buf[19] = '\0';

    printf("Buf: %s\n", buf);
}

void badly_bounded_write_example(const char *s) {
    char buf[16];
    size_t len = strlen(s);

    /* ❌ Badly bounded write (BadlyBoundedWrite.ql / VeryLikelyOverrunWrite.ql) */
    memcpy(buf, s, len);  // no check if len > sizeof(buf)
    buf[15] = '\0';
    printf("Bad write: %s\n", buf);
}

void suspicious_strncat_example(const char *s) {
    char buf[8];
    buf[0] = '\0';
    /* ❌ Suspicious strncat (SuspiciousCallToStrncat.ql) */
    strncat(buf, s, 16);  // length > remaining space
    printf("strncat result: %s\n", buf);
}

/* ===========================================================
 *  Dangerous functions / format string / snprintf overflow
 * =========================================================== */

void dangerous_function_example(void) {
    char buf[16];

    /* ❌ gets is inherently unsafe (DangerousFunctionOverflow.ql) */
    gets(buf);  // NOLINT
    printf("You typed: %s\n", buf);
}

void uncontrolled_format_string_example(const char *user) {
    /* ❌ Uncontrolled format string (UncontrolledFormatString.ql) */
    printf(user);
    printf("\n");
}

void snprintf_overflow_example(const char *user) {
    char buf[8];
    /* ❌ Misuse of snprintf return value (SnprintfOverflow.ql) */
    int needed = snprintf(buf, sizeof(buf), "%s", user);
    if (needed > 0) {
        /* assume it fit, but it might not have */
        printf("snprintf buf: %s\n", buf);
    }
}

/* ===========================================================
 *  Arithmetic issues
 * =========================================================== */

void arithmetic_uncontrolled_example(size_t user_size) {
    /* ❌ Uncontrolled arithmetic (ArithmeticUncontrolled.ql) */
    size_t total = user_size * 1024;  // may overflow
    char *p = (char *)malloc(total);
    if (!p) return;
    memset(p, 0, total);
    free(p);
}

void unsigned_difference_example(size_t a, size_t b) {
    /* ❌ Unsigned difference compared to zero (UnsignedDifferenceExpressionComparedZero.ql) */
    size_t diff = a - b;
    if ((long)diff < 0) {
        printf("This branch is never taken, but code thinks it might be\n");
    }
}

/* ===========================================================
 *  alloca in loop / pointer overflow
 * =========================================================== */

void alloca_in_loop_example(int n) {
    for (int i = 0; i < n; ++i) {
        /* ❌ alloca in loop (AllocaInLoop.ql) */
        char *buf = (char *)alloca(1024);
        memset(buf, 0, 1024);
    }
}

void pointer_overflow_example(char *base, size_t size, size_t offset) {
    /* ❌ Pointer overflow check (PointerOverflow.ql) */
    char *end = base + size;
    if (base + offset < base) {
        printf("Overflowed pointer!\n");
    }
    if (base + offset > end) {
        printf("Out of range\n");
    }
}

/* ===========================================================
 *  Exec tainted (command injection)
 * =========================================================== */

void exec_tainted_example(const char *user_input) {
    char cmd[256];
    /* ❌ Command injection (ExecTainted.ql) */
    snprintf(cmd, sizeof(cmd), "ls %s", user_input);
    system(cmd);
}

/* ===========================================================
 *  CGI XSS
 * =========================================================== */

void cgi_xss_example(void) {
    const char *qs = getenv("QUERY_STRING");
    if (!qs) return;

    /* ❌ Reflected XSS in CGI (CgiXss.ql) */
    printf("Content-Type: text/html\r\n\r\n");
    printf("<html><body>You searched for: %s</body></html>\n", qs);
}

/* ===========================================================
 *  SQL injection (sqlite3)
 * =========================================================== */

static int sql_callback(void *data, int argc, char **argv, char **colName) {
    (void)data;
    for (int i = 0; i < argc; ++i) {
        printf("%s = %s\n", colName[i], argv[i] ? argv[i] : "NULL");
    }
    return 0;
}

void sql_injection_example(sqlite3 *db, const char *userName) {
    char query[512];

    /* ❌ SQL injection (SqlTainted.ql) */
    sprintf(query, "SELECT id, name FROM users WHERE name = '%s';", userName);

    char *errMsg = NULL;
    sqlite3_exec(db, query, sql_callback, NULL, &errMsg);
    if (errMsg) {
        fprintf(stderr, "SQL error: %s\n", errMsg);
        sqlite3_free(errMsg);
    }
}

/* ===========================================================
 *  Cleartext file write / open missing mode / TOCTOU
 * =========================================================== */

void cleartext_file_write_example(const char *secret) {
    /* ❌ Cleartext storage of sensitive info (CleartextFileWrite.ql) */
    FILE *f = fopen("secrets.txt", "w");
    if (!f) return;
    fprintf(f, "password=%s\n", secret);
    fclose(f);
}

void open_missing_mode_example(const char *path) {
    /* ❌ open with O_CREAT but no mode (OpenCallMissingModeArgument.ql) */
    int fd = open(path, O_CREAT | O_WRONLY);
    if (fd >= 0) {
        write(fd, "test", 4);
        close(fd);
    }
}

void toctou_example(const char *path) {
    /* ❌ TOCTOU filesystem race (TOCTOUFilesystemRace.ql) */
    if (access(path, W_OK) == 0) {
        int fd = open(path, O_WRONLY);
        if (fd >= 0) {
            write(fd, "race", 4);
            close(fd);
        }
    }
}

/* ===========================================================
 *  Cleartext transmission / HTTP instead of HTTPS (libcurl)
 * =========================================================== */

void cleartext_transmission_example(const char *secret) {
    CURL *curl = curl_easy_init();
    if (!curl) return;

    char url[512];
    /* ❌ Cleartext transmission of credentials + HTTP (CleartextTransmission.ql / UseOfHttp.ql) */
    snprintf(url, sizeof(url),
             "http://example.com/login?user=aj&password=%s",
             secret);

    curl_easy_setopt(curl, CURLOPT_URL, url);
    curl_easy_perform(curl);
    curl_easy_cleanup(curl);
}

/* ===========================================================
 *  Weak cryptography (MD5 / SHA1)
 * =========================================================== */

void weak_crypto_example(const char *data) {
    unsigned char md5_digest[MD5_DIGEST_LENGTH];
    unsigned char sha1_digest[SHA_DIGEST_LENGTH];

    /* ❌ Broken/weak crypto (BrokenCryptoAlgorithm.ql) */
    MD5((const unsigned char *)data, strlen(data), md5_digest);
    SHA1((const unsigned char *)data, strlen(data), sha1_digest);

    printf("MD5 and SHA1 used on data: %s\n", data);
}

/* ===========================================================
 *  Exposed system data
 * =========================================================== */

void exposed_system_data_example(void) {
    const char *secret_env = getenv("SECRET_KEY");
    if (secret_env) {
        /* ❌ Exposing system data (ExposedSystemData.ql) */
        printf("DEBUG: SECRET_KEY=%s\n", secret_env);
    }
}

/* ===========================================================
 *  XXE (XML External Entity expansion, libxml2)
 * =========================================================== */

void xxe_example(void) {
    /* Attacker-controlled XML with external entity */
    const char *xml =
        "<!DOCTYPE foo ["
        " <!ELEMENT foo ANY>"
        " <!ENTITY xxe SYSTEM \"file:///etc/passwd\">"
        "]>"
        "<foo>&xxe;</foo>";

    /* ❌ XXE (XXE.ql) - using XML_PARSE_NOENT with untrusted input */
    xmlDocPtr doc = xmlReadMemory(xml, strlen(xml),
                                  "xxe.xml", NULL,
                                  XML_PARSE_NOENT);
    if (doc) {
        xmlNode *root = xmlDocGetRootElement(doc);
        if (root && root->children && root->children->content) {
            printf("XXE content: %s\n", (char *)root->children->content);
        }
        xmlFreeDoc(doc);
    }
}

/* ===========================================================
 *  Main
 * =========================================================== */

int main(int argc, char **argv) {
    const char *user_input = (argc > 1) ? argv[1] : "user";
    const char *secret     = (argc > 2) ? argv[2] : "password123";
    const char *path       = (argc > 3) ? argv[3] : "testfile.txt";

    printf("Running mega_vuln demo...\n");

    /* Memory safety examples */
    double_free_example();
    use_after_free_example();
    char *bad_ptr = return_stack_address_example();
    if (bad_ptr) {
        /* further use of bad_ptr just to keep it live */
        printf("Returned stack data: %s\n", bad_ptr);
    }

    incorrect_scanf_example();

    /* Buffer and string issues */
    overflow_static_example("This is a very very long string that will overflow.");
    badly_bounded_write_example("Another very long string that exceeds 16 bytes.");
    suspicious_strncat_example("dangerous_string");

    dangerous_function_example();
    uncontrolled_format_string_example(user_input);
    snprintf_overflow_example("This_string_is_definitely_longer_than_eight_chars");

    arithmetic_uncontrolled_example(1ULL << 60);
    unsigned_difference_example(10, 20);

    alloca_in_loop_example(5);
    char dummy[8] = {0};
    pointer_overflow_example(dummy, sizeof(dummy), (size_t)-1);

    /* Command execution and CGI/XSS */
    exec_tainted_example(user_input);
    cgi_xss_example();

    /* SQLite usage */
    sqlite3 *db;
    if (sqlite3_open(":memory:", &db) == SQLITE_OK) {
        const char *init_sql =
            "CREATE TABLE users (id INTEGER PRIMARY KEY, name TEXT);"
            "INSERT INTO users (name) VALUES ('alice');"
            "INSERT INTO users (name) VALUES ('bob');";
        sqlite3_exec(db, init_sql, NULL, NULL, NULL);

        sql_injection_example(db, user_input);
        sqlite3_close(db);
    }

    /* Filesystem issues */
    cleartext_file_write_example(secret);
    open_missing_mode_example(path);
    toctou_example(path);

    /* Network / crypto / XML / system data */
    curl_global_init(CURL_GLOBAL_DEFAULT);
    cleartext_transmission_example(secret);
    curl_global_cleanup();

    weak_crypto_example(secret);
    exposed_system_data_example();
    xxe_example();

    return 0;
}
