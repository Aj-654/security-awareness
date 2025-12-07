#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sqlite3.h>

/* Callback for sqlite3_exec */
static int callback(void *data, int argc, char **argv, char **azColName) {
    (void)data;
    for (int i = 0; i < argc; i++) {
        printf("%s = %s\n", azColName[i], argv[i] ? argv[i] : "NULL");
    }
    printf("\n");
    return 0;
}

int main(int argc, char **argv) {
    if (argc < 2) {
        printf("Usage: %s <username>\n", argv[0]);
        return 1;
    }

    sqlite3 *db;
    char *errMsg = NULL;
    int rc = sqlite3_open(":memory:", &db);
    if (rc != SQLITE_OK) {
        printf("Cannot open database: %s\n", sqlite3_errmsg(db));
        return 1;
    }

    /* Create a table */
    const char *createTableSQL =
        "CREATE TABLE users (id INTEGER PRIMARY KEY, name TEXT);"
        "INSERT INTO users (name) VALUES ('alice');"
        "INSERT INTO users (name) VALUES ('bob');";
    sqlite3_exec(db, createTableSQL, callback, 0, NULL);

    char sql[512];
    const char *userInput = argv[1];

    /* ❌ VULNERABLE CODE: SQL Injection using sprintf */
    sprintf(sql,
            "SELECT * FROM users WHERE name = '%s';",
            userInput);

    printf("Executing query: %s\n", sql);

    /* This is where SQL injection is actually executed */
    rc = sqlite3_exec(db, sql, callback, 0, &errMsg);

    if (rc != SQLITE_OK) {
        printf("SQL error: %s\n", errMsg);
        sqlite3_free(errMsg);
    }

    sqlite3_close(db);
    return 0;
}
