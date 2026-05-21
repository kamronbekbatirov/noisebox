// SPDX-License-Identifier: AGPL-3.0-or-later
// NoiseBox -- end-to-end encrypted Cardputer messenger.
// Copyright (C) 2026 Kamronbek B. See LICENSE for the full text.

// HTTPS client to the NoiseBox relay.
// Uses esp_http_client + esp_crt_bundle (Mozilla CA bundle) so Let's Encrypt
// renewals "just work".

#include "transport.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "cJSON.h"
#include "esp_crt_bundle.h"
#include "esp_http_client.h"
#include "esp_log.h"
#include "esp_tls.h"

static const char *TAG = "tx";

static const char *s_host       = NULL;
static const char *s_bot_token  = NULL;     // only for /bind_poll
static char        s_dev_token[96] = {0};   // empty until bound

void tx_init(const char *host, const char *bot_token) {
    s_host = host;
    s_bot_token = bot_token;
}

void tx_set_device_token(const char *token) {
    if (token && token[0]) {
        strncpy(s_dev_token, token, sizeof(s_dev_token) - 1);
        s_dev_token[sizeof(s_dev_token) - 1] = 0;
    } else {
        s_dev_token[0] = 0;
    }
}

// ---- HTTP helpers --------------------------------------------------------

// Hard ceiling on any response body size we will buffer. The relay's
// largest legit response is /poll with N messages of up to SESSION_MAX_CIPHER
// base64 bytes each, plus JSON overhead. We pick 16 KB which fits ~10 max
// messages comfortably; anything bigger is either a relay bug or hostile.
#define RESP_HARD_CAP   (16 * 1024)

typedef struct {
    char  *buf;
    size_t len;
    size_t cap;
    size_t limit;        // per-call cap; 0 means RESP_HARD_CAP
    bool   overflowed;
} resp_t;

static esp_err_t http_event_cb(esp_http_client_event_t *e) {
    if (e->event_id == HTTP_EVENT_ON_DATA && e->user_data) {
        resp_t *r = (resp_t *)e->user_data;
        size_t cap_limit = r->limit ? r->limit : RESP_HARD_CAP;
        size_t n = e->data_len;
        if (r->len + n + 1 > cap_limit) {
            r->overflowed = true;
            return ESP_FAIL;  // tells esp_http_client to abort the transfer
        }
        if (r->len + n + 1 > r->cap) {
            size_t want = r->len + n + 1;
            if (want > cap_limit) want = cap_limit;
            char *nb = (char *)realloc(r->buf, want);
            if (!nb) return ESP_FAIL;
            r->buf = nb;
            r->cap = want;
        }
        memcpy(r->buf + r->len, e->data, n);
        r->len += n;
        r->buf[r->len] = 0;
    }
    return ESP_OK;
}

static void log_response_safe(const char *url_method, int status, const char *body) {
    if (!body) { ESP_LOGE(TAG, "%s status=%d body=<null>", url_method, status); return; }
    // Truncate body to ~80 bytes and strip anything that looks like a bot
    // token (digits:base64) so we don't leak credentials via UART logs.
    char buf[96];
    size_t n = strlen(body);
    if (n > sizeof(buf) - 4) n = sizeof(buf) - 4;
    memcpy(buf, body, n);
    buf[n] = 0;
    // Crude pattern wipe of any "########:[A-Za-z0-9_-]{30,}" subsequence.
    for (size_t i = 0; i + 9 < n; i++) {
        if (buf[i] >= '0' && buf[i] <= '9') {
            size_t j = i;
            while (j < n && buf[j] >= '0' && buf[j] <= '9') j++;
            if (j > i + 5 && j < n && buf[j] == ':') {
                size_t k = j + 1;
                while (k < n && (
                    (buf[k] >= 'A' && buf[k] <= 'Z') ||
                    (buf[k] >= 'a' && buf[k] <= 'z') ||
                    (buf[k] >= '0' && buf[k] <= '9') ||
                    buf[k] == '_' || buf[k] == '-')) k++;
                if (k - j > 20) {
                    for (size_t r = i; r < k && r < sizeof(buf) - 1; r++) buf[r] = '*';
                }
            }
        }
    }
    ESP_LOGE(TAG, "%s status=%d body=%s%s", url_method, status, buf,
             strlen(body) > sizeof(buf) - 4 ? "..." : "");
}

static int http_call_limited(const char *url, esp_http_client_method_t method,
                             const char *body, resp_t *resp,
                             int timeout_ms, size_t resp_limit) {
    resp->limit = resp_limit;
    esp_http_client_config_t cfg = {
        .url = url,
        .timeout_ms = timeout_ms,
        .crt_bundle_attach = esp_crt_bundle_attach,
        .event_handler = http_event_cb,
        .user_data = resp,
        .keep_alive_enable = false,
        .method = method,
    };
    esp_http_client_handle_t c = esp_http_client_init(&cfg);
    if (!c) return -1;

    if (body) {
        esp_http_client_set_header(c, "Content-Type", "application/json");
        esp_http_client_set_post_field(c, body, strlen(body));
    }

    esp_err_t e = esp_http_client_perform(c);
    int status = -1;
    if (e == ESP_OK) {
        status = esp_http_client_get_status_code(c);
    } else {
        ESP_LOGE(TAG, "http perform: %s (%d)", esp_err_to_name(e), e);
    }
    if (resp->overflowed) {
        ESP_LOGW(TAG, "http response exceeded %u bytes, aborted",
                 (unsigned)(resp->limit ? resp->limit : RESP_HARD_CAP));
        status = -2;
    }
    esp_http_client_cleanup(c);
    return status;
}

// Compatibility shim for older callers - uses the default RESP_HARD_CAP.
static int http_call(const char *url, esp_http_client_method_t method,
                     const char *body, resp_t *resp, int timeout_ms) {
    return http_call_limited(url, method, body, resp, timeout_ms, 0);
}

// build_url uses the per-device bearer token. For the unauthenticated
// bind path we call build_admin_url which carries the shared bot_token.
static int build_url(char *out, size_t cap, const char *method,
                     const char *qs) {
    if (qs) {
        return snprintf(out, cap, "https://%s/v1/%s/%s?%s",
                        s_host, s_dev_token, method, qs);
    }
    return snprintf(out, cap, "https://%s/v1/%s/%s",
                    s_host, s_dev_token, method);
}
static int build_admin_url(char *out, size_t cap, const char *method,
                           const char *qs) {
    if (qs) {
        return snprintf(out, cap, "https://%s/v1/%s/%s?%s",
                        s_host, s_bot_token, method, qs);
    }
    return snprintf(out, cap, "https://%s/v1/%s/%s",
                    s_host, s_bot_token, method);
}

// ---- API methods ---------------------------------------------------------

int tx_bind_poll(const char *code, int64_t *out_user_chat_id,
                 char *out_device_token, size_t token_cap) {
    char url[256], qs[64];
    snprintf(qs, sizeof qs, "code=%s", code);
    build_admin_url(url, sizeof url, "bind_poll", qs);
    resp_t r = {0};
    int status = http_call(url, HTTP_METHOD_GET, NULL, &r, 5000);
    int rc = -1;
    if (status == 200 && r.buf) {
        cJSON *j = cJSON_Parse(r.buf);
        if (j) {
            cJSON *ok = cJSON_GetObjectItem(j, "ok");
            cJSON *bound = cJSON_GetObjectItem(j, "bound");
            cJSON *uid = cJSON_GetObjectItem(j, "user_chat_id");
            cJSON *tok = cJSON_GetObjectItem(j, "device_token");
            if (cJSON_IsTrue(ok)) {
                if (cJSON_IsTrue(bound) && cJSON_IsNumber(uid)
                        && cJSON_IsString(tok)
                        && tok->valuestring
                        && strlen(tok->valuestring) < token_cap) {
                    *out_user_chat_id = (int64_t)uid->valuedouble;
                    strncpy(out_device_token, tok->valuestring, token_cap - 1);
                    out_device_token[token_cap - 1] = 0;
                    rc = 0;
                } else {
                    rc = 1;
                }
            }
            cJSON_Delete(j);
        }
    } else if (status == 410) {
        rc = -2;                       // code expired/claimed -> regen
    } else if (status == 429) {
        rc = -3;                       // rate-limited; same code is still good
    } else {
        log_response_safe("bind_poll", status, r.buf);
    }
    free(r.buf);
    return rc;
}

int tx_get_peers(tx_peer_t *out, int cap) {
    char url[256];
    build_url(url, sizeof url, "peers", NULL);
    resp_t r = {0};
    int status = http_call(url, HTTP_METHOD_GET, NULL, &r, 8000);
    int n = -1;
    if (status == 200 && r.buf) {
        cJSON *j = cJSON_Parse(r.buf);
        if (j) {
            cJSON *peers = cJSON_GetObjectItem(j, "peers");
            n = 0;
            if (cJSON_IsArray(peers)) {
                int total = cJSON_GetArraySize(peers);
                for (int i = 0; i < total && n < cap; i++) {
                    cJSON *p   = cJSON_GetArrayItem(peers, i);
                    cJSON *uid = cJSON_GetObjectItem(p, "user_id");
                    cJSON *fn  = cJSON_GetObjectItem(p, "first_name");
                    cJSON *ln  = cJSON_GetObjectItem(p, "last_name");
                    cJSON *un  = cJSON_GetObjectItem(p, "username");
                    if (!cJSON_IsNumber(uid)) continue;
                    out[n].user_id = (int64_t)uid->valuedouble;
                    const char *f = (fn && fn->valuestring) ? fn->valuestring : "";
                    const char *l = (ln && ln->valuestring) ? ln->valuestring : "";
                    const char *u = (un && un->valuestring) ? un->valuestring : "";
                    // Display-name priority (no field guarantees a value):
                    //   "First Last @user", "First @user", "First Last",
                    //   "First", "Last", "@user", "User <id>".
                    if (f[0] && u[0] && l[0]) {
                        snprintf(out[n].name, TX_PEER_NAME, "%s %s @%s", f, l, u);
                    } else if (f[0] && u[0]) {
                        snprintf(out[n].name, TX_PEER_NAME, "%s @%s", f, u);
                    } else if (f[0] && l[0]) {
                        snprintf(out[n].name, TX_PEER_NAME, "%s %s", f, l);
                    } else if (f[0]) {
                        snprintf(out[n].name, TX_PEER_NAME, "%s", f);
                    } else if (l[0]) {
                        snprintf(out[n].name, TX_PEER_NAME, "%s", l);
                    } else if (u[0]) {
                        snprintf(out[n].name, TX_PEER_NAME, "@%s", u);
                    } else {
                        // Fall back to a 4-digit suffix of the ID. Full
                        // 64-bit IDs look like garbage on the menu.
                        long long lid = (long long)out[n].user_id;
                        snprintf(out[n].name, TX_PEER_NAME, "User %04lld", lid % 10000);
                    }
                    n++;
                }
            }
            cJSON_Delete(j);
        }
    }
    free(r.buf);
    return n;
}

int tx_get_head_id(uint32_t *out_head_id) {
    char url[256];
    build_url(url, sizeof url, "info", NULL);
    resp_t r = {0};
    int status = http_call(url, HTTP_METHOD_GET, NULL, &r, 5000);
    int rc = -1;
    if (status == 200 && r.buf) {
        cJSON *j = cJSON_Parse(r.buf);
        if (j) {
            cJSON *h = cJSON_GetObjectItem(j, "head_id");
            if (cJSON_IsNumber(h)) {
                *out_head_id = (uint32_t)h->valuedouble;
                rc = 0;
            }
            cJSON_Delete(j);
        }
    }
    free(r.buf);
    return rc;
}

int tx_send(int64_t peer_user_id, const char *text) {
    char url[256];
    build_url(url, sizeof url, "send", NULL);
    cJSON *body = cJSON_CreateObject();
    cJSON_AddNumberToObject(body, "peer_user_id", (double)peer_user_id);
    cJSON_AddStringToObject(body, "text", text);
    char *s = cJSON_PrintUnformatted(body);
    cJSON_Delete(body);
    if (!s) return -1;
    resp_t r = {0};
    int status = http_call(url, HTTP_METHOD_POST, s, &r, 8000);
    free(s);
    int rc = (status == 200) ? 0 : -1;
    if (rc != 0) log_response_safe("send", status, r.buf);
    free(r.buf);
    return rc;
}

int tx_poll(uint32_t *after_inout, tx_msg_t *out, int cap, int timeout_s) {
    char url[256], qs[64];
    snprintf(qs, sizeof qs, "after=%u&timeout=%d",
             (unsigned)*after_inout, timeout_s);
    build_url(url, sizeof url, "poll", qs);
    resp_t r = {0};
    int status = http_call(url, HTTP_METHOD_GET, NULL, &r,
                           (timeout_s + 5) * 1000);
    int n = -1;
    if (status == 200 && r.buf) {
        cJSON *j = cJSON_Parse(r.buf);
        if (j) {
            cJSON *arr = cJSON_GetObjectItem(j, "messages");
            n = 0;
            if (cJSON_IsArray(arr)) {
                int total = cJSON_GetArraySize(arr);
                for (int i = 0; i < total && n < cap; i++) {
                    cJSON *m = cJSON_GetArrayItem(arr, i);
                    cJSON *id = cJSON_GetObjectItem(m, "id");
                    cJSON *from = cJSON_GetObjectItem(m, "from");
                    cJSON *text = cJSON_GetObjectItem(m, "text");
                    cJSON *ts   = cJSON_GetObjectItem(m, "ts");
                    if (!cJSON_IsNumber(id) || !cJSON_IsNumber(from)) continue;
                    out[n].id = (uint32_t)id->valuedouble;
                    out[n].from = (int64_t)from->valuedouble;
                    out[n].ts = ts ? (int64_t)ts->valuedouble : 0;
                    const char *t = (text && text->valuestring) ? text->valuestring : "";
                    // Drop oversized messages instead of silently truncating
                    // (truncation breaks AEAD verification on the ratchet side).
                    if (strlen(t) >= TX_MAX_MSG) {
                        ESP_LOGW(TAG, "drop msg #%u: text len %u > cap",
                                 (unsigned)out[n].id, (unsigned)strlen(t));
                        if (out[n].id > *after_inout) *after_inout = out[n].id;
                        continue;
                    }
                    snprintf(out[n].text, TX_MAX_MSG, "%s", t);
                    if (out[n].id > *after_inout) *after_inout = out[n].id;
                    n++;
                }
            }
            cJSON_Delete(j);
        }
    } else {
        ESP_LOGE(TAG, "poll status=%d", status);
    }
    free(r.buf);
    return n;
}
