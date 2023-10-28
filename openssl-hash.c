#include <stdbool.h>

#include <janet.h>
#include <assert.h>
#include <openssl/evp.h>

struct hasher {
    EVP_MD_CTX *md_ctx;
    bool finalized;
};

static int hasher_gc(void *p, size_t s);
static Janet hasher_new(int32_t argc, Janet *argv);
static Janet hasher_feed(int32_t argc, Janet *argv);
static Janet hasher_finalize(int32_t argc, Janet *argv);

static const JanetAbstractType kOpenSSLHasherType = {
    .name      = "openssl-hash/hasher",
    .gc        = hasher_gc,
    .gcmark    = NULL,
    .get       = NULL,
    .put       = NULL,
    .marshal   = NULL,
    .unmarshal = NULL,
    .tostring  = NULL,
    .compare   = NULL,
    .hash      = NULL,
    .next      = NULL,
    .call      = NULL,
    .length    = NULL,
    .bytes     = NULL,
};

static const JanetReg cfuns[] = {
    {
        "new", hasher_new,
        "(openssl-hash/new algorithm-name)\n\n"
        "Creates a new hashing instance with the given algorithm."
    },
    {
        "feed", hasher_feed,
        "(openssl-hash/feed hasher & data)\n\n"
        "Feed data to the hasher instance. Data may be any type that is capable"
        " of being read as bytes (ex. string, buffer). Returns the hasher."
    },
    {
        "finalize", hasher_finalize,
        "(openssl-hash/finalize hasher &opt flag)\n\n"
        "Return a string containing the binary hash value of the supplied"
        " hasher. Invalidates the hasher. The symbol :hex may be provided as a"
        " flag in order to return a hexadecimal formatted string."
    },
    {NULL}
};

static int hasher_gc(void *p, size_t s) {
    (void) s;
    struct hasher *hasher = p;
    EVP_MD_CTX_free(hasher->md_ctx);
    return 0;
}

static Janet hasher_new(int32_t argc, Janet *argv) {
    janet_fixarity(argc, 1);

    JanetStringHead *j_alg = janet_string_head(janet_getstring(argv, 0));

    // ensure that j_alg doesn't contain any null characters
    for (size_t i = 0; i < j_alg->length; i++) {
        if (j_alg->data[i] == 0) {
            janet_panic("algorithm name invalid due to presence of null characters");
        }
    }

    // convert the name to a null terminated c string
    // janet_smalloc doesn't need a NULL check b/c it includes it's own error
    // handling
    char *j_alg_cstr = janet_smalloc(j_alg->length + 1);
    memcpy(j_alg_cstr, j_alg->data, j_alg->length);
    j_alg_cstr[j_alg->length] = 0;

    const EVP_MD *md = EVP_get_digestbyname(j_alg_cstr);
    if (md == NULL) {
        janet_panicf("no digest algorithm with name '%s'", j_alg_cstr);
    }
    janet_sfree(j_alg_cstr);

    EVP_MD_CTX *md_ctx = EVP_MD_CTX_new();
    // unclear to me if this can fail, but just in case
    if (!md_ctx)
        janet_panic("failed to create the digest context");

    int success = EVP_DigestInit(md_ctx, md);
    if (!success)
        janet_panic("failed to initialize the digest");

    struct hasher *hasher = janet_abstract(&kOpenSSLHasherType, sizeof (*hasher));
    hasher->md_ctx = md_ctx;
    hasher->finalized = false;

    return janet_wrap_abstract(hasher);
}

static Janet hasher_feed(int32_t argc, Janet *argv) {
    janet_arity(argc, 1, INT32_MAX);

    struct hasher *hasher = janet_getabstract(argv, 0, &kOpenSSLHasherType);
    if (hasher->finalized)
        janet_panic("hash already finalized");

    for (int i = 1; i < argc; i++) {
        const uint8_t *data;
        int32_t len;

        int success = janet_bytes_view(argv[1], &data, &len);
        if (!success)
            janet_panic("cannot read bytes of data argument");

        success = EVP_DigestUpdate(hasher->md_ctx, data, len);
        if (!success)
            janet_panic("failed to update digest");
    }

    return argv[0];
}

static char toHexDigit(unsigned x) {
    assert(x <= 0xF);
    if (x <= 9)
        return '0' + x;
    else
        return 'A' + (x - 0xA);
}

static Janet hasher_finalize(int32_t argc, Janet *argv) {
    janet_arity(argc, 1, 2);

    struct hasher *hasher = janet_getabstract(argv, 0, &kOpenSSLHasherType);
    if (hasher->finalized)
        janet_panic("hash already finalized");

    hasher->finalized = true;

    JanetKeyword j_flag = janet_optkeyword(argv, argc, 1, NULL);
    bool out_hex = false;
    if (j_flag) {
        if (janet_string_equal(janet_cstring("hex"), j_flag))
            out_hex = true;
        else
            janet_panicf("unknown flag %v", janet_wrap_keyword(j_flag));
    } 

    // *2 for hex encoding
    unsigned char md[EVP_MAX_MD_SIZE];
    unsigned int md_len;
    // automatically cleans up the md_ctx
    int success = EVP_DigestFinal(hasher->md_ctx, md, &md_len);
    if (!success)
        janet_panic("failed to finalize hash");

    if (out_hex) {
        unsigned char hex_md[EVP_MAX_MD_SIZE * 2];
        for (int i = 0; i < md_len; i++) {
            hex_md[i*2] = toHexDigit(md[i] >> 4);
            hex_md[i*2+1] = toHexDigit(md[i] & 0xF);
        }

        return janet_wrap_string(janet_string(hex_md, md_len*2));
    }

    return janet_wrap_string(janet_string(md, md_len));
}

JANET_MODULE_ENTRY(JanetTable *env) {
    janet_cfuns(env, "openssl-hash", cfuns);
}