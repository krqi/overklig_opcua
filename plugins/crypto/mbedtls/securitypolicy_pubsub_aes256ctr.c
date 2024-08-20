
#include <opcua/plugin/securitypolicy_default.h>
#include <opcua/util.h>

#ifdef UA_ENABLE_ENCRYPTION_MBEDTLS

#include "securitypolicy_common.h"

#include <mbedtls/aes.h>
#include <mbedtls/ctr_drbg.h>
#include <mbedtls/entropy.h>
#include <mbedtls/error.h>
#include <mbedtls/md.h>
#include <mbedtls/sha1.h>
#include <mbedtls/sha256.h>
#include <mbedtls/version.h>
#include <mbedtls/x509_crt.h>


#define UA_SHA256_LENGTH 32
#define UA_AES256CTR_SIGNING_KEY_LENGTH 32
#define UA_AES256CTR_KEY_LENGTH 32
#define UA_AES256CTR_KEYNONCE_LENGTH 4
#define UA_AES256CTR_MESSAGENONCE_LENGTH 8
#define UA_AES256CTR_ENCRYPTION_BLOCK_SIZE 16
#define UA_AES256CTR_PLAIN_TEXT_BLOCK_SIZE 16
// counter block=keynonce(4Byte)+Messagenonce(8Byte)+counter(4Byte) see Part14 7.2.2.2.3.2
// for details
#define UA_AES256CTR_COUNTERBLOCK_SIZE 16

typedef struct {
    const UA_PubSubSecurityPolicy *securityPolicy;
    mbedtls_ctr_drbg_context drbgContext;
    mbedtls_entropy_context entropyContext;
    mbedtls_md_context_t sha256MdContext;
} PUBSUB_AES256CTR_PolicyContext;

typedef struct {
    PUBSUB_AES256CTR_PolicyContext *policyContext;
    UA_Byte signingKey[UA_AES256CTR_SIGNING_KEY_LENGTH];
    UA_Byte encryptingKey[UA_AES256CTR_KEY_LENGTH];
    UA_Byte keyNonce[UA_AES256CTR_KEYNONCE_LENGTH];
    UA_Byte messageNonce[UA_AES256CTR_MESSAGENONCE_LENGTH];
} PUBSUB_AES256CTR_ChannelContext;


static UA_StatusCode
verify_sp_pubsub_aes256ctr(PUBSUB_AES256CTR_ChannelContext *cc,
                           const UA_ByteString *message,
                           const UA_ByteString *signature) {
    if(cc == NULL || message == NULL || signature == NULL)
        return UA_STATUSCODE_BADINTERNALERROR;

    
    if(signature->length != UA_SHA256_LENGTH) {
        return UA_STATUSCODE_BADSECURITYCHECKSFAILED;
    }

    PUBSUB_AES256CTR_PolicyContext *pc =
        (PUBSUB_AES256CTR_PolicyContext *)cc->policyContext;

    unsigned char mac[UA_SHA256_LENGTH];
    UA_ByteString signingKey =
        {UA_AES256CTR_SIGNING_KEY_LENGTH, cc->signingKey};
    if(mbedtls_hmac(&pc->sha256MdContext, &signingKey, message, mac) != UA_STATUSCODE_GOOD)
        return UA_STATUSCODE_BADSECURITYCHECKSFAILED;

    
    if(!UA_constantTimeEqual(signature->data, mac, UA_SHA256_LENGTH))
        return UA_STATUSCODE_BADSECURITYCHECKSFAILED;
    return UA_STATUSCODE_GOOD;
}

static UA_StatusCode
sign_sp_pubsub_aes256ctr(PUBSUB_AES256CTR_ChannelContext *cc,
                         const UA_ByteString *message, UA_ByteString *signature) {
    if(signature->length != UA_SHA256_LENGTH)
        return UA_STATUSCODE_BADINTERNALERROR;
    UA_ByteString signingKey =
        {UA_AES256CTR_SIGNING_KEY_LENGTH, cc->signingKey};
    if(mbedtls_hmac(&cc->policyContext->sha256MdContext, &signingKey,
                    message, signature->data) != UA_STATUSCODE_GOOD)
        return UA_STATUSCODE_BADSECURITYCHECKSFAILED;

    return UA_STATUSCODE_GOOD;
}

static size_t
getSignatureSize_sp_pubsub_aes256ctr(const void *channelContext) {
    return UA_SHA256_LENGTH;
}

static size_t
getSigningKeyLength_sp_pubsub_aes256ctr(const void *const channelContext) {
    return UA_AES256CTR_SIGNING_KEY_LENGTH;
}

static size_t
getEncryptionKeyLength_sp_pubsub_aes256ctr(const void *channelContext) {
    return UA_AES256CTR_KEY_LENGTH;
}

static size_t
getEncryptionBlockSize_sp_pubsub_aes256ctr(const void *const channelContext) {
    return UA_AES256CTR_ENCRYPTION_BLOCK_SIZE;
}

static size_t
getPlainTextBlockSize_sp_pubsub_aes256ctr(const void *const channelContext) {
    return UA_AES256CTR_PLAIN_TEXT_BLOCK_SIZE;
}

static UA_StatusCode
encrypt_sp_pubsub_aes256ctr(const PUBSUB_AES256CTR_ChannelContext *cc,
                            UA_ByteString *data) {
    if(cc == NULL || data == NULL)
        return UA_STATUSCODE_BADINTERNALERROR;

    

    

    
    unsigned int keylength = (unsigned int)(UA_AES256CTR_KEY_LENGTH * 8);
    mbedtls_aes_context aesContext;
    int mbedErr =
        mbedtls_aes_setkey_enc(&aesContext, cc->encryptingKey, keylength);
    if(mbedErr)
        return UA_STATUSCODE_BADINTERNALERROR;

    UA_Byte counterBlockCopy[UA_AES256CTR_ENCRYPTION_BLOCK_SIZE];
    UA_Byte counterInitialValue[4] = {0,0,0,1};
    memcpy(counterBlockCopy, cc->keyNonce, UA_AES256CTR_KEYNONCE_LENGTH);
    memcpy(counterBlockCopy + UA_AES256CTR_KEYNONCE_LENGTH,
           cc->messageNonce, UA_AES256CTR_MESSAGENONCE_LENGTH);
    memcpy(counterBlockCopy + UA_AES256CTR_KEYNONCE_LENGTH +
           UA_AES256CTR_MESSAGENONCE_LENGTH, &counterInitialValue, 4);

    size_t counterblockoffset = 0;
    UA_Byte aesBuffer[UA_AES256CTR_ENCRYPTION_BLOCK_SIZE];
    mbedErr = mbedtls_aes_crypt_ctr(&aesContext, data->length, &counterblockoffset,
                                    counterBlockCopy, aesBuffer, data->data, data->data);
    if(mbedErr)
        return UA_STATUSCODE_BADINTERNALERROR;
    return UA_STATUSCODE_GOOD;
}

static UA_StatusCode
decrypt_sp_pubsub_aes256ctr(const PUBSUB_AES256CTR_ChannelContext *cc,
                            UA_ByteString *data) {
    return encrypt_sp_pubsub_aes256ctr(cc, data);
}


static UA_StatusCode
generateKey_sp_pubsub_aes256ctr(void *policyContext,
                                    const UA_ByteString *secret,
                                    const UA_ByteString *seed, UA_ByteString *out) {
    if(policyContext == NULL || secret == NULL || seed == NULL || out == NULL)
        return UA_STATUSCODE_BADINTERNALERROR;

    PUBSUB_AES256CTR_PolicyContext *pc = (PUBSUB_AES256CTR_PolicyContext *)policyContext;

    return mbedtls_generateKey(&pc->sha256MdContext, secret, seed, out);
}
static UA_StatusCode
generateNonce_sp_pubsub_aes256ctr(void *policyContext, UA_ByteString *out) {
    if(policyContext == NULL || out == NULL)
        return UA_STATUSCODE_BADINTERNALERROR;

    PUBSUB_AES256CTR_PolicyContext *pc =
        (PUBSUB_AES256CTR_PolicyContext *) policyContext;
    int mbedErr = mbedtls_ctr_drbg_random(&pc->drbgContext, out->data, out->length);
    if(mbedErr)
        return UA_STATUSCODE_BADUNEXPECTEDERROR;
    return UA_STATUSCODE_GOOD;
}





static void
channelContext_deleteContext_sp_pubsub_aes256ctr(PUBSUB_AES256CTR_ChannelContext *cc) {
    UA_free(cc);
}

static UA_StatusCode
channelContext_newContext_sp_pubsub_aes256ctr(void *policyContext,
                                              const UA_ByteString *signingKey,
                                              const UA_ByteString *encryptingKey,
                                              const UA_ByteString *keyNonce,
                                              void **wgContext) {

    if((signingKey && signingKey->length != UA_AES256CTR_SIGNING_KEY_LENGTH) ||
       (encryptingKey && encryptingKey->length != UA_AES256CTR_KEY_LENGTH) ||
       (keyNonce && keyNonce->length != UA_AES256CTR_KEYNONCE_LENGTH))
        return UA_STATUSCODE_BADSECURITYCHECKSFAILED;

    
    PUBSUB_AES256CTR_ChannelContext *cc = (PUBSUB_AES256CTR_ChannelContext *)
        UA_calloc(1, sizeof(PUBSUB_AES256CTR_ChannelContext));
    if(cc == NULL)
        return UA_STATUSCODE_BADOUTOFMEMORY;

    
    cc->policyContext = (PUBSUB_AES256CTR_PolicyContext *)policyContext;
    if(signingKey)
        memcpy(cc->signingKey, signingKey->data, signingKey->length);
    if(encryptingKey)
        memcpy(cc->encryptingKey, encryptingKey->data, encryptingKey->length);
    if(keyNonce)
        memcpy(cc->keyNonce, keyNonce->data, keyNonce->length);
    *wgContext = cc;
    return UA_STATUSCODE_GOOD;
}

static UA_StatusCode
channelContext_setKeys_sp_pubsub_aes256ctr(PUBSUB_AES256CTR_ChannelContext *cc,
                                           const UA_ByteString *signingKey,
                                           const UA_ByteString *encryptingKey,
                                           const UA_ByteString *keyNonce) {
    if(!cc)
        return UA_STATUSCODE_BADINTERNALERROR;
    if(!signingKey || signingKey->length != UA_AES256CTR_SIGNING_KEY_LENGTH ||
       !encryptingKey || encryptingKey->length != UA_AES256CTR_KEY_LENGTH ||
       !keyNonce || keyNonce->length != UA_AES256CTR_KEYNONCE_LENGTH)
        return UA_STATUSCODE_BADSECURITYCHECKSFAILED;
    memcpy(cc->signingKey, signingKey->data, signingKey->length);
    memcpy(cc->encryptingKey, encryptingKey->data, encryptingKey->length);
    memcpy(cc->keyNonce, keyNonce->data, keyNonce->length);
    return UA_STATUSCODE_GOOD;
}

static UA_StatusCode
channelContext_setMessageNonce_sp_pubsub_aes256ctr(PUBSUB_AES256CTR_ChannelContext *cc,
                                                   const UA_ByteString *nonce) {
    if(nonce->length != UA_AES256CTR_MESSAGENONCE_LENGTH)
        return UA_STATUSCODE_BADSECURITYCHECKSFAILED;
    memcpy(cc->messageNonce, nonce->data, nonce->length);
    return UA_STATUSCODE_GOOD;
}

static void
deleteMembers_sp_pubsub_aes256ctr(UA_PubSubSecurityPolicy *securityPolicy) {
    if(securityPolicy == NULL)
        return;

    if(securityPolicy->policyContext == NULL)
        return;

    
    PUBSUB_AES256CTR_PolicyContext *pc =
        (PUBSUB_AES256CTR_PolicyContext *)securityPolicy->policyContext;

    mbedtls_ctr_drbg_free(&pc->drbgContext);
    mbedtls_entropy_free(&pc->entropyContext);
    mbedtls_md_free(&pc->sha256MdContext);
    UA_LOG_DEBUG(securityPolicy->logger, UA_LOGCATEGORY_SECURITYPOLICY,
                 "Deleted members of EndpointContext for sp_PUBSUB_AES256CTR");
    UA_free(pc);
    securityPolicy->policyContext = NULL;
}

static UA_StatusCode
policyContext_newContext_sp_pubsub_aes256ctr(UA_PubSubSecurityPolicy *securityPolicy) {
    UA_StatusCode retval = UA_STATUSCODE_GOOD;
    if(securityPolicy == NULL)
        return UA_STATUSCODE_BADINTERNALERROR;

    PUBSUB_AES256CTR_PolicyContext *pc = (PUBSUB_AES256CTR_PolicyContext *)
        UA_calloc(1, sizeof(PUBSUB_AES256CTR_PolicyContext));
    securityPolicy->policyContext = (void *)pc;
    if(!pc) {
        retval = UA_STATUSCODE_BADOUTOFMEMORY;
        goto error;
    }

    
    memset(pc, 0, sizeof(PUBSUB_AES256CTR_PolicyContext));
    mbedtls_ctr_drbg_init(&pc->drbgContext);
    mbedtls_entropy_init(&pc->entropyContext);
    mbedtls_md_init(&pc->sha256MdContext);
    pc->securityPolicy = securityPolicy;

    
    const mbedtls_md_info_t *const mdInfo = mbedtls_md_info_from_type(MBEDTLS_MD_SHA256);
    int mbedErr = mbedtls_md_setup(&pc->sha256MdContext, mdInfo, MBEDTLS_MD_SHA256);
    if(mbedErr) {
        retval = UA_STATUSCODE_BADOUTOFMEMORY;
        goto error;
    }

    mbedErr = mbedtls_entropy_self_test(0);

    if(mbedErr) {
        retval = UA_STATUSCODE_BADSECURITYCHECKSFAILED;
        goto error;
    }

    
    char *personalization = "opcua-drbg";
    mbedErr = mbedtls_ctr_drbg_seed(&pc->drbgContext, mbedtls_entropy_func,
                                    &pc->entropyContext,
                                    (const unsigned char *)personalization, 14);
    if(mbedErr) {
        retval = UA_STATUSCODE_BADSECURITYCHECKSFAILED;
        goto error;
    }

    return retval;

    error:
    UA_LOG_ERROR(securityPolicy->logger, UA_LOGCATEGORY_SECURITYPOLICY,
                 "Could not create securityContext");
    if(securityPolicy->policyContext != NULL)
        deleteMembers_sp_pubsub_aes256ctr(securityPolicy);
    return retval;
}

UA_StatusCode
UA_PubSubSecurityPolicy_Aes256Ctr(UA_PubSubSecurityPolicy *policy,
                                  const UA_Logger *logger) {
    memset(policy, 0, sizeof(UA_PubSubSecurityPolicy));
    policy->logger = logger;

    policy->policyUri =
        UA_STRING("http://opcfoundation.org/UA/SecurityPolicy#PubSub-Aes256-CTR");

    UA_SecurityPolicySymmetricModule *symmetricModule = &policy->symmetricModule;

    
    symmetricModule->generateKey = generateKey_sp_pubsub_aes256ctr;
    symmetricModule->generateNonce = generateNonce_sp_pubsub_aes256ctr;

    UA_SecurityPolicySignatureAlgorithm *signatureAlgorithm =
        &symmetricModule->cryptoModule.signatureAlgorithm;
    signatureAlgorithm->uri = UA_STRING("http://www.w3.org/2001/04/xmlenc#sha256");
    signatureAlgorithm->verify =
        (UA_StatusCode(*)(void *, const UA_ByteString *,
                          const UA_ByteString *))verify_sp_pubsub_aes256ctr;
    signatureAlgorithm->sign =
        (UA_StatusCode(*)(void *, const UA_ByteString *, UA_ByteString *))sign_sp_pubsub_aes256ctr;
    signatureAlgorithm->getLocalSignatureSize = getSignatureSize_sp_pubsub_aes256ctr;
    signatureAlgorithm->getRemoteSignatureSize = getSignatureSize_sp_pubsub_aes256ctr;
    signatureAlgorithm->getLocalKeyLength =
        (size_t(*)(const void *))getSigningKeyLength_sp_pubsub_aes256ctr;
    signatureAlgorithm->getRemoteKeyLength =
        (size_t(*)(const void *))getSigningKeyLength_sp_pubsub_aes256ctr;

    UA_SecurityPolicyEncryptionAlgorithm *encryptionAlgorithm =
        &symmetricModule->cryptoModule.encryptionAlgorithm;
    encryptionAlgorithm->uri =
        UA_STRING("https://tools.ietf.org/html/rfc3686"); 
    encryptionAlgorithm->encrypt =
        (UA_StatusCode(*)(void *, UA_ByteString *))encrypt_sp_pubsub_aes256ctr;
    encryptionAlgorithm->decrypt =
        (UA_StatusCode(*)(void *, UA_ByteString *))decrypt_sp_pubsub_aes256ctr;
    encryptionAlgorithm->getLocalKeyLength =
        getEncryptionKeyLength_sp_pubsub_aes256ctr;
    encryptionAlgorithm->getRemoteKeyLength =
        getEncryptionKeyLength_sp_pubsub_aes256ctr;
    encryptionAlgorithm->getRemoteBlockSize =
        (size_t(*)(const void *))getEncryptionBlockSize_sp_pubsub_aes256ctr;
    encryptionAlgorithm->getRemotePlainTextBlockSize =
        (size_t(*)(const void *))getPlainTextBlockSize_sp_pubsub_aes256ctr;
    symmetricModule->secureChannelNonceLength = UA_AES256CTR_SIGNING_KEY_LENGTH +
                                                UA_AES256CTR_KEY_LENGTH + UA_AES256CTR_KEYNONCE_LENGTH;

    
    policy->newContext = channelContext_newContext_sp_pubsub_aes256ctr;
    policy->deleteContext = (void (*)(void *))
        channelContext_deleteContext_sp_pubsub_aes256ctr;

    policy->setSecurityKeys = (UA_StatusCode(*)(void *, const UA_ByteString *,
                                                const UA_ByteString *,
                                                const UA_ByteString *))
        channelContext_setKeys_sp_pubsub_aes256ctr;
    policy->setMessageNonce = (UA_StatusCode(*)(void *, const UA_ByteString *))
        channelContext_setMessageNonce_sp_pubsub_aes256ctr;
    policy->clear = deleteMembers_sp_pubsub_aes256ctr;
    policy->policyContext = NULL;

    
    return policyContext_newContext_sp_pubsub_aes256ctr(policy);
}

#endif
