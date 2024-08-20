
#include <opcua/plugin/securitypolicy.h>
#include <opcua/plugin/certificategroup.h>
#include <opcua/types.h>

#if defined(UA_ENABLE_ENCRYPTION_MBEDTLS)

#include "securitypolicy_common.h"

#include <mbedtls/aes.h>
#include <mbedtls/ctr_drbg.h>
#include <mbedtls/entropy.h>
#include <mbedtls/error.h>
#include <mbedtls/md.h>
#include <mbedtls/sha1.h>
#include <mbedtls/version.h>
#include <mbedtls/x509_crt.h>
#include <mbedtls/asn1write.h>
#include <mbedtls/oid.h>
#include <mbedtls/platform.h>

#define CSR_BUFFER_SIZE 4096

void
swapBuffers(UA_ByteString *const bufA, UA_ByteString *const bufB) {
    UA_ByteString tmp = *bufA;
    *bufA = *bufB;
    *bufB = tmp;
}

UA_StatusCode
mbedtls_hmac(mbedtls_md_context_t *context, const UA_ByteString *key,
             const UA_ByteString *in, unsigned char *out) {

    if(mbedtls_md_hmac_starts(context, key->data, key->length) != 0)
        return UA_STATUSCODE_BADSECURITYCHECKSFAILED;

    if(mbedtls_md_hmac_update(context, in->data, in->length) != 0)
        return UA_STATUSCODE_BADSECURITYCHECKSFAILED;

    if(mbedtls_md_hmac_finish(context, out) != 0)
        return UA_STATUSCODE_BADSECURITYCHECKSFAILED;

    return UA_STATUSCODE_GOOD;
}

UA_StatusCode
mbedtls_generateKey(mbedtls_md_context_t *context,
                    const UA_ByteString *secret, const UA_ByteString *seed,
                    UA_ByteString *out) {
#if MBEDTLS_VERSION_NUMBER >= 0x02060000 && MBEDTLS_VERSION_NUMBER < 0x03000000
    size_t hashLen = (size_t)mbedtls_md_get_size(context->md_info);
#else
    size_t hashLen = (size_t)mbedtls_md_get_size(context->private_md_info);
#endif

    UA_ByteString A_and_seed;
    UA_ByteString_allocBuffer(&A_and_seed, hashLen + seed->length);
    memcpy(A_and_seed.data + hashLen, seed->data, seed->length);

    UA_ByteString ANext_and_seed;
    UA_ByteString_allocBuffer(&ANext_and_seed, hashLen + seed->length);
    memcpy(ANext_and_seed.data + hashLen, seed->data, seed->length);

    UA_ByteString A = {
        hashLen,
        A_and_seed.data
    };

    UA_ByteString ANext = {
        hashLen,
        ANext_and_seed.data
    };

    UA_StatusCode retval = mbedtls_hmac(context, secret, seed, A.data);

    if(retval != UA_STATUSCODE_GOOD){
        UA_ByteString_clear(&A_and_seed);
        UA_ByteString_clear(&ANext_and_seed);
        return retval;
    }

    for(size_t offset = 0; offset < out->length; offset += hashLen) {
        UA_ByteString outSegment = {
            hashLen,
            out->data + offset
        };
        UA_Boolean bufferAllocated = UA_FALSE;
        // Not enough room in out buffer to write the hash.
        if(offset + hashLen > out->length) {
            outSegment.data = NULL;
            outSegment.length = 0;
            retval = UA_ByteString_allocBuffer(&outSegment, hashLen);
            if(retval != UA_STATUSCODE_GOOD) {
                UA_ByteString_clear(&A_and_seed);
                UA_ByteString_clear(&ANext_and_seed);
                return retval;
            }
            bufferAllocated = UA_TRUE;
        }

        retval = mbedtls_hmac(context, secret, &A_and_seed, outSegment.data);
        if(retval != UA_STATUSCODE_GOOD){
            UA_ByteString_clear(&A_and_seed);
            UA_ByteString_clear(&ANext_and_seed);
            return retval;
        }
        retval = mbedtls_hmac(context, secret, &A, ANext.data);
        if(retval != UA_STATUSCODE_GOOD){
            UA_ByteString_clear(&A_and_seed);
            UA_ByteString_clear(&ANext_and_seed);
            return retval;
        }

        if(bufferAllocated) {
            memcpy(out->data + offset, outSegment.data, out->length - offset);
            UA_ByteString_clear(&outSegment);
        }

        swapBuffers(&ANext_and_seed, &A_and_seed);
        swapBuffers(&ANext, &A);
    }

    UA_ByteString_clear(&A_and_seed);
    UA_ByteString_clear(&ANext_and_seed);
    return UA_STATUSCODE_GOOD;
}

UA_StatusCode
mbedtls_verifySig_sha1(mbedtls_x509_crt *certificate, const UA_ByteString *message,
                       const UA_ByteString *signature) {
    
    unsigned char hash[UA_SHA1_LENGTH];
#if MBEDTLS_VERSION_NUMBER >= 0x02070000 && MBEDTLS_VERSION_NUMBER < 0x03000000
    mbedtls_sha1_ret(message->data, message->length, hash);
#else
    mbedtls_sha1(message->data, message->length, hash);
#endif

    
    mbedtls_rsa_context *rsaContext = mbedtls_pk_rsa(certificate->pk);
    if(!rsaContext)
        return UA_STATUSCODE_BADINTERNALERROR;
    mbedtls_rsa_set_padding(rsaContext, MBEDTLS_RSA_PKCS_V15, MBEDTLS_MD_NONE);

    
    int mbedErr = mbedtls_pk_verify(&certificate->pk,
                                    MBEDTLS_MD_SHA1, hash, UA_SHA1_LENGTH,
                                    signature->data, signature->length);
    if(mbedErr)
        return UA_STATUSCODE_BADSECURITYCHECKSFAILED;
    return UA_STATUSCODE_GOOD;
}

UA_StatusCode
mbedtls_sign_sha1(mbedtls_pk_context *localPrivateKey,
                  mbedtls_ctr_drbg_context *drbgContext,
                  const UA_ByteString *message,
                  UA_ByteString *signature) {
    unsigned char hash[UA_SHA1_LENGTH];
#if MBEDTLS_VERSION_NUMBER >= 0x02070000 && MBEDTLS_VERSION_NUMBER < 0x03000000
    mbedtls_sha1_ret(message->data, message->length, hash);
#else
    mbedtls_sha1(message->data, message->length, hash);
#endif

    mbedtls_rsa_context *rsaContext = mbedtls_pk_rsa(*localPrivateKey);
    mbedtls_rsa_set_padding(rsaContext, MBEDTLS_RSA_PKCS_V15, MBEDTLS_MD_NONE);

    size_t sigLen = 0;
    int mbedErr = mbedtls_pk_sign(localPrivateKey, MBEDTLS_MD_SHA1, hash,
                                  UA_SHA1_LENGTH, signature->data,
#if MBEDTLS_VERSION_NUMBER >= 0x03000000
                                  signature->length,
#endif
                                  &sigLen,
                                  mbedtls_ctr_drbg_random, drbgContext);
    if(mbedErr)
        return UA_STATUSCODE_BADINTERNALERROR;
    return UA_STATUSCODE_GOOD;
}

UA_StatusCode
mbedtls_thumbprint_sha1(const UA_ByteString *certificate,
                        UA_ByteString *thumbprint) {
    if(UA_ByteString_equal(certificate, &UA_BYTESTRING_NULL))
        return UA_STATUSCODE_BADINTERNALERROR;

    if(thumbprint->length != UA_SHA1_LENGTH)
        return UA_STATUSCODE_BADINTERNALERROR;

    
#if MBEDTLS_VERSION_NUMBER >= 0x02070000 && MBEDTLS_VERSION_NUMBER < 0x03000000
    mbedtls_sha1_ret(certificate->data, certificate->length, thumbprint->data);
#else
    mbedtls_sha1(certificate->data, certificate->length, thumbprint->data);
#endif
    return UA_STATUSCODE_GOOD;
}

UA_StatusCode
mbedtls_encrypt_rsaOaep(mbedtls_rsa_context *context,
                        mbedtls_ctr_drbg_context *drbgContext,
                        UA_ByteString *data, const size_t plainTextBlockSize) {
    if(data->length % plainTextBlockSize != 0)
        return UA_STATUSCODE_BADINTERNALERROR;

    size_t max_blocks = data->length / plainTextBlockSize;
#if MBEDTLS_VERSION_NUMBER >= 0x02060000 && MBEDTLS_VERSION_NUMBER < 0x03000000
    size_t keylen = context->len;
#else
    size_t keylen = mbedtls_rsa_get_len(context);
#endif

    UA_ByteString encrypted;
    UA_StatusCode retval = UA_ByteString_allocBuffer(&encrypted, max_blocks * keylen);
    if(retval != UA_STATUSCODE_GOOD)
        return retval;

    size_t lenDataToEncrypt = data->length;
    size_t inOffset = 0;
    size_t offset = 0;
    const unsigned char *label = NULL;
    while(lenDataToEncrypt >= plainTextBlockSize) {
#if MBEDTLS_VERSION_NUMBER >= 0x02060000 && MBEDTLS_VERSION_NUMBER < 0x03000000
        int mbedErr = mbedtls_rsa_rsaes_oaep_encrypt(context, mbedtls_ctr_drbg_random,
                                                     drbgContext, MBEDTLS_RSA_PUBLIC,
                                                     label, 0, plainTextBlockSize,
                                                     data->data + inOffset, encrypted.data + offset);
#else
        int mbedErr = mbedtls_rsa_rsaes_oaep_encrypt(context, mbedtls_ctr_drbg_random,
                                                     drbgContext, label, 0, plainTextBlockSize,
                                                     data->data + inOffset, encrypted.data + offset);
#endif

        if(mbedErr) {
            UA_ByteString_clear(&encrypted);
            return UA_STATUSCODE_BADINTERNALERROR;
        }

        inOffset += plainTextBlockSize;
        offset += keylen;
        lenDataToEncrypt -= plainTextBlockSize;
    }

    memcpy(data->data, encrypted.data, offset);
    UA_ByteString_clear(&encrypted);
    return UA_STATUSCODE_GOOD;
}

UA_StatusCode
mbedtls_decrypt_rsaOaep(mbedtls_pk_context *localPrivateKey,
                        mbedtls_ctr_drbg_context *drbgContext,
                        UA_ByteString *data, int hash_id) {
    mbedtls_rsa_context *rsaContext = mbedtls_pk_rsa(*localPrivateKey);
#if MBEDTLS_VERSION_NUMBER >= 0x02060000 && MBEDTLS_VERSION_NUMBER < 0x03000000
    mbedtls_rsa_set_padding(rsaContext, MBEDTLS_RSA_PKCS_V21, hash_id);
    size_t keylen = rsaContext->len;
#else
    mbedtls_rsa_set_padding(rsaContext, MBEDTLS_RSA_PKCS_V21, (mbedtls_md_type_t)hash_id);
    size_t keylen = mbedtls_rsa_get_len(rsaContext);
#endif
    if(data->length % keylen != 0)
        return UA_STATUSCODE_BADINTERNALERROR;

    size_t inOffset = 0;
    size_t outOffset = 0;
    size_t outLength = 0;
    unsigned char buf[512];

    while(inOffset < data->length) {
#if MBEDTLS_VERSION_NUMBER >= 0x02060000 && MBEDTLS_VERSION_NUMBER < 0x03000000
        int mbedErr = mbedtls_rsa_rsaes_oaep_decrypt(rsaContext, mbedtls_ctr_drbg_random,
                                                     drbgContext, MBEDTLS_RSA_PRIVATE,
                                                     NULL, 0, &outLength,
                                                     data->data + inOffset,
                                                     buf, 512);
#else
        int mbedErr = mbedtls_rsa_rsaes_oaep_decrypt(rsaContext, mbedtls_ctr_drbg_random,
                                                     drbgContext,
                                                     NULL, 0, &outLength,
                                                     data->data + inOffset,
                                                     buf, 512);
#endif

        if(mbedErr)
            return UA_STATUSCODE_BADSECURITYCHECKSFAILED;

        memcpy(data->data + outOffset, buf, outLength);
        inOffset += keylen;
        outOffset += outLength;
    }

    data->length = outOffset;
    return UA_STATUSCODE_GOOD;
}

static size_t
mbedtls_getSequenceListDeep(const mbedtls_x509_sequence *sanlist) {
    size_t ret = 0;
    const mbedtls_x509_sequence *cur = sanlist;
    while(cur) {
        ret++;
        cur = cur->next;
    }

    return ret;
}

static UA_StatusCode
mbedtls_x509write_csrSetSubjectAltName(mbedtls_x509write_csr *ctx, const mbedtls_x509_sequence* sanlist) {
    int	ret = 0;
    const mbedtls_x509_sequence* cur = sanlist;
    unsigned char *buf;
    unsigned char *pc;
    size_t len = 0;

    
    size_t sandeep = mbedtls_getSequenceListDeep(sanlist);
    if(sandeep == 0)
        return UA_STATUSCODE_GOOD;

    size_t buflen = MBEDTLS_SAN_MAX_LEN * sandeep + sandeep;
    buf = (unsigned char *)mbedtls_calloc(1, buflen);
    if(!buf)
        return MBEDTLS_ERR_ASN1_ALLOC_FAILED;

    memset(buf, 0, buflen);
    pc = buf + buflen;

    while(cur) {
        switch (cur->buf.tag & 0x0F) {
            case MBEDTLS_X509_SAN_DNS_NAME:
            case MBEDTLS_X509_SAN_RFC822_NAME:
            case MBEDTLS_X509_SAN_UNIFORM_RESOURCE_IDENTIFIER:
            case MBEDTLS_X509_SAN_IP_ADDRESS: {
                const int writtenBytes = mbedtls_asn1_write_raw_buffer(
                    &pc, buf, (const unsigned char *)cur->buf.p, cur->buf.len);
                MBEDTLS_ASN1_CHK_CLEANUP_ADD(len, writtenBytes);
                MBEDTLS_ASN1_CHK_CLEANUP_ADD(len, mbedtls_asn1_write_len(&pc, buf, cur->buf.len));
                MBEDTLS_ASN1_CHK_CLEANUP_ADD(len, mbedtls_asn1_write_tag(&pc, buf,
                                                                         MBEDTLS_ASN1_CONTEXT_SPECIFIC | cur->buf.tag));
                break;
            }
            default:
                
                ret = MBEDTLS_ERR_X509_FEATURE_UNAVAILABLE;
                goto cleanup;
        }
        cur = cur->next;
    }

    MBEDTLS_ASN1_CHK_CLEANUP_ADD(len, mbedtls_asn1_write_len(&pc, buf, len));
    MBEDTLS_ASN1_CHK_CLEANUP_ADD(len, mbedtls_asn1_write_tag(&pc, buf, MBEDTLS_ASN1_CONSTRUCTED | MBEDTLS_ASN1_SEQUENCE));

#if MBEDTLS_VERSION_NUMBER < 0x03000000
    ret = mbedtls_x509write_csr_set_extension(ctx, MBEDTLS_OID_SUBJECT_ALT_NAME,
                                              MBEDTLS_OID_SIZE(MBEDTLS_OID_SUBJECT_ALT_NAME), (const unsigned char*)(buf + buflen - len), len);
#else
    ret = mbedtls_x509write_csr_set_extension(ctx, MBEDTLS_OID_SUBJECT_ALT_NAME,
                                              MBEDTLS_OID_SIZE(MBEDTLS_OID_SUBJECT_ALT_NAME), 0, (const unsigned char*)(buf + buflen - len), len);
#endif

cleanup:
    mbedtls_free(buf);
    return (ret == 0) ? UA_STATUSCODE_GOOD : UA_STATUSCODE_BADINTERNALERROR;
}

static UA_StatusCode
mbedtls_writePrivateKeyDer(mbedtls_pk_context *key, UA_ByteString *outPrivateKey) {
    unsigned char output_buf[16000];
    unsigned char *c = NULL;

    memset(output_buf, 0, 16000);
    const int len = mbedtls_pk_write_key_der(key, output_buf, 16000);
    if(len < 0)
        return UA_STATUSCODE_BADINTERNALERROR;

    c = output_buf + sizeof(output_buf) - len;

    if(UA_ByteString_allocBuffer(outPrivateKey, len) != UA_STATUSCODE_GOOD)
        return UA_STATUSCODE_BADOUTOFMEMORY;
    outPrivateKey->length = len;
    memcpy(outPrivateKey->data, c, outPrivateKey->length);

    return UA_STATUSCODE_GOOD;
}

UA_StatusCode
mbedtls_createSigningRequest(mbedtls_pk_context *localPrivateKey,
                             mbedtls_pk_context *csrLocalPrivateKey,
                             mbedtls_entropy_context *entropyContext,
                             mbedtls_ctr_drbg_context *drbgContext,
                             UA_SecurityPolicy *securityPolicy,
                             const UA_String *subjectName,
                             const UA_ByteString *nonce,
                             UA_ByteString *csr,
                             UA_ByteString *newPrivateKey) {
    
    if(!securityPolicy || !csr || !localPrivateKey || !csrLocalPrivateKey) {
        return UA_STATUSCODE_BADINVALIDARGUMENT;
    }

    UA_StatusCode retval = UA_STATUSCODE_GOOD;
    size_t ret = 0;
    char *subj = NULL;
    const mbedtls_x509_sequence *san_list = NULL;

    mbedtls_pk_free(csrLocalPrivateKey);

    if(newPrivateKey && newPrivateKey->length > 0) {
        mbedtls_pk_init(csrLocalPrivateKey);
        mbedtls_pk_setup(csrLocalPrivateKey, mbedtls_pk_info_from_type(MBEDTLS_PK_RSA));

        
        if(UA_mbedTLS_LoadPrivateKey(newPrivateKey, csrLocalPrivateKey, entropyContext))
            return UA_STATUSCODE_BADSECURITYCHECKSFAILED;

        return UA_STATUSCODE_GOOD;
    }

    
    if(csr && csr->length > 0)
        return UA_STATUSCODE_GOOD;

    
    mbedtls_x509_crt x509Cert;
    mbedtls_x509_crt_init(&x509Cert);
    UA_ByteString certificateStr = UA_mbedTLS_CopyDataFormatAware(&securityPolicy->localCertificate);
    ret = mbedtls_x509_crt_parse(&x509Cert, certificateStr.data, certificateStr.length);
    UA_ByteString_clear(&certificateStr);
    if(ret)
        return UA_STATUSCODE_BADCERTIFICATEINVALID;

    mbedtls_x509write_csr request;
    mbedtls_x509write_csr_init(&request);
    
    mbedtls_x509write_csr_set_md_alg(&request, MBEDTLS_MD_SHA256);

    
    if(mbedtls_x509write_csr_set_key_usage(&request, MBEDTLS_X509_KU_DIGITAL_SIGNATURE |
                                                     MBEDTLS_X509_KU_DATA_ENCIPHERMENT |
                                                     MBEDTLS_X509_KU_NON_REPUDIATION |
                                                     MBEDTLS_X509_KU_KEY_ENCIPHERMENT) != 0) {
        retval = UA_STATUSCODE_BADINTERNALERROR;
        goto cleanup;
    }

    
    UA_Boolean hasEntropy = entropyContext && nonce && nonce->length > 0;
    if(hasEntropy) {
        if(mbedtls_entropy_update_manual(entropyContext,
                                         (const unsigned char*)(nonce->data),
                                         nonce->length) != 0) {
            retval = UA_STATUSCODE_BADINTERNALERROR;
            goto cleanup;
        }
    }

    
    if(subjectName && subjectName->length > 0) {
        
        subj = (char *)UA_malloc(subjectName->length + 1);
        if(!subj) {
            retval = UA_STATUSCODE_BADOUTOFMEMORY;
            goto cleanup;
        }
        memset(subj, 0x00, subjectName->length + 1);
        strncpy(subj, (char *)subjectName->data, subjectName->length);
        
        char *p = subj;
        for(size_t i = 0; i < subjectName->length; i++) {
            if(*p == '/' ) {
                *p = ',';
            }
            ++p;
        }
    } else {
        
        mbedtls_x509_name s = x509Cert.subject;
        subj = (char *)UA_malloc(UA_MAXSUBJECTLENGTH);
        if(!subj) {
            retval = UA_STATUSCODE_BADOUTOFMEMORY;
            goto cleanup;
        }
        if(mbedtls_x509_dn_gets(subj, UA_MAXSUBJECTLENGTH, &s) <= 0) {
            retval = UA_STATUSCODE_BADINTERNALERROR;
            goto cleanup;
        }
    }

    
    if(mbedtls_x509write_csr_set_subject_name(&request, subj) != 0) {
        retval = UA_STATUSCODE_BADINTERNALERROR;
        goto cleanup;
    }

    
    san_list = &x509Cert.subject_alt_names;
    mbedtls_x509write_csrSetSubjectAltName(&request, san_list);

    
    if(newPrivateKey) {
        mbedtls_pk_init(csrLocalPrivateKey);
        mbedtls_pk_setup(csrLocalPrivateKey, mbedtls_pk_info_from_type(MBEDTLS_PK_RSA));

        size_t keySize = 0;
        UA_CertificateUtils_getKeySize(&securityPolicy->localCertificate, &keySize);
        mbedtls_rsa_gen_key(mbedtls_pk_rsa(*csrLocalPrivateKey), mbedtls_ctr_drbg_random,
                            drbgContext, (unsigned int)keySize, 65537);
        mbedtls_x509write_csr_set_key(&request, csrLocalPrivateKey);
        mbedtls_writePrivateKeyDer(csrLocalPrivateKey, newPrivateKey);
    } else {
        mbedtls_x509write_csr_set_key(&request, localPrivateKey);
    }


    unsigned char requestBuf[CSR_BUFFER_SIZE];
    memset(requestBuf, 0, sizeof(requestBuf));
    ret = mbedtls_x509write_csr_der(&request, requestBuf, sizeof(requestBuf),
                                    mbedtls_ctr_drbg_random, drbgContext);
    if(ret <= 0) {
        retval = UA_STATUSCODE_BADINTERNALERROR;
        goto cleanup;
    }

    
    size_t byteCount = ret;
    size_t offset = sizeof(requestBuf) - byteCount;

    
    UA_ByteString_init(csr);
    UA_ByteString_allocBuffer(csr, byteCount);
    memcpy(csr->data, requestBuf + offset, byteCount);

cleanup:
    mbedtls_x509_crt_free(&x509Cert);
    mbedtls_x509write_csr_free(&request);
    if(subj)
        UA_free(subj);

    return retval;
}

int
UA_mbedTLS_LoadPrivateKey(const UA_ByteString *key, mbedtls_pk_context *target, void *p_rng) {
    UA_ByteString data = UA_mbedTLS_CopyDataFormatAware(key);
#if MBEDTLS_VERSION_NUMBER >= 0x02060000 && MBEDTLS_VERSION_NUMBER < 0x03000000
    int mbedErr = mbedtls_pk_parse_key(target, data.data, data.length, NULL, 0);
#else
    int mbedErr = mbedtls_pk_parse_key(target, data.data, data.length, NULL, 0, mbedtls_entropy_func, p_rng);
#endif
    UA_ByteString_clear(&data);
    return mbedErr;
}

UA_StatusCode
UA_mbedTLS_LoadLocalCertificate(const UA_ByteString *certData,
                                UA_ByteString *target) {
    UA_ByteString data = UA_mbedTLS_CopyDataFormatAware(certData);

    mbedtls_x509_crt cert;
    mbedtls_x509_crt_init(&cert);

    int mbedErr = mbedtls_x509_crt_parse(&cert, data.data, data.length);

    UA_StatusCode result = UA_STATUSCODE_BADINVALIDARGUMENT;

    if (!mbedErr) {
        UA_ByteString tmp;
        tmp.data = cert.raw.p;
        tmp.length = cert.raw.len;

        result = UA_ByteString_copy(&tmp, target);
    } else {
        UA_ByteString_init(target);
    }

    UA_ByteString_clear(&data);
    mbedtls_x509_crt_free(&cert);
    return result;
}

// mbedTLS expects PEM data to be null terminated
// The data length parameter must include the null terminator
UA_ByteString
UA_mbedTLS_CopyDataFormatAware(const UA_ByteString *data) {
    UA_ByteString result;
    UA_ByteString_init(&result);

    if (!data->length)
        return result;

    if (data->length && data->data[0] == '-') {
        UA_ByteString_allocBuffer(&result, data->length + 1);
        memcpy(result.data, data->data, data->length);
        result.data[data->length] = '\0';
    } else {
        UA_ByteString_copy(data, &result);
    }

    return result;
}

#endif
