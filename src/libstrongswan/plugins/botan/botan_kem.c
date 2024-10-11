/*
 * Copyright (C) 2024 Tobias Brunner, codelabs GmbH
 *
 * Permission is hereby granted, free of charge, to any person obtaining a copy
 * of this software and associated documentation files (the "Software"), to deal
 * in the Software without restriction, including without limitation the rights
 * to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
 * copies of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included in
 * all copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
 * OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
 * THE SOFTWARE.
 */

#include "botan_kdf.h"
#include "botan_util.h"

#include <botan/build.h>

#if defined(BOTAN_HAS_ML_KEM) || defined (BOTAN_HAS_FRODOKEM)

#include <asn1/asn1.h>

#include <botan/ffi.h>

/**
 * Length of the private key seed (d || z).
 */
#define ML_KEM_SEED_LEN 64

/**
 * Length of the shared secret.
 */
#define ML_KEM_SHARED_LEN 32

/**
 * Length of the shared secrets in FrodoKEM, which is also used during key
 * generation while testing as seeds s and seedSE have the same length as the
 * shared secret in the ephemeral versions of FrodoKEM.
 */
#define FRODO_L1_SECRET_LEN 16
#define FRODO_L3_SECRET_LEN 24
#define FRODO_L5_SECRET_LEN 32

/**
 * Length of seed z/seed A used to generate matrix A when creating a key pair.
 */
#define FRODO_SEED_A_LEN    16

typedef struct private_key_exchange_t private_key_exchange_t;

/**
 * Private data.
 */
struct private_key_exchange_t {

	/**
	 * Public interface.
	 */
	key_exchange_t public;

	/**
	 * KE method.
	 */
	key_exchange_method_t method;

	/**
	 * Internal algorithm name.
	 */
	char *name;

	/**
	 * Key pair as initiator.
	 */
	botan_privkey_t kem;

	/**
	 * Ciphertext as responder.
	 */
	chunk_t ciphertext;

	/**
	 * Shared secret.
	 */
	chunk_t shared_secret;

	/**
	 * DRBG for testing.
	 */
	drbg_t *drbg;
};

/**
 * Check if the algorithm is ML-KEM.
 */
static bool is_ml_kem(private_key_exchange_t *this)
{
	switch (this->method)
	{
		case ML_KEM_512:
		case ML_KEM_768:
		case ML_KEM_1024:
			return TRUE;
		default:
			return FALSE;
	}
}

/**
 * Determine the length of the shared secret for the given KEM.
 */
static size_t get_shared_secret_len(private_key_exchange_t *this)
{
	switch (this->method)
	{
		case ML_KEM_512:
		case ML_KEM_768:
		case ML_KEM_1024:
			return ML_KEM_SHARED_LEN;
		case KE_FRODO_AES_L1:
		case KE_FRODO_SHAKE_L1:
			return FRODO_L1_SECRET_LEN;
		case KE_FRODO_AES_L3:
		case KE_FRODO_SHAKE_L3:
			return FRODO_L3_SECRET_LEN;
		case KE_FRODO_AES_L5:
		case KE_FRODO_SHAKE_L5:
			return FRODO_L5_SECRET_LEN;
		default:
			return 0;
	}
}

/**
 * Determine the length of the seed for the given KEM during testing.
 */
static size_t get_seed_len(private_key_exchange_t *this)
{
	if (is_ml_kem(this))
	{
		/* d || z */
		return ML_KEM_SEED_LEN;
	}
	/* s // seedSE // z */
	return 2 * get_shared_secret_len(this) + FRODO_SEED_A_LEN;
}

CALLBACK(get_random, int,
	drbg_t *drbg, uint8_t *out, size_t out_len)
{
	if (!drbg->generate(drbg, out_len, out))
	{
		return -1;
	}
	return 0;
}

/**
 * Initializes the given RNG, either based on a DRBG during testing or using
 * the plugin's configured RNG.
 */
static bool get_rng(private_key_exchange_t *this, botan_rng_t *rng)
{
	if (this->drbg)
	{
		return !botan_rng_init_custom(rng, "kem-drbg", this->drbg,
									  get_random, NULL, NULL);
	}
	return botan_get_rng(rng, RNG_STRONG);
}

/**
 * Convert the given "view" to a chunk.
 */
CALLBACK(botan_view_to_chunk, int,
	chunk_t *chunk, const uint8_t *data, size_t len)
{
	*chunk = chunk_clone(chunk_create((u_char*)data, len));
	return 0;
}

#ifdef BOTAN_HAS_FRODOKEM

/**
 * Determine the OID used for a specific FrodoKEM variant.
 */
static char *get_oid(private_key_exchange_t *this)
{
	switch (this->method)
	{
		case KE_FRODO_AES_L1:
			return "1.3.6.1.4.1.25258.1.17.1";
		case KE_FRODO_AES_L3:
			return "1.3.6.1.4.1.25258.1.17.2";
		case KE_FRODO_AES_L5:
			return "1.3.6.1.4.1.25258.1.17.3";
		case KE_FRODO_SHAKE_L1:
			return "1.3.6.1.4.1.25258.1.16.1";
		case KE_FRODO_SHAKE_L3:
			return "1.3.6.1.4.1.25258.1.16.2";
		case KE_FRODO_SHAKE_L5:
			return "1.3.6.1.4.1.25258.1.16.3";
		default:
			return NULL;
	}
}

/**
 * Data for an RNG that serves static data for testing.
 */
typedef struct {
	/** Random data to serve. */
	chunk_t random;
	/** Offset into the data already served. */
	size_t offset;
} static_rng_t;

CALLBACK(get_random_static, int,
	static_rng_t *rng, uint8_t *out, size_t out_len)
{
	if (rng->offset + out_len <= rng->random.len)
	{
		memcpy(out, rng->random.ptr + rng->offset, out_len);
		rng->offset += out_len;
		return 0;
	}
	return -1;
}

/**
 * Initializes the given RNG as a static RNG.
 */
static bool get_static_rng(static_rng_t *source, botan_rng_t *rng)
{
	return !botan_rng_init_custom(rng, "kem-static-rng", source,
								  get_random_static, NULL, NULL);
}

#endif /* BOTAN_HAS_FRODOKEM */

/**
 * Load/create a key pair during testing.
 */
static bool create_test_keypair(private_key_exchange_t *this)
{
	uint8_t random[get_seed_len(this)];

	if (!this->drbg->generate(this->drbg, sizeof(random), random))
	{
		return FALSE;
	}

#ifdef BOTAN_HAS_ML_KEM
	if (is_ml_kem(this))
	{
		/* during testing, we load the DRBG-generated seed (d || z) as private
		 * key, as Botan would otherwise pull these separately from the RNG */
		if (botan_privkey_load_ml_kem(&this->kem, random, sizeof(random),
									  this->name))
		{
			return FALSE;
		}
	}
	else
#endif
#ifdef BOTAN_HAS_FRODOKEM
	{
		botan_rng_t rng = NULL;
		static_rng_t static_rng = {
			.random = chunk_create(random, sizeof(random)),
		};

		/* FIXME: there is currently no function to load a FrodoKEM private key
		 * via seed values (the PKCS#8 format Botan uses the format described
		 * in the spec, i.e. s // seedA // b // ST // pkh, most of which are
		 * derived from the seeds), and since Botan pulls the seeds in separate
		 * calls, which doesn't match our vectors, we preallocate them */
		if (!get_static_rng(&static_rng, &rng) ||
			botan_privkey_create(&this->kem, "FrodoKEM", this->name, rng))
		{
			botan_rng_destroy(rng);
			return FALSE;
		}
		botan_rng_destroy(rng);
	}
#endif
	return TRUE;
}

/**
 * Generate a key pair as initiator.
 */
static bool generate_keypair(private_key_exchange_t *this)
{
	botan_rng_t rng = NULL;

	if (this->drbg)
	{
		return create_test_keypair(this);
	}

	if (!botan_get_rng(&rng, RNG_STRONG) ||
		botan_privkey_create(&this->kem, "ML-KEM", this->name, rng))
	{
		botan_rng_destroy(rng);
		return FALSE;
	}
	botan_rng_destroy(rng);
	return TRUE;
}

/**
 * Export the public key of the generated key pair as initiator.
 */
static bool export_pubkey(private_key_exchange_t *this, chunk_t *public)
{
	botan_pubkey_t pubkey = NULL;

	if (!this->kem && !generate_keypair(this))
	{
		DBG1(DBG_LIB, "%N key pair generation failed",
			 key_exchange_method_names, this->method);
		return FALSE;
	}

#ifdef BOTAN_HAS_FRODOKEM
	if (!is_ml_kem(this))
	{
		chunk_t encoded, unwrap, inner;

		/* FIXME: there is currently no way to get the raw public key, so we
		 * have to unwrap the DER encoded key (at least that's just the raw
		 * key bits we need) */
		if (botan_privkey_export_pubkey(&pubkey, this->kem) ||
			botan_pubkey_view_der(pubkey, &encoded, botan_view_to_chunk))
		{
			DBG1(DBG_LIB, "%N public key encoding failed",
					 key_exchange_method_names, this->method);
			botan_pubkey_destroy(pubkey);
			return FALSE;
		}
		botan_pubkey_destroy(pubkey);
		unwrap = encoded;
		if (asn1_unwrap(&unwrap, &unwrap) == ASN1_SEQUENCE &&
			asn1_unwrap(&unwrap, &inner) == ASN1_SEQUENCE &&
			asn1_unwrap(&unwrap, &inner) == ASN1_BIT_STRING)
		{
			*public = chunk_clone(chunk_skip(inner, 1));
			chunk_free(&encoded);
			return TRUE;
		}
		chunk_free(&encoded);
		return FALSE;
	}
#endif
#ifdef BOTAN_HAS_ML_KEM
	if (botan_privkey_export_pubkey(&pubkey, this->kem) ||
		botan_pubkey_view_ml_kem_raw_key(pubkey, public, botan_view_to_chunk))
	{
		DBG1(DBG_LIB, "%N public key encoding failed",
				 key_exchange_method_names, this->method);
		botan_pubkey_destroy(pubkey);
		return FALSE;
	}
	botan_pubkey_destroy(pubkey);
	return TRUE;
#else
	return FALSE;
#endif
}

METHOD(key_exchange_t, get_public_key, bool,
	private_key_exchange_t *this, chunk_t *value)
{
	/* as responder, this method is called after set_public_key(), which
	 * encapsulated the secret to produce this ciphertext */
	if (this->ciphertext.len)
	{
		*value = chunk_clone(this->ciphertext);
		return TRUE;
	}

	/* as initiator, we generate a key pair and return the public key */
	return export_pubkey(this, value);
}

/**
 * Decapsulate the shared secret from the given ciphertext using our key pair.
 */
static bool decaps_ciphertext(private_key_exchange_t *this, chunk_t ciphertext)
{
	botan_pk_op_kem_decrypt_t op;

	if (botan_pk_op_kem_decrypt_create(&op, this->kem, "Raw"))
	{
		return FALSE;
	}
	this->shared_secret = chunk_alloc(ML_KEM_SHARED_LEN);

	if (botan_pk_op_kem_decrypt_shared_key(op, NULL, 0, ciphertext.ptr,
							ciphertext.len, this->shared_secret.len,
							this->shared_secret.ptr, &this->shared_secret.len))
	{
		DBG1(DBG_LIB, "%N decapsulation failed",
			 key_exchange_method_names, this->method);
		botan_pk_op_kem_decrypt_destroy(op);
		return FALSE;
	}
	botan_pk_op_kem_decrypt_destroy(op);
	return TRUE;
}

/**
 * Generate a shared secret an encapsulate it using the given public key.
 */
static bool encaps_shared_secret(private_key_exchange_t *this, chunk_t public)
{
	botan_pk_op_kem_encrypt_t op;
	botan_pubkey_t kem;
	botan_rng_t rng;
	size_t len;

#ifdef BOTAN_HAS_FRODOKEM
	if (!is_ml_kem(this))
	{
		chunk_t encoding;

		/* FIXME: there is currently no way to load raw FrodoKEM public keys,
		 * so we have to DER-encode them with a matching OID */
		encoding = asn1_wrap(ASN1_SEQUENCE, "mm",
							asn1_wrap(ASN1_SEQUENCE, "m",
								asn1_wrap(ASN1_OID, "m",
									asn1_oid_from_string(get_oid(this)))),
							asn1_bitstring("c", public));

		if (botan_pubkey_load(&kem, encoding.ptr, encoding.len))
		{
			DBG1(DBG_LIB, "%N public key invalid",
			 key_exchange_method_names, this->method);
			chunk_free(&encoding);
			return FALSE;
		}
		chunk_free(&encoding);
	}
	else
#endif
#ifdef BOTAN_HAS_ML_KEM
	if (botan_pubkey_load_ml_kem(&kem, public.ptr, public.len, this->name))
	{
		DBG1(DBG_LIB, "%N public key invalid",
			 key_exchange_method_names, this->method);
		return FALSE;
	}
#else
	return FALSE;
#endif
	if (botan_pk_op_kem_encrypt_create(&op, kem, "Raw"))
	{
		botan_pubkey_destroy(kem);
		return FALSE;
	}
	if (botan_pk_op_kem_encrypt_encapsulated_key_length(op, &len) ||
		!get_rng(this, &rng))
	{
		botan_pk_op_kem_encrypt_destroy(op);
		botan_pubkey_destroy(kem);
		return FALSE;
	}
	this->ciphertext = chunk_alloc(len);
	this->shared_secret = chunk_alloc(ML_KEM_SHARED_LEN);

	if (botan_pk_op_kem_encrypt_create_shared_key(op, rng, NULL, 0,
							this->shared_secret.len,
							this->shared_secret.ptr, &this->shared_secret.len,
							this->ciphertext.ptr, &this->ciphertext.len))
	{
		DBG1(DBG_LIB, "%N encapsulation failed",
			 key_exchange_method_names, this->method);
		botan_pk_op_kem_encrypt_destroy(op);
		botan_pubkey_destroy(kem);
		botan_rng_destroy(rng);
		return FALSE;
	}
	botan_pk_op_kem_encrypt_destroy(op);
	botan_pubkey_destroy(kem);
	botan_rng_destroy(rng);
	return TRUE;
}

METHOD(key_exchange_t, set_public_key, bool,
	private_key_exchange_t *this, chunk_t value)
{
	/* as initiator, we decapsulate the secret from the given ciphertext */
	if (this->kem)
	{
		return decaps_ciphertext(this, value);
	}

	/* as responder, we generate a secret and encapsulate it */
	return encaps_shared_secret(this, value);
}

METHOD(key_exchange_t, get_shared_secret, bool,
	private_key_exchange_t *this, chunk_t *secret)
{
	*secret = chunk_clone(this->shared_secret);
	return TRUE;
}

METHOD(key_exchange_t, get_method, key_exchange_method_t,
	private_key_exchange_t *this)
{
	return this->method;
}

METHOD(key_exchange_t, set_seed, bool,
	private_key_exchange_t *this, chunk_t value, drbg_t *drbg)
{
	if (!drbg)
	{
		return FALSE;
	}
	DESTROY_IF(this->drbg);
	this->drbg = drbg->get_ref(drbg);
	return TRUE;
}

METHOD(key_exchange_t, destroy, void,
	private_key_exchange_t *this)
{
	chunk_clear(&this->shared_secret);
	chunk_free(&this->ciphertext);
	botan_privkey_destroy(this->kem);
	DESTROY_IF(this->drbg);
	free(this->name);
	free(this);
}

/*
 * Described in header
 */
key_exchange_t *botan_kem_create(key_exchange_method_t method)
{
	private_key_exchange_t *this;
	char *name;

	switch (method)
	{
		case ML_KEM_512:
			name = "ML-KEM-512";
			break;
		case ML_KEM_768:
			name = "ML-KEM-768";
			break;
		case ML_KEM_1024:
			name = "ML-KEM-1024";
			break;
		case KE_FRODO_AES_L1:
			name = "eFrodoKEM-640-AES";
			break;
		case KE_FRODO_AES_L3:
			name = "eFrodoKEM-976-AES";
			break;
		case KE_FRODO_AES_L5:
			name = "eFrodoKEM-1344-AES";
			break;
		case KE_FRODO_SHAKE_L1:
			name = "eFrodoKEM-640-SHAKE";
			break;
		case KE_FRODO_SHAKE_L3:
			name = "eFrodoKEM-976-SHAKE";
			break;
		case KE_FRODO_SHAKE_L5:
			name = "eFrodoKEM-1344-SHAKE";
			break;
		default:
			return NULL;
	}

	INIT(this,
		.public = {
			.get_method = _get_method,
			.get_public_key = _get_public_key,
			.set_public_key = _set_public_key,
			.get_shared_secret = _get_shared_secret,
			.set_seed = _set_seed,
			.destroy = _destroy,
		},
		.method = method,
		.name = strdup(name),
	);
	return &this->public;
}

#endif /* BOTAN_HAS_ML_KEM */
