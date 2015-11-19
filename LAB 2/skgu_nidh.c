#include "skgu.h"

#define DEFAULT_LABEL "skgu_key"

struct rawpub {
  mpz_t p;			/* Prime */
  mpz_t q;			/* Order */
  mpz_t g;			/* Element of given order */
  mpz_t y;			/* g^x mod p */
};
typedef struct rawpub rawpub;

struct rawpriv {
  mpz_t p;			/* Prime */
  mpz_t q;			/* Order */
  mpz_t g;			/* Element of given order */
  mpz_t x;			/* x mod q */
};
typedef struct rawpriv rawpriv;

int 
get_rawpub (rawpub *rpub_ptr, dckey *pub) {
  const char *pub_as_str = (const char *) dcexport (pub);

  if (skip_str (&pub_as_str, ELGAMAL_STR)
      || skip_str (&pub_as_str, ":Pub,p="))
    return -1;

  mpz_init (rpub_ptr->p);
  mpz_init (rpub_ptr->q);
  mpz_init (rpub_ptr->g);
  mpz_init (rpub_ptr->y);

  if (read_mpz (&pub_as_str, rpub_ptr->p)
      || skip_str (&pub_as_str, ",q=")
      || read_mpz (&pub_as_str, rpub_ptr->q)
      || skip_str (&pub_as_str, ",g=")
      || read_mpz (&pub_as_str, rpub_ptr->g)
      || skip_str (&pub_as_str, ",y=")
      || read_mpz (&pub_as_str, rpub_ptr->y)) {
    return -1;
  }

  return 0;
}

int 
get_rawpriv (rawpriv *rpriv_ptr, dckey *priv) {
  const char *priv_as_str = (const char *) dcexport (priv);

  if (skip_str (&priv_as_str, ELGAMAL_STR)
      || skip_str (&priv_as_str, ":Priv,p="))
    return -1;

  mpz_init (rpriv_ptr->p);
  mpz_init (rpriv_ptr->q);
  mpz_init (rpriv_ptr->g);
  mpz_init (rpriv_ptr->x);

  if (read_mpz (&priv_as_str, rpriv_ptr->p)
      || skip_str (&priv_as_str, ",q=")
      || read_mpz (&priv_as_str, rpriv_ptr->q)
      || skip_str (&priv_as_str, ",g=")
      || read_mpz (&priv_as_str, rpriv_ptr->g)
      || skip_str (&priv_as_str, ",x=")
      || read_mpz (&priv_as_str, rpriv_ptr->x)) {
    return -1;
  }

  return 0;
}

void 
usage (const char *pname)
{
  printf ("Simple Shared-Key Generation Utility\n");
  printf ("Usage: %s PRIV-FILE PRIV-CERT PRIV-ID PUB-FILE PUB-CERT PUB-ID [LABEL]\n", pname);
  exit (-1);
}

void
nidh (dckey *priv, dckey *pub, char *priv_id, char *pub_id, char *label)
{
  rawpub rpub;
  rawpriv rpriv;

  /* YOUR VARS HERE */
  int status, fdsk;
  char* buffer = NULL;
  char* dstp = NULL;
  char* fp = NULL;
  char* key_master = NULL;
  char* key_share = NULL;
  char* key_share0 = NULL;
  char* key_share1 = NULL;
  char* key_share_base64 = NULL;
  char* key_share_buffer0 = NULL;
  char* key_share_buffer1 = NULL;
  mpz_t dh_secret;
  
  /* step 0: check that the private and public keys are compatible,
     i.e., they use the same group parameters */

  if ((-1 == get_rawpub (&rpub, pub)) 
      || (-1 == get_rawpriv (&rpriv, priv))) {
    printf ("%s: trouble importing GMP values from ElGamal-like keys\n",
	    getprogname ());

    printf ("priv:\n%s\n", dcexport_priv (priv));
    printf ("pub:\n%s\n", dcexport_pub (pub));

    exit (-1);    
  } else if (mpz_cmp (rpub.p, rpriv.p)
	     || mpz_cmp (rpub.q, rpriv.q)
	     || mpz_cmp (rpub.g, rpriv.g)) {
    printf ("%s:  the private and public keys are incompatible\n",
	    getprogname ());
    
    printf ("priv:\n%s\n", dcexport_priv (priv));
    printf ("pub:\n%s\n", dcexport_pub (pub));

    exit (-1);
  } else {
    
    /* step 1a: compute the Diffie-Hellman secret
                (use mpz_init, mpz_powm, mpz_clear; look at elgamal.c in 
                 the libdcrypt source directory for sample usage 
     */
    
    /* YOUR CODE HERE */
    mpz_init(dh_secret);
    mpz_powm(dh_secret, rpub.y, rpriv.x, rpub.p);
    status = cat_mpz(&dstp, dh_secret);
    if(status != 0)
    {
	printf("trouble arose when allocating space!\n");
	mpz_clear(dh_secret); dstp = NULL; exit(-1);
    }
    
    /* step 1b: order the IDs lexicographically */
    char *fst_id = NULL, *snd_id = NULL;
    
    if (strcmp (priv_id, pub_id) < 0) {
      fst_id = priv_id;
      snd_id = pub_id;
    } else {
      fst_id = pub_id;
      snd_id = priv_id;
    }    
    
    /* step 1c: hash DH secret and ordered id pair into a master key */
    /* YOUR CODE HERE */
    key_master = (char*)malloc(20 * sizeof(char));
    buffer = (char*)malloc((strlen(dstp) + strlen(fst_id) + strlen(snd_id) + 1) * sizeof(char));
    strcpy(buffer, dstp);
    strcat(buffer, fst_id);
    strcat(buffer, snd_id);
    sha1_hash(key_master, buffer, strlen(buffer));

    /* step 2: derive the shared key from the label and the master key */    
    /* YOUR CODE HERE */
    key_share_buffer0 = (char*)malloc((strlen(label) + strlen("AES-CTR") + 1) * sizeof(char));
    strcpy(key_share_buffer0, label);
    strcat(key_share_buffer0, "AES-CTR");    
    key_share0 = (char*)malloc(20 * sizeof(char));
    hmac_sha1(key_master, 20, key_share0, key_share_buffer0, strlen(key_share_buffer0)); 
    free(key_share_buffer0);
    
    key_share_buffer1 = (char*)malloc((strlen(label) + strlen("CBC-MAC") + 1) * sizeof(char));
    strcpy(key_share_buffer1, label);
    strcat(key_share_buffer1, "CBC-MAC");     
    key_share1 = (char*)malloc(20 * sizeof(char));
    hmac_sha1(key_master, 20, key_share1, key_share_buffer1, strlen(key_share_buffer1));
    free(key_share_buffer1);

    key_share = (char*)malloc(32 * sizeof(char) + sizeof(char));
    strncpy(key_share, key_share0, 16);
    strncat(key_share, key_share1, 16);
    free(key_share0); free(key_share1);

    /* step 3: armor the shared key and write it to file.
       Filename should be of the form <label>-<priv_id>.b64 */
    /* YOUR CODE HERE */
    key_share_base64 = (char*)malloc(48 * sizeof(char));
    key_share_base64 = armor64(key_share, 32);
    free(key_share);
    fp = (char*)malloc((strlen(label) + strlen(priv_id) + 6) * sizeof(char));
    strcpy(fp, label); strcat(fp, "-");
    strcat(fp, priv_id); strcat(fp, ".b64");
    if((fdsk = open(fp, O_RDWR|O_TRUNC|O_CREAT, 0600)) == -1)
    { perror(getprogname()); exit(-1); }
    else
    {
       status = write(fdsk, key_share_base64, strlen(key_share_base64));
       if(status != -1)
       { status = write(fdsk, "\n", 1); }
       else
       { printf("Writing Fail!"); }
       close(fdsk);
    }
    free(key_share_base64);
    free(buffer);    

    /* DELETE FOLLOWING LINES WHEN YOU ARE DONE */
    /*
    printf ("NOT YET IMPLEMENTED.\n");
    printf ("priv:\n%s\n", dcexport_priv (priv));
    printf ("pub:\n%s\n", dcexport_pub (pub));
    printf ("priv_id: %s\n", priv_id);
    printf ("pub_id: %s\n", pub_id);
    printf ("fst_id: %s\n", fst_id);
    printf ("snd_id: %s\n", snd_id);
    printf ("label: %s\n", label);
    */
  }
}

int
main (int argc, char **argv)
{
  int arg_idx = 0;
  char *privcert_file = NULL;
  char *pubcert_file = NULL;
  char *priv_file = NULL;
  char *pub_file = NULL;
  char *priv_id = NULL;
  char *pub_id = NULL;
  char *label = DEFAULT_LABEL;
  dckey *priv = NULL;
  dckey *pub = NULL;
  cert *priv_cert = NULL;
  cert *pub_cert = NULL;

  if ((7 > argc) || (8 < argc))    usage (argv[0]);

  ri ();

  priv_file = argv[++arg_idx];
  privcert_file = argv[++arg_idx];
  priv_id = argv[++arg_idx];
  pub_file  = argv[++arg_idx];
  pubcert_file = argv[++arg_idx];
  pub_id = argv[++arg_idx];
  if (argc - 2 == arg_idx) {
    /* there was a label */
    label = argv[++arg_idx];
  }

  pub_cert = pki_check(pubcert_file, pub_file, pub_id);
  /* check above won't return if something was wrong */
  pub = pub_cert->public_key;

  if (!cert_verify (priv_cert = cert_read (privcert_file))) {
      printf ("%s: trouble reading certificate from %s, "
	      "or certificate expired\n", getprogname (), privcert_file);
      perror (getprogname ());

      exit (-1);
  } else if (!dcareequiv(pub_cert->issuer,priv_cert->issuer)) {
    printf ("%s: certificates issued by different CAs.\n",
	    getprogname ());
    printf ("\tOwn (%s's) certificate in %s\n", priv_id, privcert_file);
    printf ("\tOther (%s's) certificate in %s\n", pub_id, pubcert_file);
  } else {
    priv = priv_from_file (priv_file);
    
    nidh (priv, pub, priv_id, pub_id, label);
  }

  return 0;
}
