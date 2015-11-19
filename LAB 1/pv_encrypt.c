#include "pv.h"

void
encrypt_file (const char *ctxt_fname, void *raw_sk, size_t raw_len, int fin)
{
  /*************************************************************************** 
   * Task: Read the content from file descriptor fin, encrypt it using raw_sk,
   *       and place the resulting ciphertext in a file named ctxt_fname.
   *       The encryption should be CCA-secure, which is the level of 
   *       cryptographic protection that you should always expect of any 
   *       implementation of an encryption algorithm.
   * 
   * As we have learned in class, the gold standard for encryption is
   * CCA-security. The approach that we will take in this lab is to
   * use AES in CTR-mode (AES-CTR), and then append an AES-CBC-MAC mac
   * of the resulting ciphertext. (Always mac after encrypting!) The
   * dcrypt library contains an implementation of AES (see source at
   * ~nicolosi/devel/libdcrypt/src/aes.c), but you need to implement
   * the logic for using AES in CTR-mode and in CBC-MAC'ing.
   *
   * Notice that the keys used to compute AES-CTR and AES-CBC-MAC mac
   * must be different. Never use the same cryptographic key for two
   * different purposes: bad interference could occur.  For this
   * reason, the key raw_sk actually consists of two pieces, one for
   * use in AES-CTR and the other for AES-CBC-MAC. The length of each
   * piece (and hence the cryptographic strength of the encryption) is
   * specified by the constant CCA_STRENGTH in pv.h; the default is
   * 128 bits, or 16 bytes.
   * 
   * Recall that AES works on blocks of 128 bits; in the case that the
   * length (in bytes) of the plaintext is not a multiple of 16, just
   * discard the least-significant bytes that you obtains from the
   * CTR-mode operation.
   * 
   * Thus, the overall layout of an encrypted file will be:
   *
   *         +--------------------------+---+
   *         |             Y            | W |
   *         +--------------------------+---+
   *
   * where Y = AES-CTR (K_CTR, plaintext)
   *       W = AES-CBC-MAC (K_MAC, Y)
   *
   * As for the sizes of the various components of a ciphertext file,
   * notice that:
   *
   * - the length of Y (in bytes) is just 16 bytes more than the length
   *   of the plaintext, and thus it may not be a multiple of 16; 
   * - the hash value AES-CBC-MAC (K_MAC, Y) is 16-byte long;
   *
   ***************************************************************************/

  /* Create the ciphertext file---the content will be encrypted, 
   * so it can be world-readable! */
   int fd, status, cursor, iv_cursor;
   int padlen = 0;
   ssize_t current_block_length;
   const ssize_t sk_len = raw_len / 2;
   char* initial_vector = (char*)malloc(sk_len * sizeof(char));
   char* mac_initial_vector = (char*)malloc(sk_len * sizeof(char));
   char* buffer = (char*)malloc(sk_len * sizeof(char));
   char* outbound_buffer = (char*)malloc(sk_len * sizeof(char));
   aes_ctx* aes_ctr = NULL;
   aes_ctx* aes_cbc_mac = NULL;
   if((fd = open(ctxt_fname, O_WRONLY|O_TRUNC|O_CREAT, 0600)) == -1)
   {
       perror(getprogname());
       exit(-1);
   }
  /* initialize the pseudorandom generator (for the IV) */
   ri();
   prng_getbytes(initial_vector, sk_len);
   memcpy(mac_initial_vector, initial_vector, sk_len);
   status = write(fd, initial_vector, sk_len);
   if(status == -1)
   {
      perror(getprogname());
      close(fd);
      exit(-1);
   }
  /* The buffer for the symmetric key actually holds two keys: */
  /* use the first key for the AES-CTR encryption ...*/
   aes_ctr = (aes_ctx*)malloc(sizeof(aes_ctx) * sizeof(char));
   aes_setkey(aes_ctr, raw_sk, sk_len);
  /* ... and the second part for the AES-CBC-MAC */
   aes_cbc_mac = (aes_ctx*)malloc(sizeof(aes_ctx) * sizeof(char));
   aes_setkey(aes_cbc_mac, raw_sk + sk_len, sk_len);
  /* Now start processing the actual file content using symmetric encryption */
  /* Remember that CTR-mode needs a random IV (Initialization Vector) */
   while((current_block_length = read(fin, buffer, sk_len)) > 0)
   {
      if(current_block_length < sk_len)
	 padlen = sk_len - current_block_length;
      if(current_block_length > 0)
      {
	 aes_encrypt(aes_ctr, outbound_buffer, initial_vector);
	 for(cursor = 0; cursor < current_block_length; cursor++)
	 { buffer[cursor] = outbound_buffer[cursor] ^ buffer[cursor]; }
      }
      /* IV increment implement */
      initial_vector[0]++;
      for(iv_cursor = 0; iv_cursor < sk_len; iv_cursor++)
      {
	 if(initial_vector[iv_cursor] == -128)
	 { initial_vector[iv_cursor + 1] = initial_vector[iv_cursor + 1] + 1; }
	 else break;
      }
      status = write(fd, buffer, current_block_length);
      if(status == -1)
      {
	 perror(getprogname());
	 close(fd);	  
	 aes_clrkey(aes_ctr);
	 aes_clrkey(aes_cbc_mac);
	 exit(-1);
      }

      /* Compute the AES-CBC-MAC while you go */
      if(current_block_length == sk_len)
      {
	 for(cursor = 0; cursor < sk_len; cursor++)
	 { buffer[cursor] = mac_initial_vector[cursor] ^ buffer[cursor]; }
	 aes_encrypt(aes_cbc_mac, mac_initial_vector, buffer);	  
      }
      /* Don't forget to pad the last block with trailing zeroes */
      else 
      {
	 for(cursor = 0; cursor < current_block_length; cursor++)
	 { buffer[cursor] = mac_initial_vector[cursor] ^ buffer[cursor]; }
	 for(; cursor < current_block_length + padlen; cursor++)
	 { buffer[cursor] = mac_initial_vector[cursor] ^ '0'; }
         aes_encrypt(aes_cbc_mac, mac_initial_vector, buffer);
      }
      /* Finish up computing the AES-CBC-MAC and write the resulting */
      /* 16-byte MAC after the last chunk of the AES-CTR ciphertext */
      status = write(fd, mac_initial_vector, sk_len);
      if(status == -1)
      {
         perror(getprogname());
         aes_clrkey(aes_ctr);
         aes_clrkey(aes_cbc_mac);
         exit(-1);
      }
   }
   close(fd);
   aes_clrkey(aes_ctr);
   aes_clrkey(aes_cbc_mac);
}

void 
usage (const char *pname)
{
  printf ("Personal Vault: Encryption \n");
  printf ("Usage: %s SK-FILE PTEXT-FILE CTEXT-FILE\n", pname);
  printf ("       Exits if either SK-FILE or PTEXT-FILE don't exist.\n");
  printf ("       Otherwise, encrpyts the content of PTEXT-FILE under\n");
  printf ("       sk, and place the resulting ciphertext in CTEXT-FILE.\n");
  printf ("       If CTEXT-FILE existed, any previous content is lost.\n");

  exit (1);
}

int 
main (int argc, char **argv)
{
  int fdsk, fdptxt;
  char *raw_sk;
  size_t raw_len;

  /* YOUR CODE HERE */

  if (argc != 4) {
    usage (argv[0]);
  }   /* Check if argv[1] and argv[2] are existing files */
  else if (((fdsk = open (argv[1], O_RDONLY)) == -1)
	   || ((fdptxt = open (argv[2], O_RDONLY)) == -1)) {
    if (errno == ENOENT) {
      usage (argv[0]);
    }
    else {
      perror (argv[0]);
      
      exit (-1);
    }
  }
  else {
    setprogname (argv[0]);
    
    /* Import symmetric key from argv[1] */
    if (!(import_sk_from_file (&raw_sk, &raw_len, fdsk))) {
      printf ("%s: no symmetric key found in %s\n", argv[0], argv[1]);
      
      close (fdsk);
      exit (2);
    }
    close (fdsk);

    /* Enough setting up---let's get to the crypto... */
    encrypt_file (argv[3], raw_sk, raw_len, fdptxt);    

    /* scrub the buffer that's holding the key before exiting */

    /* YOUR CODE HERE */
    bzero(raw_sk, raw_len);
    free(raw_sk);
    close (fdptxt);
  }
  return 0;
}
