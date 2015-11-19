#include "pv.h"

void
decrypt_file (const char *ptxt_fname, void *raw_sk, size_t raw_len, int fin)
{
  /*************************************************************************** 
   * Task: Read the ciphertext from the file descriptor fin, decrypt it using
   *       sk, and place the resulting plaintext in a file named ptxt_fname.
   *
   * This procedure basically `undoes' the operations performed by pv_encrypt;
   * it expects a ciphertext featuring the following structure (please refer 
   * to the comments in edu_encrypt.c for more details):
   *
   *
   *         +--------------------------+---+
   *         |             Y            | W |
   *         +--------------------------+---+
   *
   * where Y = AES-CTR (K_CTR, plaintext)
   *       W = AES-CBC-MAC (K_MAC, Y)
   *
   * Note that the length of Y (in bytes) is not necessarily a
   * multiple of 16 (aes_blocklen) (it is just 16 bytes more than the
   * length of the original plaintext), whereas W is exactly 16-byte
   * long.  So to figure out the split between Y and W, you could
   * repeatedly attempt to perform `long read' of (2 * aes_blocklen +
   * 1) bytes: once we get to the end of the ciphertext and only the
   * last chunk of Y has to be read, such "long reads" will encounter
   * the end-of-file, at which point we will know where Y ends, and
   * how to finish reading the last bytes of the ciphertext.
   *
   */

   int fd, status, cursor, iv_cursor, k = 0;
   ssize_t current_block_length;
   const ssize_t sk_len = raw_len / 2;
   char* initial_vector = (char*)malloc(sk_len * sizeof(char));
   char* mac_initial_vector = (char*)malloc(sk_len * sizeof(char));
   char* buffer = (char*)malloc(2 * sk_len * sizeof(char));
   char* txt_buffer = (char*)malloc(sk_len * sizeof(char));
   char* mac_buffer = (char*)malloc(sk_len * sizeof(char));
   aes_ctx* aes_ctr = NULL;
   aes_ctx* aes_cbc_mac = NULL;
   if((fd = open(ptxt_fname, O_WRONLY|O_TRUNC|O_CREAT, 0600)) == -1)
   {
      perror(getprogname());
      exit(-1);
   }
  /* use the first part of the symmetric key for the AES-CTR decryption ...*/
   aes_ctr = (aes_ctx*)malloc(sizeof(aes_ctx) * sizeof(char));
   aes_setkey(aes_ctr, raw_sk, sk_len);
  /* ... and the second for the AES-CBC-MAC */
   aes_cbc_mac = (aes_ctx*)malloc(sizeof(aes_ctx) * sizeof(char));
   aes_setkey(aes_cbc_mac, raw_sk + sk_len, sk_len);
  /* Reading Y */
  /* First, read the IV (Initialization Vector) */
   current_block_length = read(fin, initial_vector, sk_len);
   if(current_block_length != sk_len)
   {
      perror(getprogname());
      aes_clrkey(aes_ctr);
      aes_clrkey(aes_cbc_mac);
      exit(-1);
   }
   memcpy(mac_initial_vector, initial_vector, sk_len);
   while((current_block_length = read(fin, buffer, 2 * sk_len)) > 0)
   {
      if(current_block_length > sk_len)
      {
	 for(cursor = 0; cursor < current_block_length - sk_len; cursor++)
	 { txt_buffer[cursor] = buffer[cursor]; }
	 for(; cursor < current_block_length; cursor++)
	 { mac_buffer[cursor + sk_len - current_block_length] = buffer[cursor]; } 
	 if(current_block_length == 2 * sk_len)
         {
	    /* compute the AES-CBC-MAC as you go */
	    for(cursor = 0; cursor < sk_len; cursor++)
            { txt_buffer[cursor] = txt_buffer[cursor] ^ mac_initial_vector[cursor]; }
	    aes_encrypt(aes_cbc_mac, mac_initial_vector, txt_buffer);
	 }else
         {
	    /* Block length less than sk_len */
	    for(cursor = 0; cursor < current_block_length - sk_len; cursor++)
            { txt_buffer[cursor] = txt_buffer[cursor] ^ mac_initial_vector[cursor]; }
	    for(; cursor < sk_len; cursor++)
	    { txt_buffer[cursor] = mac_initial_vector[cursor] ^ '0'; }
	    aes_encrypt(aes_cbc_mac, mac_initial_vector, txt_buffer);
	 }
         /* CTR-mode decryption */
	 if(strcmp(mac_initial_vector, mac_buffer) == 0) /* Auth success */
         {
	    aes_encrypt(aes_ctr, txt_buffer, initial_vector);
	    for(cursor = 0; cursor < current_block_length - sk_len; cursor++)
	    { txt_buffer[cursor] = buffer[cursor] ^ txt_buffer[cursor]; }
	    initial_vector[0]++;
	    /* IV increment */
	    for(iv_cursor = 0; iv_cursor < sk_len; iv_cursor++)
	    {
	       if(initial_vector[iv_cursor] == -128)
	       { initial_vector[iv_cursor + 1] = initial_vector[iv_cursor + 1] + 1; }
	       else break;
	    }
	    /* Write current block into file */
	    status = write(fd, txt_buffer, current_block_length - sk_len);
	    if(status == -1)
	    {
	       perror(getprogname());
	       close(fd);
	       aes_clrkey(aes_ctr);
	       aes_clrkey(aes_cbc_mac);
	    }
	 }else  /* Auth fail */
	 { 
	    printf("No.%d Block Authorization Fail !!!\n", k);
	    aes_clrkey(aes_ctr);
	    aes_clrkey(aes_cbc_mac);
            break;
	 }
	 k++;
      }
   }
}

void 
usage (const char *pname)
{
  printf ("Simple File Decryption Utility\n");
  printf ("Usage: %s SK-FILE CTEXT-FILE PTEXT-FILE\n", pname);
  printf ("       Exits if either SK-FILE or CTEXT-FILE don't exist, or\n");
  printf ("       if a symmetric key sk cannot be found in SK-FILE.\n");
  printf ("       Otherwise, tries to use sk to decrypt the content of\n");
  printf ("       CTEXT-FILE: upon success, places the resulting plaintext\n");
  printf ("       in PTEXT-FILE; if a decryption problem is encountered\n"); 
  printf ("       after the processing started, PTEXT-FILE is truncated\n");
  printf ("       to zero-length and its previous content is lost.\n");

  exit (1);
}

int 
main (int argc, char **argv)
{
  int fdsk, fdctxt;
  char *sk = NULL;
  size_t sk_len = 0;
  
  if (argc != 4) {
    usage (argv[0]);
  }   /* Check if argv[1] and argv[2] are existing files */
  else if (((fdsk = open (argv[1], O_RDONLY)) == -1)
	   || ((fdctxt = open (argv[2], O_RDONLY)) == -1)) {
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
    if (!(sk = import_sk_from_file (&sk, &sk_len, fdsk))) {
      printf ("%s: no symmetric key found in %s\n", argv[0], argv[1]);
      
      close (fdsk);
      exit (2);
    }
    close (fdsk);

    /* Enough setting up---let's get to the crypto... */
    decrypt_file (argv[3], sk, sk_len, fdctxt);    
    /* scrub the buffer that's holding the key before exiting */

    /* YOUR CODE HERE */
    bzero(sk, sk_len);
    free(sk);
    close (fdctxt);
  }

  return 0;
}
