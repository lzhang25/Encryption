/*	$NetBSD: aed.c,v 1.4 2013/12/8 19:46:33 Lin Exp $	*/

/*
 * Copyright (c) 2013
 * Codes by Lin Zhang.  All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 * 3. Neither the name of the University nor the names of its contributors
 *    may be used to endorse or promote products derived from this software
 *    without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE REGENTS AND CONTRIBUTORS ``AS IS'' AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED.  IN NO EVENT SHALL THE REGENTS OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 */

#include <sys/file.h>
#include <sys/prctl.h>

#include <errno.h>
#include <fcntl.h>
#include <openssl/evp.h>
#include <openssl/err.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#define ENCRYPTION 1
#define NOTYPE -1
#define DECRYPTION 0
#define BUFFSIZE 64

char *info[2] = {
  "Decryption",
  "Encryption"
};

int ishex(char);
int checksalt(char*);
char *checkpassphrase(int);
char *inputpassphrase(int);
void start_aed(int, char*, char*);
void passphrase_mask(int, char*[], int);
void usage(void);



int
main(int argc, char *argv[])
{
  int ch, argc_mask, aed_type = NOTYPE;
  char * aed_passphrase = NULL;
  char * aed_salt = NULL;

  while ((ch = getopt(argc,argv,"dehp:s:"))!=-1)
    switch (ch) {
    case 'd':
      aed_type = DECRYPTION;
      break;
    case 'e':
      aed_type = ENCRYPTION;
      break;
    case 'h':
      usage();
      break;
    /* In case p, use argc_mask to record the position of the argument to mask later. */
    case 'p':
      aed_passphrase = optarg;
      argc_mask = optind - 1;
      break;
    case 's':
      aed_salt = optarg;
      break;
    case '?':
    default:
      usage();
      break;
    }
  if (checksalt(aed_salt)) {
    fprintf(stderr, "Invalid salt syntax: salt must be exactly 8 hexadecimal characters\n");
    exit(EXIT_FAILURE);
  }
  /* Must specify -e or -d. */
  if (aed_type == NOTYPE)
    usage();
  /* If -p was specified, try to mask the argv argument. */
  if (aed_passphrase)
    passphrase_mask(argc, argv, argc_mask);
  /* If -p was not specified, read passphrase from stdin. */
  else
    aed_passphrase = checkpassphrase(aed_type);

  start_aed(aed_type, aed_passphrase, aed_salt);

  return 0;
}

int
checksalt(char *salt)
{
  /* Salt must be exactly 8 hexadecimal characters. */
  int i;

  if (!salt)
    return 0;
  for (i=0; i<strlen(salt); i++)
    if (!ishex(salt[i]))
      return 1;
  if (i == 8)
    return 0;
  else
    return 1;
}

int
ishex(char c)
{
  if (c >= '0' && c <= '9')
    return 1;
  else if (c >= 'A' && c <= 'F')
    return 1;
  else if (c >= 'a' && c <= 'f')
    return 1;
  else
    return 0;
}

void
start_aed(int aed_type, char *aed_passphrase, char *aed_salt)
{
  EVP_CIPHER_CTX ctx;
  int read_number, len, tmp_len;
  const EVP_CIPHER *cipher;
  const EVP_MD *digest = NULL;
  unsigned char key[EVP_MAX_KEY_LENGTH];
  unsigned char iv[EVP_MAX_IV_LENGTH];
  unsigned char read_buffer[BUFFSIZE];
  unsigned char write_buffer[2*BUFFSIZE];

  OpenSSL_add_all_algorithms();
  if ((cipher = EVP_get_cipherbyname("aes-256-cbc")) == NULL) {
    fprintf(stderr, "Unable to get cipher.\n");
    exit(EXIT_FAILURE);
  }
  if ((digest=EVP_get_digestbyname("sha1")) == NULL) {
    fprintf(stderr, "Unable to get digest.\n");
    exit(EXIT_FAILURE);
  }
  /* Get key and iv from passphrase. */
  if(EVP_BytesToKey(cipher, digest, (unsigned char*)aed_salt, 
                    (unsigned char*)aed_passphrase,
                    strlen(aed_passphrase), 1, key, iv) <= 0) {
    fprintf(stderr, "Unable to get key and iv.\n");
    exit(EXIT_FAILURE);
  }
  /* Begin to encrypt or decrypt*/
  while ((read_number = read(STDIN_FILENO, read_buffer, BUFFSIZE)) > 0) {
    EVP_CIPHER_CTX_init(&ctx);
    EVP_CIPHER_CTX_set_padding(&ctx, aed_type);
    if (EVP_CipherInit_ex(&ctx, cipher, NULL, key, iv, aed_type) == 0) {
      fprintf(stderr, "%s: Failed in EVP_CipherInit_ex.\n", info[aed_type]);
      ERR_print_errors_fp(stderr);
      exit(EXIT_FAILURE);
    }
    if (EVP_CipherUpdate(&ctx, write_buffer, 
                         &len, read_buffer, read_number) == 0) {
      fprintf(stderr, "%s: Failed in EVP_CipherUpdate.\n", info[aed_type]);
      ERR_print_errors_fp(stderr);
      exit(EXIT_FAILURE);
    }
    /* write the buffer and then clear ctx */
    if (read_number == BUFFSIZE) {
      if (write(STDOUT_FILENO, write_buffer, BUFFSIZE) != BUFFSIZE) {
        fprintf(stderr, "Unable to write: %s\n",strerror(errno));
        exit(EXIT_FAILURE);
      }
      EVP_CIPHER_CTX_cleanup(&ctx);
    }
  }
  if (EVP_CipherFinal_ex(&ctx, write_buffer+len, &tmp_len) == 0) {
    fprintf(stderr, "%s: Failed in EVP_CipherFinal.\n", info[aed_type]);
    ERR_print_errors_fp(stderr);
    exit(EXIT_FAILURE);
  }
  len = len + tmp_len;
  if (write(STDOUT_FILENO, write_buffer, len) != len) {
    fprintf(stderr, "Unable to write: %s\n",strerror(errno));
    exit(EXIT_FAILURE);
  }
  EVP_CIPHER_CTX_cleanup(&ctx);
}

void
passphrase_mask(int argc, char *argv[], int argc_mask)
{
  int i, argl = 0;
  char * argv_mask;

  for (i=0; i<strlen(argv[argc_mask]); i++) {
    argv[argc_mask][i] = '*';
  }
  for (i=0; i<argc; i++)
    argl = argl + strlen(argv[i]);
  /* Use argv_mask instead of the original progress name. */
  if ((argv_mask = 
       (char*)malloc((argl+argc+10)*sizeof(char))) == NULL) {
    fprintf(stderr, "Unable to allocate memory: %s\n",
            strerror(errno));
    exit(EXIT_FAILURE);
  }
  argv_mask[0] = '\0';
  for (i=0; i<argc; i++) {
    strcat(argv_mask, argv[i]);  
    strcat(argv_mask, " ");
  }
  /* Set the new progress name. */
  if (prctl(PR_SET_NAME, argv_mask) < 0) {
    fprintf(stderr, "Unable to rename progress: %s\n",
            strerror(errno));
    exit(EXIT_FAILURE);
  }
  free(argv_mask);
}

char *
checkpassphrase(int aed_type)
{
  int fd;
  char * aed_passphrase = NULL;
  char * tmp_passphrase;

  /* Open tty to remind user to input passphrase */
  if((fd = open("/dev/tty", O_RDWR)) == -1) {
    fprintf(stderr, "Unable to open: %s\n", strerror(errno));
    exit(EXIT_FAILURE);
  }
  /* Set a exclusive lock to prevent other progress writing */
  if (flock(fd,LOCK_EX) < 0) {
    fprintf(stderr, "Unable to lock: %s\n",
            strerror(errno));
    exit(EXIT_FAILURE);
  }
  /* Display the type of current action */
  if (write(fd, info[aed_type], strlen(info[aed_type])) != 
      strlen(info[aed_type])) {
    fprintf(stderr, "Unable to write: %s\n",
            strerror(errno));
    exit(EXIT_FAILURE);
  }
  while (aed_passphrase == NULL) {
    if (write(fd, "\npassphrase: ", strlen("\npassphrase: \0")) != 
        strlen("\npassphrase: \0")) {
      fprintf(stderr, "Unable to write: %s\n",
              strerror(errno));
      exit(EXIT_FAILURE);
    }
    tmp_passphrase = inputpassphrase(fd);
    /* If it is an encryption, ask the passphrase twice. */
    if (aed_type == ENCRYPTION) {
      if (write(fd, "Again: ", strlen("Again: \0")) != strlen("Again: \0")) {
        fprintf(stderr, "Unable to write: %s\n",
                strerror(errno));
        exit(EXIT_FAILURE);
      }
      if (strcmp(tmp_passphrase, inputpassphrase(fd)) == 0)
        aed_passphrase = tmp_passphrase;
    }
    /* If it is an decryption, just accept the passphrase. */
    else
      aed_passphrase = tmp_passphrase;
  }
  if (flock(fd,LOCK_UN) < 0) {
    fprintf(stderr, "Unable to unlock: %s\n",
            strerror(errno));
    exit(EXIT_FAILURE);
  }
  (void)close(fd);
  return aed_passphrase;
}

char *
inputpassphrase(int fd)
{
  char buffer[1];
  char * return_pp = NULL;
  char * tmp_pp = NULL;
  int n;

  while ((n = read(fd, buffer, 1)) > 0) {
    /* Read from stdin until \n or \r */
    if (buffer[0] == '\n' || buffer[0] == '\r')
      return return_pp;
    if (return_pp) {
      if ((tmp_pp = 
           (char*)malloc((strlen(return_pp)+1)*sizeof(char))) == NULL) {
        fprintf(stderr, "Unable to allocate memory: %s\n",
                strerror(errno));
        exit(EXIT_FAILURE);
      }
      strcpy(tmp_pp, return_pp);
      free (return_pp);
    }
    if (tmp_pp) {
      if ((return_pp = 
           (char*)malloc((strlen(tmp_pp)+2)*sizeof(char))) == NULL) {
        fprintf(stderr, "Unable to allocate memory: %s\n",
                strerror(errno));
        exit(EXIT_FAILURE);
      }
      strcpy(return_pp, tmp_pp);
      strncat(return_pp, buffer, 1);
    }
    else {
      if ((return_pp = (char*)malloc(2*sizeof(char))) == NULL) {
        fprintf(stderr, "Unable to allocate memory: %s\n",
                strerror(errno));
        exit(EXIT_FAILURE);
      }
      return_pp[0] = buffer[0];
      return_pp[1] = '\0';
    }
  }
  if (tmp_pp)
    free(tmp_pp);
  return return_pp;
}

void 
usage(void)
{
  fprintf(stderr, "Usage: aed [ -deh] [ -p passphrase] [ -s salt]\n");
  exit(EXIT_FAILURE);
}