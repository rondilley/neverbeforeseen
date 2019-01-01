/*****
 *
 * Description: File Processing Functions
 *
 * Copyright (c) 2009-2018, Ron Dilley
 * All rights reserved.
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
 *
 ****/

/****
 *
 * includes
 *.
 ****/

#include "processFile.h"

/****
 *
 * local variables
 *
 ****/

FILE *out;

/****
 *
 * global variables
 *
 ****/

/****
 *
 * external variables
 *
 ****/

extern int errno;
extern char **environ;
extern struct hash_s *nbsHash;
extern int quit;
extern Config_t *config;

/****
 *
 * functions
 *
 ****/

/****
 * 
 * process file
 * 
 ****/

int processFile(char *inFilename)
{
  FILE *inFile = NULL;
  char inBuf[65536], *tok, *sol, *endPtr, *eol, *lineBuf = NULL;
  int i, done = FALSE, match = 0;
  size_t a, count, linePos = 0, *offsets, rCount, rLeft, lineBufSize = 0;
  MD5_CTX md5_ctx;
  sha256_context sha256_ctx;
  metaData_t *tmpMD;

#ifdef DEBUG
  if (config->debug >= 1)
    fprintf(stderr, "Opening [%s] for read\n", inFilename);
#endif

#ifdef HAVE_FOPEN64
  if ((inFile = fopen64(inFilename, "r")) EQ NULL)
  {
#else
  if ((inFile = fopen(inFilename, "r")) EQ NULL)
  {
#endif
    fprintf(stderr, "ERR - Unable to open file [%s] %d (%s)\n", inFilename, errno,
            strerror(errno));
    return (EXIT_FAILURE);
  }

  while ((rCount = fread(inBuf, 1, sizeof(inBuf), inFile)) > 0)
  {
#ifdef DEBUG
    if (config->debug >= 7)
      fprintf(stderr, "DEBUG - Read [%lu] bytes\n", rCount);
#endif

    sol = inBuf;
    rLeft = rCount;
    while (rLeft && ((eol = strchr(sol, '\n')) != NULL))
    {
      /* copy bytes (sol to eol) to lineBuf */
      lineBufSize += (eol - sol);
#ifdef DEBUG
      if (config->debug >= 6)
        fprintf(stderr, "DEBUG - Line Buf: [%lu]\n", lineBufSize);
#endif

      if (lineBuf EQ NULL)
      {
        if ((lineBuf = XMALLOC(lineBufSize + 1)) EQ NULL)
        {
          fprintf(stderr,
                  "ERR - Unable to allocate memory for index buffer [%lu]\n",
                  lineBufSize);
          exit(EXIT_FAILURE);
        }
      }
      else
      {
        if ((lineBuf = XREALLOC(lineBuf, lineBufSize + 1)) EQ NULL)
        {
          fprintf(stderr,
                  "ERR - Unable to allocate memory for index buffer [%lu]\n",
                  lineBufSize);
          exit(EXIT_FAILURE);
        }
      }
      XMEMCPY(lineBuf + linePos, sol, eol - sol);
      lineBuf[lineBufSize] = '\0';

#ifdef DEBUG
      if (config->debug >= 9)
        printf("%s\n", lineBuf);
#endif

      /* have we seen this line before */

      if (getHashRecord(nbsHash, lineBuf) EQ NULL)
      {
        /* never before seen, store it */
        printf("%s\n", lineBuf);

        /* XXX really should not store the full line */

        if ((tmpMD = (metaData_t *)XMALLOC(sizeof(metaData_t))) EQ NULL)
        {
          fprintf(stderr, "ERR - Unable to allocate memory for nbs record\n");
          return (EXIT_FAILURE);
        }
        XMEMSET(tmpMD, 0, sizeof(metaData_t));

        /* zero buffers */
        //XMEMSET(&md5_ctx, 0, sizeof(md5_ctx));
        //XMEMSET(&sha256_ctx, 0, sizeof(sha256_ctx));

        /* init hashing digests */
        sha256_starts(&sha256_ctx);
        MD5_Init(&md5_ctx);

        /* update hashing digests */
        sha256_update(&sha256_ctx, lineBuf, lineBufSize);
        MD5_Update(&md5_ctx, lineBuf, lineBufSize);

        /* complete hashing digests */
        sha256_finish(&sha256_ctx, tmpMD->shadigest);
        MD5_Final(tmpMD->md5digest, &md5_ctx);
      }

#ifdef DEBUG
      if (config->debug >= 5)
        printf("DEBUG - Adding RECORD\n");
#endif
      addUniqueHashRec(nbsHash, lineBuf,
                       lineBufSize + 1, tmpMD);
      /* check to see if the hash should be grown */
      /* XXX may be too agressive */
      nbsHash = dyGrowHash(nbsHash);

      /* reset lineBuf */
      rLeft -= (eol - sol) + 1;
      sol = eol + 1;
      lineBufSize = 0;
      linePos = 0;
      XFREE(lineBuf);
      lineBuf = NULL;
    }

    if (rLeft)
    {
#ifdef DEBUG
      if (config->debug >= 3)
        fprintf(stderr, "Overflow [%lu] bytes saved\n", rLeft);
#endif
      /* copy remainder from sol to end of inBuf to lineBuf */
      lineBufSize += rLeft;
      if (lineBuf EQ NULL)
      {
        if ((lineBuf = XMALLOC(lineBufSize + 1)) EQ NULL)
        {
          fprintf(stderr,
                  "ERR - Unable to allocate memory for index buffer [%lu]\n",
                  lineBufSize);
          exit(EXIT_FAILURE);
        }
      }
      else
      {
        if ((lineBuf = XREALLOC(lineBuf, lineBufSize + 1)) EQ NULL)
        {
          fprintf(stderr,
                  "ERR - Unable to allocate memory for index buffer [%lu]\n",
                  lineBufSize);
          exit(EXIT_FAILURE);
        }
      }
      XMEMCPY(lineBuf + linePos, sol, rLeft);
      linePos += rLeft;
      lineBuf[lineBufSize] = '\0';
    }
  }

  fclose(inFile);

  return (EXIT_SUCCESS);
}

/****
 *
 * convert hash to hex
 *
 ****/

char *hash2hex(const unsigned char *hash, char *hashStr, int hLen)
{
  int i;
  char hByte[3];
  bzero(hByte, sizeof(hByte));
  hashStr[0] = 0;

  for (i = 0; i < hLen; i++)
  {
    snprintf(hByte, sizeof(hByte), "%02x", hash[i] & 0xff);
#ifdef HAVE_STRNCAT
    strncat(hashStr, hByte, hLen * 2);
#else
    strlcat(hashStr, hByte, hLen * 2);
#endif
  }

  return hashStr;
}
