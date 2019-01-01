/*****
 *
 * Description: NeverBeforeSeen Functions
 *
 * Copyright (c) 2010-2018, Ron Dilley
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
 *
 ****/

#include <stdio.h>
#include <stdlib.h>

#include "nbs.h"

/****
 *
 * local variables
 *
 ****/

/****
 *
 * global variables
 *
 ****/

PUBLIC int quit = FALSE;
PUBLIC int reload = FALSE;
PUBLIC Config_t *config = NULL;
PUBLIC int inFileLen;
PUBLIC char *inFilename;

/* hashes */
struct hash_s *nbsHash = NULL;

/****
 *
 * external variables
 *
 ****/

extern int errno;
extern char **environ;

/****
 *
 * main function
 *
 ****/

int main(int argc, char *argv[]) {
  PRIVATE int pid = 0;
  PRIVATE int c = 0, i = 0, fds = 0, status = 0;
  int digit_optind = 0;
  PRIVATE struct passwd *pwd_ent;
  PRIVATE struct group *grp_ent;
  PRIVATE char **ptr;
  char *tmp_ptr = NULL;
  char *pid_file = NULL;
  char *user = NULL;
  char *group = NULL;
#ifdef LINUX
  struct rlimit rlim;

  getrlimit(RLIMIT_CORE, &rlim);
#ifdef DEBUG
  rlim.rlim_cur = rlim.rlim_max;
  printf("DEBUG - RLIMIT_CORE: %ld\n", rlim.rlim_cur);
#else
  rlim.rlim_cur = 0;
#endif
  setrlimit(RLIMIT_CORE, &rlim);
#endif

  /* setup config */
  config = (Config_t *)XMALLOC(sizeof(Config_t));
  XMEMSET(config, 0, sizeof(Config_t));

  /* get real uid and gid, we may want to drop privs */
  config->gid = getgid();
  config->uid = getuid();

  while (1) {
    int this_option_optind = optind ? optind : 1;
#ifdef HAVE_GETOPT_LONG
    int option_index = 0;
    static struct option long_options[] = {
        {"debug", required_argument, 0, 'd'},
        {"help", no_argument, 0, 'h'},
        {"version", no_argument, 0, 'v'},
        {0, no_argument, 0, 0}};
    c = getopt_long(argc, argv, "d:hv", long_options,
                    &option_index);
#else
    c = getopt(argc, argv, "d:hv");
#endif

    if (c EQ - 1)
      break;

    switch (c) {
    
    case 'd':
      /* show debig info */
      config->debug = atoi(optarg);
      config->mode = MODE_INTERACTIVE;
      break;

    case 'h':
      /* show help info */
      print_help();
      return (EXIT_SUCCESS);

    case 'v':
      /* show the version */
      print_version();
      return (EXIT_SUCCESS);

    default:
      fprintf(stderr, "Unknown option code [0%o]\n", c);
    }
  }

  /* check dirs and files for danger */

  if (time(&config->current_time) EQ - 1) {
    fprintf(stderr, "ERR - Unable to get current time\n");
    /* cleanup buffers */
    cleanup();
    return EXIT_FAILURE;
  }

  /* initialize program wide config options */
  config->hostname = (char *)XMALLOC(MAXHOSTNAMELEN + 1);

  /* get processor hostname */
  if (gethostname(config->hostname, MAXHOSTNAMELEN) != 0) {
    fprintf(stderr, "Unable to get hostname\n");
    strncpy(config->hostname, "unknown", MAXHOSTNAMELEN);
  }

  /* setup gracefull shutdown */
  signal(SIGINT, sigint_handler);
  signal(SIGTERM, sigterm_handler);
  signal(SIGFPE, sigfpe_handler);
  signal(SIGILL, sigill_handler);
  signal(SIGSEGV, sigsegv_handler);
#ifndef MINGW
  signal(SIGHUP, sighup_handler);
  signal(SIGBUS, sigbus_handler);
#endif

  /****
   *
   * lets get this party started
   *
   ****/

  show_info();

  nbsHash = initHash(52);

  /* load existing hashes */

  /* process files passed as arguments */

  while (optind < argc) {
    if ((inFileLen = strlen(argv[optind])) >= PATH_MAX) {
      fprintf(stderr, "ERR - Argument too long\n");
      cleanup();
      return (EXIT_FAILURE);
    } else {
      if ( ( inFilename = XMALLOC( inFileLen+1 ) ) EQ NULL ) {
        fprintf( stderr, "ERR - Unable to allocate memory for filename\n" );
        freeHash( nbsHash );
        cleanup();
        return( EXIT_FAILURE );
      }
      XMEMSET( inFilename, '\0', inFileLen+1 );
      strncpy(inFilename, argv[optind++], inFileLen);
      /* process directory tree */
      if (processFile(inFilename) EQ FAILED) {
        freeHash(nbsHash);
        cleanup();
        return (EXIT_FAILURE);
      }

      /* Prep for next dir to compare */
      XFREE( inFilename );
    }
  }

  if (nbsHash != NULL)
    freeHash(nbsHash);

  /****
   *
   * we are done
   *
   ****/

  cleanup();

  return (EXIT_SUCCESS);
}

/****
 *
 * display prog info
 *
 ****/

void show_info(void) {
  fprintf(stderr, "%s v%s [%s - %s]\n", PROGNAME, VERSION, __DATE__, __TIME__);
  fprintf(stderr, "By: Ron Dilley\n");
  fprintf(stderr, "\n");
  fprintf(stderr, "%s comes with ABSOLUTELY NO WARRANTY.\n", PROGNAME);
  fprintf(stderr, "This is free software, and you are welcome\n");
  fprintf(stderr, "to redistribute it under certain conditions;\n");
  fprintf(stderr, "See the GNU General Public License for details.\n");
  fprintf(stderr, "\n");
}

/*****
 *
 * display version info
 *
 *****/

PRIVATE void print_version(void) {
  printf("%s v%s [%s - %s]\n", PROGNAME, VERSION, __DATE__, __TIME__);
}

/*****
 *
 * print help info
 *
 *****/

PRIVATE void print_help(void) {
  print_version();

  fprintf(stderr, "\n");
  fprintf(stderr, "syntax: %s [options] {dir}|{file} [{dir} ...]\n", PACKAGE);

#ifdef HAVE_GETOPT_LONG
  fprintf(stderr, " -d|--debug (0-9)     enable debugging info\n");
  fprintf(stderr, " -h|--help            this info\n");
  fprintf(stderr, " -v|--version         display version information\n");
#else
  fprintf(stderr, " -d {lvl}   enable debugging info\n");
  fprintf(stderr, " -h         this info\n");
  fprintf(stderr, " -v         display version information\n");
#endif

  fprintf(stderr, "\n");
}

/****
 *
 * cleanup
 *
 ****/

PRIVATE void cleanup(void) {
  if (inFilename != NULL)
    XFREE(inFilename);
  XFREE(config->hostname);
  if (config->home_dir != NULL)
    XFREE(config->home_dir);
  if (config->outfile != NULL)
    XFREE(config->outfile);
  XFREE(config);
#ifdef MEM_DEBUG
  XFREE_ALL();
#endif
}

/****
 *
 * SIGINT handler
 *
 ****/

void sigint_handler(int signo) {
  signal(signo, SIG_IGN);

  /* do a calm shutdown as time and pcap_loop permit */
  quit = TRUE;
  signal(signo, sigint_handler);
}

/****
 *
 * SIGTERM handler
 *
 ****/

void sigterm_handler(int signo) {
  signal(signo, SIG_IGN);

  /* do a calm shutdown as time and pcap_loop permit */
  quit = TRUE;
  signal(signo, sigterm_handler);
}

/****
 *
 * SIGHUP handler
 *
 ****/

#ifndef MINGW
void sighup_handler(int signo) {
  signal(signo, SIG_IGN);

  /* time to rotate logs and check the config */
  reload = TRUE;
  signal(SIGHUP, sighup_handler);
}
#endif

/****
 *
 * SIGSEGV handler
 *
 ****/

void sigsegv_handler(int signo) {
  signal(signo, SIG_IGN);

  fprintf(stderr, "ERR - Caught a sig%d, shutting down fast\n", signo);

  cleanup();
#ifdef MEM_DEBUG
  XFREE_ALL();
#endif
  /* core out */
  abort();
}

/****
 *
 * SIGBUS handler
 *
 ****/

void sigbus_handler(int signo) {
  signal(signo, SIG_IGN);

  fprintf(stderr, "ERR - Caught a sig%d, shutting down fast\n", signo);

  cleanup();
#ifdef MEM_DEBUG
  XFREE_ALL();
#endif
  /* core out */
  abort();
}

/****
 *
 * SIGILL handler
 *
 ****/

void sigill_handler(int signo) {
  signal(signo, SIG_IGN);

  fprintf(stderr, "ERR - Caught a sig%d, shutting down fast\n", signo);

  cleanup();
#ifdef MEM_DEBUG
  XFREE_ALL();
#endif
  /* core out */
  abort();
}

/****
 *
 * SIGFPE handler
 *
 ****/

void sigfpe_handler(int signo) {
  signal(signo, SIG_IGN);

  fprintf(stderr, "ERR - Caught a sig%d, shutting down fast\n", signo);

  cleanup();
#ifdef MEM_DEBUG
  XFREE_ALL();
#endif
  /* core out */
  abort();
}
