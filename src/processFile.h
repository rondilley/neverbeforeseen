/*****
 *
 * Description: File Processing Function Headers
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

#ifndef PROCESSFILE_DOT_H
#define PROCESSFILE_DOT_H

/****
 *
 * defines
 *
 ****/

/****
 *
 * includes
 *
 ****/

#ifdef HAVE_CONFIG_H
# include <config.h>
#endif

#include <sysdep.h>

#ifndef __SYSDEP_H__
# error something is messed up
#endif

#include <stdio.h>
#include <common.h>
#include "util.h"
#include "mem.h"
#include "hash.h"
#include "md5.h"
#include "sha256.h"
#include "parser.h"
#include "fileHandlers.h"

/****
 *
 * consts & enums
 *
 ****/

/****
 *
 * typedefs & structs
 *
 ****/

typedef struct {
  size_t len;
  unsigned char md5digest[32];
  unsigned char shadigest[32];
} metaData_t;

/****
 *
 * function prototypes
 *
 ****/

PUBLIC int processFile( char *inFile );
char *hash2hex(const unsigned char *hash, char *hashStr, int hLen );

#endif /* PROCESSFILE_DOT_H */
