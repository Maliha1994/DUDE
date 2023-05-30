#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <fcntl.h>
#include <unistd.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <limits.h>
#include <dirent.h>
#include <errno.h>

#define HEADER "@^@^@^@^@^@^@^@^@^@^@^@^7a6c7173"

#define HEADER_SIZE 32
#define NAME_MAX_SIZE 40
#define PATH_SIZE 100

struct unique_header{
  char header[HEADER_SIZE];
  uint32_t ver;
  uint32_t num_entries;
  uint32_t misc;
};

struct unique_entry{
  char name[NAME_MAX_SIZE];
  uint32_t size;
  uint32_t offset;
};


int write_file(char *file_name, char *buffer, size_t size){
  FILE *fp_out = NULL;
  fp_out = fopen(file_name, "w");
  fwrite(buffer, 1, size, fp_out);
  fclose(fp_out);
}


void concat(char str_1[], char str_2[]) {
  int i, j;
  i = 0;
  while (str_1[i] != '\0') {
    i++;
  }
  j = 0;
  while (str_2[j] != '\0') {
    str_1[i] = str_2[j];
    j++;
    i++;
  }
  str_1[i] = '\0';
}

void decomress(char *command){
    system(command);
}

int main(int argc, char *argv[]){

  if(argc < 2 || argv[1][0] == '-'){
      printf("Usage: filename.bin destination_folder\n");
      goto end;
  }

  struct stat _fstat = {0};
  char *buffer = NULL;
  FILE *fp_in;
  char root_dir[PATH_SIZE];
  char *file_dir = NULL, *folder_name = NULL;
  char sel[5]="/";
  char cd[5]="cd ";
  file_dir=argv[1];
  folder_name = argv[2];
  getcwd(root_dir, sizeof(root_dir));
  stat(file_dir,&_fstat);
  fp_in = open(file_dir, O_RDONLY);
  buffer = malloc(_fstat.st_size);
  read(fp_in,buffer,_fstat.st_size);

  int i = 0, offset = 0;
  struct unique_header *header = NULL;
  struct unique_entry * entry = NULL;
  char file_name[PATH_SIZE] = {0};

  header = (struct unique_header *) buffer;
  header->num_entries = htonl(header->num_entries);

  char command[9000]={0};

  strcpy(command,cd);
  concat(command, root_dir);
  concat(command,sel);
  concat(command,folder_name);
  concat(command," && xz -d *.lzma");

  char dir_c[900]={0};
  strcpy(dir_c, root_dir);
  concat(dir_c,sel);
  concat(dir_c,folder_name);

  char dir_d[900]={0};
  strcpy(dir_d, "rm -r ");
  concat(dir_d, dir_c);
  DIR* dir;

  if (dir = opendir(dir_c)) {
    system (dir_d);
    mkdir(folder_name, (S_IRWXU | S_IRWXG | S_IRWXO));
  } else if (ENOENT == errno) {
    mkdir(folder_name, (S_IRWXU | S_IRWXG | S_IRWXO));
  }

  if(memcmp(header->header, HEADER, HEADER_SIZE) != 0){
    printf("Trying different method...\n");
    goto end;
  	}
  else{
      printf("Custom Extractor Worked!\n");
    }

  for(i=0,offset=sizeof(struct unique_header); (i < header->num_entries && offset < _fstat.st_size); i++,offset+=sizeof(struct unique_entry)){
    entry = (struct unique_entry *) (buffer + offset);
    entry->size = htonl(entry->size);
    entry->offset = htonl(entry->offset);
    strcpy(file_name, root_dir);
    concat(file_name, sel);
    concat(file_name, folder_name);
    concat(file_name, sel);
    concat(file_name, entry->name);
    concat(file_name, ".lzma");
    write_file((char *) &file_name, (buffer + entry->offset), entry->size);
 	}
  decomress(command);

end:
	return EXIT_SUCCESS;
}
