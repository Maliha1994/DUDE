#include <stdio.h>
#include <inttypes.h>
#include <sys/stat.h>
#include <linux/cramfs_fs.h>
#include <byteswap.h>
#include <zlib.h> 
#include <sys/mman.h>
#include <fcntl.h>
#include <stdlib.h>
#include <string.h>

#include <sys/sendfile.h>


#define BUFFERSIZE	16384
#define MAXFILES	4096
#define BLKSIZE		4096	

int main(int argc, char *argv[]){

	if(argc < 2 || argv[1][0] == '-'){
      printf("Usage: input_filename.bin output_filename.bin\n");
      goto end;
	}
	uint32_t		superblock_in[16], superblock_out[16], blockpointer_in, blockpointer_out, blockpointer_last;
	unsigned char		buffer[BUFFERSIZE];
	int			infile, outfile;
	unsigned int		filecnt, filepos, *fileoffset, *filesize, file, remaining, nblocks, x, copybytes, readbytes;
	uint8_t	        inode_in[12], inode_out[12];
	struct cramfs_inode	inode;

	if ( (infile=open(argv[1],O_RDONLY)) < 0 ){
		perror("while trying to open binary input file");
		exit(1);
	}


	if ( read(infile, &superblock_in, sizeof(superblock_in)) != sizeof(superblock_in) ){
		perror("while trying to read superblock");
		exit(1);
	}
	if (superblock_in[0]==0x453dcd28){
		printf("%s\n","Big endian compressed romfs found");
		if ( (outfile=open(argv[2], O_RDWR|O_TRUNC|O_CREAT, 0644)) < 0 ){
			perror("while trying to open image output file");
			exit(1);
		}

		// convert superblock 
		superblock_out[ 0] = bswap_32(superblock_in[ 0]);	// Magic 
		superblock_out[ 1] = bswap_32(superblock_in[ 1]);	// Size 
		superblock_out[ 2] = bswap_32(superblock_in[ 2]);	// Flags 
		superblock_out[ 3] = bswap_32(superblock_in[ 3]);	// Future Use 
		superblock_out[ 4] =          superblock_in[ 4] ;     // Sig 1/4 
		superblock_out[ 5] =          superblock_in[ 5] ;     // Sig 2/4 
		superblock_out[ 6] =          superblock_in[ 6] ;     // Sig 3/4 
		superblock_out[ 7] =          superblock_in[ 7] ;     // Sig 4/4 
		superblock_out[ 8] = bswap_32(superblock_in[ 8]);	// fsid crc 
		superblock_out[ 9] = bswap_32(superblock_in[ 9]);	// fsid edition 
		superblock_out[10] = bswap_32(superblock_in[10]);	// fsid blocks 
		superblock_out[11] = bswap_32(superblock_in[11]);	// fsid files 
		superblock_out[12] =          superblock_in[12] ;     // Name 1/4 
		superblock_out[13] =          superblock_in[13] ;     // Name 2/4 
		superblock_out[14] =          superblock_in[14] ;     // Name 3/4 
		superblock_out[15] =          superblock_in[15] ;     // Name 4/4 
		write(outfile, &superblock_out, sizeof(superblock_out));

		
	    filecnt = superblock_out[11];
		fileoffset = (unsigned int*)malloc( filecnt * sizeof( *fileoffset ));
		filesize = (unsigned int*)malloc( filecnt * sizeof( *filesize ));
		filepos = 16;
		remaining = 0;

		// Read directory entries 
		for ( file=0; file<filecnt; file++ ){
			if ( read(infile, &inode_in, sizeof(inode_in)) != sizeof(inode_in) ){
				perror("while trying to read directory entry");
				exit(1);
			}
			// convert the inode. 

			inode_out[0] = inode_in[1]; // 16 bit: mode 
			inode_out[1] = inode_in[0];

			inode_out[2] = inode_in[3]; // 16 bit: uid 
			inode_out[3] = inode_in[2]; 

			inode_out[4] = inode_in[6]; // 24 bit: size 
			inode_out[5] = inode_in[5];
			inode_out[6] = inode_in[4];

			inode_out[7] = inode_in[7]; 
			inode_out[ 8] = ( (inode_in[ 8]&0xFD) >> 2 ) | 
			              ( (inode_in[11]&0x03) << 6 );
			             
			inode_out[ 9] = ( (inode_in[11]&0xFD) >> 2 ) | 
			              ( (inode_in[10]&0x03) << 6 );
			             
			inode_out[10] = ( (inode_in[10]&0xFD) >> 2 ) | 
			              ( (inode_in[ 9]&0x03) << 6 );
			             
			inode_out[11] = ( (inode_in[ 9]&0xFD) >> 2 ) | 
			              ( (inode_in[ 8]&0x03) << 6 );


			memcpy(&inode, &inode_out, sizeof(inode_in));

			// write the converted inode 
			write(outfile, &inode_out, sizeof(inode_out));

			if ( read(infile, &buffer, inode.namelen<<2) != inode.namelen<<2 ){
				perror("while trying to read filename");
				exit(1);
			}
			write(outfile, &buffer, inode.namelen<<2);
			filesize  [file] = inode.size;
			fileoffset[file] = inode.offset;

			filepos += inode.namelen + 3;

			if ( ( S_ISREG(inode.mode) || S_ISLNK(inode.mode) ) && inode.size > 0 ){
				remaining++;
			}
		}                                            

		while ( remaining ){
			for ( file=1; fileoffset[file]!=filepos&&file<filecnt; file++ );
			for ( x=1; x<filecnt; x++ )
				if ( fileoffset[x] == filepos )
					remaining--;
	 
			nblocks = (filesize[file]-1)/BLKSIZE + 1;

			// convert the blockpointer 
			for ( x=0; x<nblocks; x++ ){
				if ( read(infile, &blockpointer_in, 4) != 4 ){
					perror("while trying to read blockpointer");
					exit(1);
				}
				blockpointer_out = bswap_32(blockpointer_in);
				write(outfile, &blockpointer_out, 4);
				filepos++;
			}

			blockpointer_last = blockpointer_out;

			blockpointer_last += (4-(blockpointer_last%4))%4;

			// Copy the file data 
			copybytes = blockpointer_last-(filepos<<2);

			while (copybytes>0){
				readbytes = (copybytes>BUFFERSIZE) ? BUFFERSIZE : copybytes;

				if ( read(infile, &buffer, readbytes) != readbytes ){
					perror("while trying to read file data");
					exit(1);
				}
				write(outfile, &buffer, readbytes);
				copybytes -= readbytes;
			}
			filepos = (blockpointer_last)>>2;
		}
		printf("%s\n","Conversion to little endian is successfull");
	}else if(superblock_in[0]==0x28cd3d45){

		printf("%s\n","little endian compressed romfs");

		int input, output;    
	    if ((input = open(argv[1], O_RDONLY)) == -1)
	    {
	        return -1;
	    }    
	    if ((output = creat(argv[2], 0660)) == -1)
	    {
	        close(input);
	        return -1;
	    }
	    off_t bytesCopied = 0;
	    struct stat fileinfo = {0};
	    fstat(input, &fileinfo);
	    int result = sendfile(output, input, &bytesCopied, fileinfo.st_size);
	    close(input);
    	close(output);


	}else{
		printf("%s\n","Not a big or little endian compressed romfs");
	}
	end:
	return EXIT_SUCCESS;
}
