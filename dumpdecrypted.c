/*

Dumps decrypted iPhone Applications to a file - better solution than those GDB scripts for non working GDB versions
(C) Copyright 2011-2014 Stefan Esser

iPod:~ root# DYLD_INSERT_LIBRARIES=dumpdecrypted.dylib /var/mobile/Applications/xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx/Scan.app/Scan
mach-o decryption dumper

DISCLAIMER: This tool is only meant for security research purposes, not for application crackers.

[+] Found encrypted data at address 00002000 of length 1826816 bytes - type 1.
[+] Opening /private/var/mobile/Applications/xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx/Scan.app/Scan for reading.
[+] Reading header
[+] Detecting header type
[+] Executable is a FAT image - searching for right architecture
[+] Correct arch is at offset 2408224 in the file
[+] Opening Scan.decrypted for writing.
[-] Failed opening. Most probably a sandbox issue. Trying something different.
[+] Opening /private/var/mobile/Applications/xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx/tmp/Scan.decrypted for writing.
[+] Copying the not encrypted start of the file
[+] Dumping the decrypted data into the file
[+] Copying the not encrypted remainder of the file
[+] Closing original file
[+] Closing dump file

*/
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <fcntl.h>
#include <mach-o/fat.h>
#include <mach-o/loader.h>

struct ProgramVars {
  struct mach_header*	mh;
  int*		NXArgcPtr;
  const char***	NXArgvPtr;
  const char***	environPtr;
  const char**	__prognamePtr;
};

#define swap32(value) (((value & 0xFF000000) >> 24) | ((value & 0x00FF0000) >> 8) | ((value & 0x0000FF00) << 8) | ((value & 0x000000FF) << 24) )

__attribute__((constructor))
void dumptofile(int argc, const char **argv, const char **envp, const char **apple, struct ProgramVars *pvars)
{	
	struct load_command *lc;
	struct encryption_info_command *eic;
	struct fat_header *fh;
	struct fat_arch *arch;
	struct mach_header *mh;
	char buffer[1024];
	// char rpath[4096],npath[4096]; /* should be big enough for PATH_MAX */
	char rpath[4096]; /* should be big enough for PATH_MAX */
	unsigned int fileoffs = 0, off_cryptid = 0, restsize;
	int i,fd,outfd,r,n,toread;
	unsigned int stdoffset = 0;
	char *tmp;
	
	fprintf(stderr, "mach-o decryption dumper\n");
	fprintf(stderr, "DISCLAIMER: This tool is only meant for security research purposes, not for application crackers.\n\n");
	
	/* detect if this is a arm64 binary */
	if (pvars->mh->magic == MH_MAGIC_64) {
		lc = (struct load_command *)((unsigned char *)pvars->mh + sizeof(struct mach_header_64));
		fprintf(stderr, "[+] detected 64bit ARM binary in memory.\n");
	} else { /* we might want to check for other errors here, too */
		lc = (struct load_command *)((unsigned char *)pvars->mh + sizeof(struct mach_header));
		fprintf(stderr, "[+] detected 32bit ARM binary in memory.\n");
	}
	
	/* searching all load commands for an LC_ENCRYPTION_INFO load command */
	for (i=0; i<pvars->mh->ncmds; i++) {
		/*fprintf(stderr, "Load Command (%d): %08x\n", i, lc->cmd);*/
		
		if (lc->cmd == LC_ENCRYPTION_INFO || lc->cmd == LC_ENCRYPTION_INFO_64) {
			eic = (struct encryption_info_command *)lc;
			
			/* If this load command is present, but data is not crypted then exit */
			if (eic->cryptid == 0) {
				break;
			}
			off_cryptid=(off_t)((void*)&eic->cryptid - (void*)pvars->mh);
			fprintf(stderr, "[+] offset to cryptid found: @%p(from %p) = %x\n", &eic->cryptid, pvars->mh, off_cryptid);

			fprintf(stderr, "[+] Found encrypted data at address %08x of length %u bytes - type %u.\n", eic->cryptoff, eic->cryptsize, eic->cryptid);
			
			if (realpath(argv[0], rpath) == NULL) {
				strlcpy(rpath, argv[0], sizeof(rpath));
			}
			
			fprintf(stderr, "[+] Opening %s for reading.\n", rpath);
			fd = open(rpath, O_RDONLY);
			if (fd == -1) {
				fprintf(stderr, "[-] Failed opening.\n");
				_exit(1);
			}
			
			fprintf(stderr, "[+] Reading header\n");
			n = read(fd, (void *)buffer, sizeof(buffer));
			if (n != sizeof(buffer)) {
				fprintf(stderr, "[W] Warning read only %d bytes\n", n);
			}
			
			fprintf(stderr, "[+] Detecting header type\n");
			fh = (struct fat_header *)buffer;
			
			/* Is this a FAT file - we assume the right endianess */
			if (fh->magic == FAT_CIGAM) {
				fprintf(stderr, "[+] Executable is a FAT image - searching for right architecture\n");
				arch = (struct fat_arch *)&fh[1];
				for (i=0; i<swap32(fh->nfat_arch); i++) {
					if ((pvars->mh->cputype == swap32(arch->cputype)) && (pvars->mh->cpusubtype == swap32(arch->cpusubtype))) {
						fileoffs = swap32(arch->offset);
						fprintf(stderr, "[+] Correct arch is at offset %u in the file\n", fileoffs);
						break;
					}
					arch++;
				}
				if (fileoffs == 0) {
					fprintf(stderr, "[-] Could not find correct arch in FAT image\n");
					_exit(1);
				}
			} else if (fh->magic == MH_MAGIC || fh->magic == MH_MAGIC_64) {
				fprintf(stderr, "[+] Executable is a plain MACH-O image\n");
			} else {
				fprintf(stderr, "[-] Executable is of unknown type\n");
				_exit(1);
			}
			
			/* calculate address of beginning of crypted data */
			n = fileoffs + eic->cryptoff;
			
			restsize = lseek(fd, 0, SEEK_END) - n - eic->cryptsize;			
			lseek(fd, 0, SEEK_SET);
			
			if (off_cryptid) {
				off_cryptid+=fileoffs;
			}
			
			fprintf(stderr, "[+] Copying the not encrypted start of the file\n");
			/* first copy all the data before the encrypted data */
			while (n > 0) {
				toread = (n > sizeof(buffer)) ? sizeof(buffer) : n;
				r = read(fd, buffer, toread);
				if (r != toread) {
					fprintf(stderr, "[-] Error reading file\n");
					_exit(1);
				}
				n -= r;
				
				if (off_cryptid) {
					stdoffset += toread;
					if (stdoffset >= off_cryptid) {
						int buf_offset = 1024-(stdoffset-off_cryptid);
						fprintf(stderr, "[+] Setting the LC_ENCRYPTION_INFO->cryptid to 0 at offset %x\n", off_cryptid);
						memset(buffer+(buf_offset), 0, 4);
						off_cryptid = 0;
					}
				}
								
				r = write(STDOUT_FILENO, buffer, toread);				
				if (r != toread) {
					fprintf(stderr, "[-] Error writing file\n");
					_exit(1);
				}
			}
			
			/* now write the previously encrypted data */
			fprintf(stderr, "[+] Dumping the decrypted data into the file\n");
			// r = write(outfd, (unsigned char *)pvars->mh + eic->cryptoff, eic->cryptsize);
			r = write(STDOUT_FILENO, (unsigned char *)pvars->mh + eic->cryptoff, eic->cryptsize);			
			if (r != eic->cryptsize) {
				fprintf(stderr, "[-] Error writing file\n");
				_exit(1);
			}
			
			/* and finish with the remainder of the file */
			n = restsize;
			lseek(fd, eic->cryptsize, SEEK_CUR);
			fprintf(stderr, "[+] Copying the not encrypted remainder of the file\n");
			while (n > 0) {
				toread = (n > sizeof(buffer)) ? sizeof(buffer) : n;
				r = read(fd, buffer, toread);
				if (r != toread) {
					fprintf(stderr, "[-] Error reading file\n");
					_exit(1);
				}
				n -= r;
				
				r = write(STDOUT_FILENO, buffer, toread);	
				if (r != toread) {
					fprintf(stderr, "[-] Error writing file\n");
					_exit(1);
				}
			}

			fprintf(stderr, "[+] Closing original file\n");
			close(fd);
			fprintf(stderr, "[+] Closing dump file\n");

			_exit(0);
		}
		
		lc = (struct load_command *)((unsigned char *)lc+lc->cmdsize);		
	}
	fprintf(stderr, "[-] This mach-o file is not encrypted. Nothing was decrypted.\n");
	_exit(1);
}
