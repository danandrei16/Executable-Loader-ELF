/*
 * Loader Implementation
 *
 * 2022, Operating Systems
 */

#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <signal.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/mman.h>
#include <stdbool.h>

#include "exec_parser.h"

#define PAGESIZE 4096
#define ERR 139

static so_exec_t *exec; /* executabil */
static int fd; /* descriptor */

void mapping(so_seg_t *segment, int faultOffset, bool zero)
{
	/* mapez pagina la adresa calculata */
	void *page = mmap((void *)(segment->vaddr + faultOffset), PAGESIZE, PROT_READ | PROT_WRITE, MAP_FIXED | MAP_SHARED | MAP_ANONYMOUS, -1, 0);
	char file[PAGESIZE] = "";

	read(fd, file, PAGESIZE);
	memcpy(page, file, PAGESIZE); /* copiez datele in pagina */
	/* zona zeroizata intre file_size si mem_size */
	if (zero == true)
		memset((void *)(segment->vaddr + segment->file_size), 0, PAGESIZE - segment->file_size + faultOffset - 1);
	mprotect(page, PAGESIZE, segment->perm);
}
/* verific daca pagina este deja mapata */
void check_perms(so_seg_t *segment)
{
	if (!segment->data)
		segment->data = (void *)"page is now mapped";
	else
		exit(ERR);
}

static void segv_handler(int signum, siginfo_t *info, void *context)
{
	so_seg_t *segm = NULL;
	int faultAddr = (int)info->si_addr;
	/* caut segmentul care contine eroarea si il retin */
	for (int i = 0; i < exec->segments_no; i++)
		if (exec->segments[i].vaddr <= faultAddr && faultAddr <= exec->segments[i].vaddr + exec->segments[i].mem_size) {
			segm = &(exec->segments[i]);
			break;
		}
	/* eroarea nu e in niciun segment */
	if (!segm)
		exit(ERR);
	/* calculez inceputul paginii ce contine eroarea (maparea se va face la inceput de pagina) */
	int faultOffset = faultAddr - segm->vaddr;

	while (faultOffset % PAGESIZE)
		faultOffset--;

	lseek(fd, faultOffset + segm->offset, SEEK_SET); /* repozitionez offsetul pentru a citi dupa offset-ul fisierului */
	if (faultOffset <= segm->file_size) {
		bool setToZero = false;

		if ((int)(segm->file_size - faultOffset) < PAGESIZE) {
			/* daca o portiune din pagina mapata va depasi file_size, aceasta va fi zeroizata */
			check_perms(segm);
			setToZero = true;
		}
		mapping(segm, faultOffset, setToZero);
	} else {
		/* se mapeaza in intregime peste file_size */
		mmap((void *)(segm->vaddr + faultOffset), PAGESIZE, PROT_READ | PROT_WRITE, MAP_FIXED | MAP_SHARED | MAP_ANONYMOUS, -1, 0);
	}
}

int so_init_loader(void)
{
	int rc;
	struct sigaction sa;

	memset(&sa, 0, sizeof(sa));
	sa.sa_sigaction = segv_handler;
	sa.sa_flags = SA_SIGINFO;
	rc = sigaction(SIGSEGV, &sa, NULL);
	if (rc < 0) {
		perror("sigaction");
		return -1;
	}
	return 0;
}

int so_execute(char *path, char *argv[])
{
	fd = open(path, O_RDONLY); /* descriptorul */
	exec = so_parse_exec(path);
	if (!exec)
		return -1;
	so_start_exec(exec, argv);
	close(fd);
	return -1;
}
