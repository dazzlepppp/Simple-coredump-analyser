#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define EI_NIDENT 16
#define ELF32_ST_BIND(i)	((i)>>4)
#define ELF32_ST_TYPE(i)	((i)&0xf)
#define ELF32_ST_INFO(b,t) 	(((b)<<4)+((t)&0xf))

typedef short int Elf32_Half; 
typedef unsigned int Elf32_Word;
typedef unsigned int Elf32_Off;
typedef unsigned int Elf32_Addr;

typedef struct { 
	unsigned char e_ident[EI_NIDENT];
	Elf32_Half e_type;
	Elf32_Half e_machine;
	Elf32_Word e_version;
	Elf32_Addr e_entry;
	Elf32_Off  e_phoff;
	Elf32_Off  e_shoff;
	Elf32_Word e_flags;
	Elf32_Half e_ehsize;
	Elf32_Half e_phentsize;
	Elf32_Half e_phnum;
	Elf32_Half e_shentsize;
	Elf32_Half e_shnum;
	Elf32_Half e_shstrndx;
} Elf32_Ehdr; 

typedef struct {
	Elf32_Word sh_name;
	Elf32_Word sh_type;
	Elf32_Word sh_flags;
	Elf32_Addr sh_addr;
	Elf32_Off  sh_offset;
	Elf32_Word sh_size;
	Elf32_Word sh_link;
	Elf32_Word sh_info;
	Elf32_Word sh_addralign;
	Elf32_Word sh_entsize;
} Elf32_Shdr;

typedef struct {
	Elf32_Word p_type;
	Elf32_Off  p_offset;
	Elf32_Addr p_vaddr;
	Elf32_Addr p_paddr;
	Elf32_Word p_filesz;
	Elf32_Word p_memsz;
	Elf32_Word p_flags;
	Elf32_Word p_align;
} Elf32_Phdr;


unsigned int u32(char string[])
{
	int i;
	unsigned int result = 0;
	strncpy((char *)&result, string, 4);
	return result;
}

unsigned int ForwardTrace(FILE *fp, unsigned int TextStart, unsigned int TextRange, unsigned int StackBase, int EspOffset)
{
	int offset = EspOffset;
	unsigned int value;
	char buf[5];
	while ( offset > 0 )
	{
		memset(buf, 0, 5);
		fseek(fp, StackBase + offset, SEEK_SET);
		fread(buf, 4, 1, fp);
		value = u32(buf);
		if ( value > TextStart && value < (TextStart + TextRange) )
			return ((value - 5) - TextStart);
			//return value;
		else
			offset = offset - 4;
	}
	return 0;
}

unsigned int BackTrace(FILE *fp, unsigned int TextStart, unsigned int TextRange, unsigned int start, int range)
{
	int offset = 0;
	unsigned int value;
	char buf[5];
	while ( offset <= range )
	{
		memset(buf, 0, 5);
		fseek(fp, start + offset, SEEK_SET);
		fread(buf, 4, 1, fp);
		value = u32(buf);
		if ( value > TextStart && value < (TextStart + TextRange) )
			return ((value - 5) - TextStart);
			//return value;
		else
			offset = offset + 4;
	}
	return 0;
}

void ReadElfHeader(FILE *fp, Elf32_Ehdr *elfhdr, void *fphdr)
{
	fphdr = malloc(sizeof(Elf32_Ehdr));
	fread(fphdr, sizeof(Elf32_Ehdr),1, fp);
	
	
	int i;
	for ( i = 0; i < 16; i ++ )
		elfhdr->e_ident[i] = ((Elf32_Ehdr*)fphdr)->e_ident[i];
	
	elfhdr->e_ident[6] = ((Elf32_Ehdr*)fphdr)->e_ident[6];
	elfhdr->e_type = ((Elf32_Ehdr*)fphdr)->e_type;
	elfhdr->e_machine = ((Elf32_Ehdr*)fphdr)->e_machine;
	elfhdr->e_entry = ((Elf32_Ehdr*)fphdr)->e_entry;
	elfhdr->e_phoff = ((Elf32_Ehdr*)fphdr)->e_phoff;
	elfhdr->e_shoff = ((Elf32_Ehdr*)fphdr)->e_shoff;
	elfhdr->e_phentsize = ((Elf32_Ehdr*)fphdr)->e_phentsize;
	elfhdr->e_phnum = ((Elf32_Ehdr*)fphdr)->e_phnum;
	elfhdr->e_shentsize = ((Elf32_Ehdr*)fphdr)->e_shentsize; 
	elfhdr->e_shnum = ((Elf32_Ehdr*)fphdr)->e_shnum;
	elfhdr->e_shstrndx = ((Elf32_Ehdr*)fphdr)->e_shstrndx;
}

int main(int argc, char* argv[])
{
	int i, j;
	FILE *fp;
	void *fphdr;
	void *shdr;
	void *phdr;
	ssize_t size;
	Elf32_Ehdr elfhdr;

	fp = fopen(argv[2], "r");
	
	ReadElfHeader(fp, &elfhdr, fphdr);
	
	fseek(fp, elfhdr.e_shoff, SEEK_SET);
	shdr = malloc(sizeof(Elf32_Shdr)*elfhdr.e_shnum);
	size = fread(shdr, sizeof(Elf32_Shdr),elfhdr.e_shnum, fp);
	
	char SectionName[128];
	//printf("%d\n", elfhdr.e_shnum);
	for ( i = 0; i < elfhdr.e_shnum; i ++ )
	{
		j = 0;
		//printf("%d\n", i);
		//printf("* [%2d]",i); 
		//memset(SectionName, 0, 128);
		fseek(fp, ((((Elf32_Shdr*)shdr)[elfhdr.e_shstrndx]).sh_offset + (((Elf32_Shdr*)shdr)[i]).sh_name), SEEK_SET);
		do
		{
			SectionName[j] = getc(fp);		
		}while('\0' != SectionName[j++]);
		//printf("%s\n", SectionName);
		if ( !strcmp(SectionName, ".text") )
			break;
	}
	int TextRange, TextStart, TextOffset;
	TextOffset = (((Elf32_Shdr*)shdr)[i]).sh_offset;
	TextStart = (((Elf32_Shdr*)shdr)[i]).sh_addr;
	TextRange = (((Elf32_Shdr*)shdr)[i]).sh_size;
	
	close(fp);
	fp = fopen(argv[1], "r");
	
	ReadElfHeader(fp, &elfhdr, fphdr);
	
	fseek(fp, elfhdr.e_shoff, SEEK_SET);
	shdr = malloc(sizeof(Elf32_Shdr)*elfhdr.e_shnum);
	size = fread(shdr, sizeof(Elf32_Shdr),elfhdr.e_shnum, fp);
	
	fseek(fp, elfhdr.e_phoff, SEEK_SET);
	phdr = malloc(sizeof(Elf32_Phdr)*elfhdr.e_phnum);
	size = fread(phdr, sizeof(Elf32_Phdr), elfhdr.e_phnum, fp);

	int NoteBase, StackBase, VirtStackBase;
	int StackSize;
	int OffsetToNote_ebp = 0x70, OffsetToNote_esp = 0x98;
	char buf[5];
	
	NoteBase = (((Elf32_Phdr*)phdr)[0]).p_offset;
	StackBase = (((Elf32_Phdr*)phdr)[elfhdr.e_phnum - 1]).p_offset;
	VirtStackBase = (((Elf32_Phdr*)phdr)[elfhdr.e_phnum - 1]).p_vaddr;
	StackSize = (((Elf32_Phdr*)phdr)[elfhdr.e_phnum - 1]).p_memsz;
	
	printf("Note base:       0x%08x\n", NoteBase);
	printf("Stack base:      0x%08x\n", StackBase);
	printf("Stack VirAddr:   0x%08x\n", VirtStackBase);
	printf("Stack size:      0x%08x\n", StackSize);
	printf("Text start:      0x%08x\n", TextStart);
	printf("Text range:      0x%08x\n", TextRange);
	
	fseek(fp, NoteBase + OffsetToNote_ebp, SEEK_SET);
	memset(buf, 0, 5);
	fread(buf, 4, 1, fp);
	
	int EbpPtr = u32(buf);
	
	printf("ebp ptr: 0x%08x\n", EbpPtr);

	fseek(fp, NoteBase + OffsetToNote_esp, SEEK_SET);
	memset(buf, 0, 5);
	fread(buf, 4, 1, fp);
	
	int EspPtr = u32(buf);
	
	printf("esp ptr: 0x%08x\n", EspPtr);
	
	int OffsetToStack_ebp = EbpPtr - VirtStackBase;
	int OffsetToStack_esp = EspPtr - VirtStackBase;
	
	printf("ebp ptr offset: 0x%08x\n", OffsetToStack_ebp);
	printf("esp ptr offset: 0x%08x\n", OffsetToStack_esp);
	
	if ( OffsetToStack_ebp < 0 || OffsetToStack_ebp > StackSize )
	{
		unsigned int VulAddr = ForwardTrace(fp, TextStart, TextRange, StackBase, OffsetToStack_esp);
		printf("Stack Overflow Detected\n");
		printf("Vul Offset To Binary:    0x%08x\n", VulAddr + TextOffset);
		printf("Vul Address:             0x%08x\n", VulAddr + TextStart);
		close(fp);
		return 0;
	}
	
	unsigned int VulAddr = BackTrace(fp, TextStart, TextRange, OffsetToStack_ebp + StackBase, StackSize - OffsetToStack_ebp);
	
	printf("Vul Offset To Binary:    0x%08x\n", VulAddr + TextOffset);
	printf("Vul Address:             0x%08x\n", VulAddr + TextStart);
	
	close(fp);
	
	return 0;
}
