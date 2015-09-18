/* radare - LGPL - 2015 - maijin */

#include <r_bin.h>

#define PRG_PAGE_SIZE                       0x4000
#define CHR_PAGE_SIZE                       0x2000
#define INES_HDR_SIZE                       sizeof (ines_hdr)


typedef struct __attribute__((__packed__)) {
	char id[0x4];						  // NES\x1A
	ut8 prg_page_count_16k;			   // number of PRG-ROM pages
	ut8 chr_page_count_8k;				// number of CHR-ROM pages
	ut8 rom_control_byte_0;			   // flags describing ROM image
	ut8 rom_control_byte_1;			   // flags describing ROM image
	ut8 ram_bank_count_8k;				// size of PRG RAM
	ut8 reserved[7];					  // zero filled
} ines_hdr;


static int check(RBinFile *arch);
static int check_bytes(const ut8 *buf, ut64 length);

static void * load_bytes(RBinFile *arch, const ut8 *buf, ut64 sz, ut64 loadaddr, Sdb *sdb){
	check_bytes (buf, sz);
	return R_NOTNULL;
}

static int check(RBinFile *arch) {
	const ut8 *bytes = arch ? r_buf_buffer (arch->buf) : NULL;
	ut64 sz = arch ? r_buf_size (arch->buf): 0;
	return check_bytes (bytes, sz);
}

static int check_bytes(const ut8 *buf, ut64 length) {
	if (!buf || length < 4) return false;
	return (!memcmp (buf, "\x4E\x45\x53\x1A", 4));
}

static RBinInfo* info(RBinFile *arch) {
	RBinInfo *ret = NULL;
  ines_hdr ihdr;
  memset (&ihdr, 0, sizeof (ihdr));
  int reat = r_buf_read_at (arch->buf, 0, (ut8*)&ihdr, sizeof (ihdr));
  if (reat != sizeof (ihdr)) {
		eprintf ("Truncated Header\n");
		return NULL;
  }

  if (!(ret = R_NEW0 (RBinInfo)))
		return NULL;

	ret->file = strdup (arch->file);
	ret->type = strdup ("ROM");
	ret->machine = strdup ("Nintendo NES");
	ret->os = strdup ("nes");
	ret->arch = strdup ("6502");
	ret->bits = 8;

	return ret;
}

static RList* sections(RBinFile *arch) {
  ut64 textsize = UT64_MAX;
  RList *ret = NULL;
  RBinSection *ptr = NULL;
  ines_hdr ihdr;
  memset (&ihdr, 0, sizeof (ihdr));
  int reat = r_buf_read_at (arch->buf, 0, (ut8*)&ihdr, sizeof (ihdr));
  if (reat != sizeof (ihdr)) {
		eprintf ("Truncated Header\n");
		return NULL;
  }

  if (!(ret = r_list_new ()))
		return NULL;
	ret->free = free;
  int i;
  ut64 first_chr_chunk;
  for(i=0; i<ihdr.prg_page_count_16k; i++) {
		if (!(ptr = R_NEW0 (RBinSection)))
  		return ret;
		char* section_name;
		asprintf(&section_name, "PRG %i",i);
		strcpy (ptr->name, section_name);
		ptr->vsize = ptr->size = PRG_PAGE_SIZE;
		ptr->vaddr = ptr->paddr = INES_HDR_SIZE+i*PRG_PAGE_SIZE;
		first_chr_chunk = ptr->vaddr + PRG_PAGE_SIZE;
		r_list_append (ret, ptr);
		free(section_name);
  }
  for(i=0; i<ihdr.chr_page_count_8k; i++) {
		if (!(ptr = R_NEW0 (RBinSection)))
  		return ret;
		char* section_name;
		asprintf(&section_name, "CHR %i",i);
		strcpy (ptr->name, section_name);
		ptr->vsize = ptr->size = CHR_PAGE_SIZE;
		ptr->vaddr = ptr->paddr = first_chr_chunk+i*CHR_PAGE_SIZE;
		r_list_append (ret, ptr);
		free(section_name);
  }

  return ret;
}


struct r_bin_plugin_t r_bin_plugin_nes = {
	.name = "nes",
	.desc = "NES",
	.license = "BSD",
	.init = NULL,
	.fini = NULL,
	.get_sdb = NULL,
	.load = NULL,
	.load_bytes = &load_bytes,
	.check = &check,
	.baddr = NULL,
	.check_bytes = &check_bytes,
	.entries = NULL,
	.sections = sections,
	.info = &info,
};

#ifndef CORELIB
struct r_lib_struct_t radare_plugin = {
	.type = R_LIB_TYPE_BIN,
	.data = &r_bin_plugin_nes,
	.version = R2_VERSION
};
#endif
