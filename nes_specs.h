#ifndef _NES_H
#define _NES_H

#define PRG_PAGE_SIZE                       0x4000
#define CHR_PAGE_SIZE                       0x2000
#define INES_HDR_SIZE                       sizeof (ines_hdr)

#define RAM_START_ADDRESS                   0x0
#define RAM_SIZE                            0x2000

#define IOREGS_START_ADDRESS                0x2000
#define IOREGS_SIZE                         0x2020

#define EXPROM_START_ADDRESS                0x4020
#define EXPROM_SIZE                         0x1FE0

#define SRAM_START_ADDRESS                  0x6000
#define SRAM_SIZE                           0x2000

#define TRAINER_START_ADDRESS               0x7000
#define TRAINER_SIZE                        0x0200

#define ROM_START_ADDRESS                   0x8000
#define ROM_SIZE                            0x8000




#endif // _NES_H