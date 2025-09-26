#include <cstdio>
#include <cstring>

#include "md5.h"
#include "util.h"
#include "xxhash.h"

// uint64_t weakHash(unsigned char *buf, int len) {
//   uint64_t res = 0;
//   if (len <= 8)
//   {
//     memcpy((uint8_t*)&res, buf, len);
//   }
//   else
//   {
//     for (int i = 0; i < 8; i++)
//     {
//       memcpy((uint8_t*)(&res) + i, buf + (len / 8) * i, 1);
//     }
//   }

//   return res;
// }

uint64_t weakHash(unsigned char *buf, int len) {
  uint64_t seed = 0x7fcaf1;
  uint64_t p1=0x9e3779b185ebca87,p2=0xc2b2ae3d27d4eb4f,p3=0x165667b19e3779f9;
  uint64_t p4=0x85ebca77c2b2ae63,p5=0x27d4eb2f165667c5;
  uint64_t n=len,h=seed+p5+n,x,v0=seed+p1+p2,v1=seed+p2,v2=seed+0,v3=seed-p1;
  uint8_t *p=(uint8_t*)buf;
  #define XXH8()(x=*((uint64_t*)p),p+=8,len-=8,x)
  #define XXH4()(x=*((uint32_t*)p),p+=4,len-=4,x)
  #define XXHR(x,r)(((x)<<(r))|((x)>>(64-(r))))
  #define XXHS(v)v+=XXH8()*p2,v=XXHR(v,31),v*=p1
  #define XXHF(v)v*=p2,v=XXHR(v,31),v*=p1,h^=v,h=h*p1+p4
  if(n<32)goto l8;
  do XXHS(v0),XXHS(v1),XXHS(v2),XXHS(v3);while(len>=32);
  h=XXHR(v0,1)+XXHR(v1,7)+XXHR(v2,12)+XXHR(v3,18);
  XXHF(v0),XXHF(v1),XXHF(v2),XXHF(v3),h+=n;
  l8:while(len>=8)XXH8(),x*=p2,x=XXHR(x,31),x*=p1,h^=x,h=XXHR(h,27)*p1+p4;
  if(len>=4)h^=XXH4()*p1,h=XXHR(h,23)*p2+p3;
  while(len)h^=(*p)*p5,h=XXHR(h,11)*p1,p++,len--;
  h=(h^(h>>33))*p2;h=(h^(h>>29))*p3;h=(h^(h>>32));
  return h;
}

// jump by STRMIN bytes
/* different from rolling_gear_v2, where @n indicates the bytes left in @p that
 * can be chunked. And rolling_gear_v2 is abandoned.
 */
int rolling_gear_v3(unsigned char *p, int n, int num_of_chunks, int *cut) {
  uint32_t fingerprint = 0;
  int i = 0, count = 0;
  cut[count++] = 0;

  i += STRMIN + 1;

  int j = 0;
  while (j < num_of_chunks) {
    if (i < n) {
      fingerprint = (fingerprint << 1) + GEAR[p[i]];
      if (i <= (cut[count - 1] + STRMAX)) {
        if (!(fingerprint & STRAVG)) {
          /* this requires the last few bits of fingerprint to be all 0 */
          cut[count++] = i;
          i += STRMIN;
          fingerprint = 0;
          j++;
        }
      } else {
        cut[count++] = i;
        i += STRMIN;
        fingerprint = 0;
        j++;
      }
      i++;
    } else {
      while (j < num_of_chunks) {
        cut[count++] = n;
        j++;
      }

      break;
    }
  }

  return cut[count - 1];
}

// jump by STRMIN bytes
int chunk_gear(unsigned char *p, int n) {
  uint32_t fingerprint = 0;
  int i = STRMIN + 1;
  if (n <= STRMAX) {
    return n;
  }

  while (i <= n) {
    fingerprint = (fingerprint << 1) + GEAR[p[i]];
    if (i <= STRMAX) {
      if (!(fingerprint & STRAVG))
        return i;
    } else {
      return i;
    }
    i++;
  }
  return i;
}

#ifndef PREDEFINED_GEAR_MATRIX
uint32_t GEAR[256];

void PrintGearV2() {
  printf("uint32_t gear_matrix[256] = {\n");
  for (int i = 0; i < 255; ++i) {
    if (i % 3 == 0)
      printf("\n   ");
    printf("%0#8x, ", GEAR[i]);
  }
  printf("}\n");
}

void InitGearMatrix() {
  const uint32_t SymbolTypes = 256;
  const uint32_t MD5Length = 16;
  const int SeedLength = 32;

  char seed[SeedLength];
  for (int i = 0; i < SymbolTypes; i++) {
    for (int j = 0; j < SeedLength; j++) {
      seed[j] = i;
    }

    GEAR[i] = 0;
    char md5_result[MD5Length];
    md5_state_t md5_state;
    md5_init(&md5_state);
    md5_append(&md5_state, (md5_byte_t *)seed, SeedLength);
    md5_finish(&md5_state, (md5_byte_t *)md5_result);

    memcpy(&GEAR[i], md5_result, sizeof(uint32_t));
  }
  PrintGearV2();
}
#endif

uint32_t GEAR[256] = {
    0x4b8fbc70, 0x95a75be0, 0x7fa97617, 0xdb51a0d,  0x7c71d5b3, 0x97842403,
    0x87d60b89, 0x10c081cb, 0x176c2faf, 0xc7392648, 0x2f15cf70, 0x842062ac,
    0x7d19bc1b, 0xc9a22b6d, 0x29f65703, 0x54f0a470, 0x4913c078, 0x91dd2661,
    0xce401296, 0x1080796b, 0x3c6ba084, 0x291fd606, 0x1be96ae,  0x5e104df3,
    0x953a3946, 0xd59e7f77, 0x9f4734d9, 0xf095c27c, 0xe4448418, 0x47ca4676,
    0xe9131404, 0xc6965ee3, 0x2f46c05a, 0x8ba2c750, 0x5fb2fec6, 0xaae07db7,
    0xf96ad818, 0xaed74a8d, 0x3b73296d, 0x42b47c83, 0x3f14fa76, 0xe775583b,
    0x8583a649, 0xe347effd, 0x1814ed33, 0xd747a499, 0x1241b4c,  0xc2ba1de6,
    0x9e459ecd, 0xf2cb801a, 0xb1575ba0, 0x57230ea3, 0xfd6e88ca, 0x1d0501a2,
    0xf33ed508, 0x531f339c, 0xece73621, 0x2171ee60, 0xc545563a, 0x3b68b071,
    0x480657e4, 0x69b955c1, 0x954a24b1, 0xc458ee33, 0x48958571, 0xccdd1652,
    0xa67ad0f0, 0xa93e0890, 0x8255fe6,  0xc190ff58, 0x6d2966a,  0x1e3e1a20,
    0x1649fd23, 0xa5452efe, 0x247ce55,  0xf4220d84, 0xf817eb4b, 0xab0ff6bf,
    0xd98c80da, 0xbb660cad, 0xce39b4a0, 0xebfa6bfe, 0xc4baba1b, 0x5cfd0930,
    0x7cdba262, 0xab2c4cdb, 0xdd1858e7, 0x7aa35c54, 0x36c7793b, 0xc3298957,
    0x5212e006, 0x772a10b3, 0x4b412801, 0x6348ea44, 0x90b7a8c,  0xf3903817,
    0x55ec8d5,  0xd39bca5e, 0xa19e4f8b, 0xf8472700, 0xd792025e, 0xcfdc83e0,
    0x576880c7, 0xcbaa6558, 0x692f5350, 0x1400ee49, 0x3a89aa8b, 0x46873d99,
    0x63ecb853, 0x9860b122, 0x31685257, 0x32874e3d, 0x6b44e063, 0x87525cd0,
    0xf0a5025c, 0x6ccb4020, 0xf1d8849d, 0x414f66e7, 0x6afed5a4, 0x9a9befeb,
    0xd6e18fdc, 0x27129a4c, 0x7d6bcf28, 0x37fa944a, 0xe9b09b54, 0x9159093,
    0x4a31242,  0x28d0d7d2, 0x97e8d65a, 0xfcf68625, 0x1800702,  0x39dbe43f,
    0x35da0210, 0xa6c68d9,  0x68500f4e, 0xc8a5ab6e, 0x8b2b756a, 0xd5fb25bd,
    0xb0c0405d, 0xc453b18c, 0xe2e66ea4, 0xda553370, 0x7dbc5759, 0x886eeab,
    0x9fafd0e5, 0x4e430b,   0x8331c2e5, 0x5a5d06b4, 0xe43f7b9d, 0xf3ec3644,
    0x6a46d11,  0xcd41e503, 0xa18a2e19, 0xadde1ea1, 0x36f7488e, 0x455255bd,
    0x8075175e, 0x88d32d58, 0x9a0a25b0, 0x970e0c67, 0x77b009e,  0x12d5bf75,
    0xdc7fd18,  0xde77a2bb, 0x6ab176e0, 0xa6ab6c09, 0x6210efa8, 0xd947e049,
    0x5fb01605, 0xde4bd448, 0x5b2af7ba, 0xd2b49fe9, 0x1783f531, 0x66fffd39,
    0x59e8a9ba, 0xc2ee818b, 0x1f3b0f3c, 0x4cd0e620, 0xeaf278ba, 0x92045e3d,
    0x64e6ebca, 0x9b70573,  0x3aaf57a4, 0xe287e26,  0x54dcafbb, 0x8c25a8,
    0x99642381, 0x5c8de9f0, 0x51fda6c0, 0x910e0b6d, 0xf6328e12, 0xec5e5389,
    0x8ed195f,  0xe80f0583, 0xa7185a25, 0xa83c3268, 0xa4e79433, 0xe6def4b,
    0x77065b1f, 0x43678dc7, 0x7e506399, 0x88503f60, 0x62c4983d, 0x70ece12,
    0xe0d421a4, 0x71821295, 0x801310e8, 0x3bd7bf4b, 0xe42779be, 0xefee3449,
    0xd6aaaffc, 0xa5608bae, 0xf6e0b8ae, 0xdd79aa9f, 0x8bd6606d, 0x3b83977a,
    0x512a0c70, 0x2c6de88,  0x25f5ea97, 0x68ceb140, 0xdaa87097, 0x602b8497,
    0x7767467a, 0xfee216a8, 0x14512325, 0x142c4e04, 0x7bf5ac09, 0x384364d5,
    0xf58188a8, 0xa410598,  0x799223f,  0xc1b76b42, 0xd828d74b, 0x931ecbb1,
    0x41922ad3, 0x787fb489, 0xf41c1d00, 0x3dbc3f88, 0x12a70e39, 0x26ae363d,
    0x47f7274,  0x86385074, 0x2ffb7263, 0xb8e3de33, 0x9496a61,  0x92025809,
    0xbf8b296d, 0xf1a57003, 0xa8057fb6, 0x2ce2e565, 0x56d7a64a, 0xa6e30007,
    0xe0562996, 0xabec18bd, 0x6b8c68ed};

uint64_t GEARmx[256] = {
    0xb088d3a9e840f559,
    0x5652c7f739ed20d6,
    0x45b28969898972ab,
    0x6b0a89d5b68ec777,
    0x368f573e8b7a31b7,
    0x1dc636dce936d94b,
    0x207a4c4e5554d5b6,
    0xa474b34628239acb,
    0x3b06a83e1ca3b912,
    0x90e78d6c2f02baf7,
    0xe1c92df7150d9a8a,
    0x8e95053a1086d3ad,
    0x5a2ef4f1b83a0722,
    0xa50fac949f807fae,
    0x0e7303eb80d8d681,
    0x99b07edc1570ad0f,
    0x689d2fb555fd3076,
    0x00005082119ea468,
    0xc4b08306a88fcc28,
    0x3eb0678af6374afd,
    0xf19f87ab86ad7436,
    0xf2129fbfbe6bc736,
    0x481149575c98a4ed,
    0x0000010695477bc5,
    0x1fba37801a9ceacc,
    0x3bf06fd663a49b6d,
    0x99687e9782e3874b,
    0x79a10673aa50d8e3,
    0xe4accf9e6211f420,
    0x2520e71f87579071,
    0x2bd5d3fd781a8a9b,
    0x00de4dcddd11c873,
    0xeaa9311c5a87392f,
    0xdb748eb617bc40ff,
    0xaf579a8df620bf6f,
    0x86a6e5da1b09c2b1,
    0xcc2fc30ac322a12e,
    0x355e2afec1f74267,
    0x2d99c8f4c021a47b,
    0xbade4b4a9404cfc3,
    0xf7b518721d707d69,
    0x3286b6587bf32c20,
    0x0000b68886af270c,
    0xa115d6e4db8a9079,
    0x484f7e9c97b2e199,
    0xccca7bb75713e301,
    0xbf2584a62bb0f160,
    0xade7e813625dbcc8,
    0x000070940d87955a,
    0x8ae69108139e626f,
    0xbd776ad72fde38a2,
    0xfb6b001fc2fcc0cf,
    0xc7a474b8e67bc427,
    0xbaf6f11610eb5d58,
    0x09cb1f5b6de770d1,
    0xb0b219e6977d4c47,
    0x00ccbc386ea7ad4a,
    0xcc849d0adf973f01,
    0x73a3ef7d016af770,
    0xc807d2d386bdbdfe,
    0x7f2ac9966c791730,
    0xd037a86bc6c504da,
    0xf3f17c661eaa609d,
    0xaca626b04daae687,
    0x755a99374f4a5b07,
    0x90837ee65b2caede,
    0x6ee8ad93fd560785,
    0x0000d9e11053edd8,
    0x9e063bb2d21cdbd7,
    0x07ab77f12a01d2b2,
    0xec550255e6641b44,
    0x78fb94a8449c14c6,
    0xc7510e1bc6c0f5f5,
    0x0000320b36e4cae3,
    0x827c33262c8b1a2d,
    0x14675f0b48ea4144,
    0x267bd3a6498deceb,
    0xf1916ff982f5035e,
    0x86221b7ff434fb88,
    0x9dbecee7386f49d8,
    0xea58f8cac80f8f4a,
    0x008d198692fc64d8,
    0x6d38704fbabf9a36,
    0xe032cb07d1e7be4c,
    0x228d21f6ad450890,
    0x635cb1bfc02589a5,
    0x4620a1739ca2ce71,
    0xa7e7dfe3aae5fb58,
    0x0c10ca932b3c0deb,
    0x2727fee884afed7b,
    0xa2df1c6df9e2ab1f,
    0x4dcdd1ac0774f523,
    0x000070ffad33e24e,
    0xa2ace87bc5977816,
    0x9892275ab4286049,
    0xc2861181ddf18959,
    0xbb9972a042483e19,
    0xef70cd3766513078,
    0x00000513abfc9864,
    0xc058b61858c94083,
    0x09e850859725e0de,
    0x9197fb3bf83e7d94,
    0x7e1e626d12b64bce,
    0x520c54507f7b57d1,
    0xbee1797174e22416,
    0x6fd9ac3222e95587,
    0x0023957c9adfbf3e,
    0xa01c7d7e234bbe15,
    0xaba2c758b8a38cbb,
    0x0d1fa0ceec3e2b30,
    0x0bb6a58b7e60b991,
    0x4333dd5b9fa26635,
    0xc2fd3b7d4001c1a3,
    0xfb41802454731127,
    0x65a56185a50d18cb,
    0xf67a02bd8784b54f,
    0x696f11dd67e65063,
    0x00002022fca814ab,
    0x8cd6be912db9d852,
    0x695189b6e9ae8a57,
    0xee9453b50ada0c28,
    0xd8fc5ea91a78845e,
    0xab86bf191a4aa767,
    0x0000c6b5c86415e5,
    0x267310178e08a22e,
    0xed2d101b078bca25,
    0x3b41ed84b226a8fb,
    0x13e622120f28dc06,
    0xa315f5ebfb706d26,
    0x8816c34e3301bace,
    0xe9395b9cbb71fdae,
    0x002ce9202e721648,
    0x4283db1d2bb3c91c,
    0xd77d461ad2b1a6a5,
    0xe2ec17e46eeb866b,
    0xb8e0be4039fbc47c,
    0xdea160c4d5299d04,
    0x7eec86c8d28c3634,
    0x2119ad129f98a399,
    0xa6ccf46b61a283ef,
    0x2c52cedef658c617,
    0x2db4871169acdd83,
    0x0000f0d6f39ecbe9,
    0x3dd5d8c98d2f9489,
    0x8a1872a22b01f584,
    0xf282a4c40e7b3cf2,
    0x8020ec2ccb1ba196,
    0x6693b6e09e59e313,
    0x0000ce19cc7c83eb,
    0x20cb5735f6479c3b,
    0x762ebf3759d75a5b,
    0x207bfe823d693975,
    0xd77dc112339cd9d5,
    0x9ba7834284627d03,
    0x217dc513e95f51e9,
    0xb27b1a29fc5e7816,
    0x00d5cd9831bb662d,
    0x71e39b806d75734c,
    0x7e572af006fb1a23,
    0xa2734f2f6ae91f85,
    0xbf82c6b5022cddf2,
    0x5c3beac60761a0de,
    0xcdc893bb47416998,
    0x6d1085615c187e01,
    0x77f8ae30ac277c5d,
    0x917c6b81122a2c91,
    0x5b75b699add16967,
    0x0000cf6ae79a069b,
    0xf3c40afa60de1104,
    0x2063127aa59167c3,
    0x621de62269d1894d,
    0xd188ac1de62b4726,
    0x107036e2154b673c,
    0x0000b85f28553a1d,
    0xf2ef4e4c18236f3d,
    0xd9d6de6611b9f602,
    0xa1fc7955fb47911c,
    0xeb85fd032f298dbd,
    0xbe27502fb3befae1,
    0xe3034251c4cd661e,
    0x441364d354071836,
    0x0082b36c75f2983e,
    0xb145910316fa66f0,
    0x021c069c9847caf7,
    0x2910dfc75a4b5221,
    0x735b353e1c57a8b5,
    0xce44312ce98ed96c,
    0xbc942e4506bdfa65,
    0xf05086a71257941b,
    0xfec3b215d351cead,
    0x00ae1055e0144202,
    0xf54b40846f42e454,
    0x00007fd9c8bcbcc8,
    0xbfbd9ef317de9bfe,
    0xa804302ff2854e12,
    0x39ce4957a5e5d8d4,
    0xffb9e2a45637ba84,
    0x55b9ad1d9ea0818b,
    0x00008acbf319178a,
    0x48e2bfc8d0fbfb38,
    0x8be39841e848b5e8,
    0x0e2712160696a08b,
    0xd51096e84b44242a,
    0x1101ba176792e13a,
    0xc22e770f4531689d,
    0x1689eff272bbc56c,
    0x00a92a197f5650ec,
    0xbc765990bda1784e,
    0xc61441e392fcb8ae,
    0x07e13a2ced31e4a0,
    0x92cbe984234e9d4d,
    0x8f4ff572bb7d8ac5,
    0x0b9670c00b963bd0,
    0x62955a581a03eb01,
    0x645f83e5ea000254,
    0x41fce516cd88f299,
    0xbbda9748da7a98cf,
    0x0000aab2fe4845fa,
    0x19761b069bf56555,
    0x8b8f5e8343b6ad56,
    0x3e5d1cfd144821d9,
    0xec5c1e2ca2b0cd8f,
    0xfaf7e0fea7fbb57f,
    0x000000d3ba12961b,
    0xda3f90178401b18e,
    0x70ff906de33a5feb,
    0x0527d5a7c06970e7,
    0x22d8e773607c13e9,
    0xc9ab70df643c3bac,
    0xeda4c6dc8abe12e3,
    0xecef1f410033e78a,
    0x0024c2b274ac72cb,
    0x06740d954fa900b4,
    0x1d7a299b323d6304,
    0xb3c37cb298cbead5,
    0xc986e3c76178739b,
    0x9fabea364b46f58a,
    0x6da214c5af85cc56,
    0x17a43ed8b7a38f84,
    0x6eccec511d9adbeb,
    0xf9cab30913335afb,
    0x4a5e60c5f415eed2,
    0x00006967503672b4,
    0x9da51d121454bb87,
    0x84321e13b9bbc816,
    0xfb3d6fb6ab2fdd8d,
    0x60305eed8e160a8d,
    0xcbbf4b14e9946ce8,
    0x00004f63381b10c3,
    0x07d5b7816fcc4e10,
    0xe5a536726a6a8155,
    0x57afb23447a07fdd,
    0x18f346f7abc9d394,
    0x636dc655d61ad33d,
    0xcc8bab4939f7f3f6,
    0x63c7a906c1dd187b,
};
