
/*
	https://github.com/m1tch
	Zelda Quest decrypter/password remover.			** little endian only **
	Being released Jan 2020 due to ZC's open source movement.
	For better understanding old ZC encryption methods.

	THIS SOFTWARE IS PROVIDED AS-IS WITH NO GUARANTEES
	YOU ARE FREE TO USE MODIFY OR REDISTRIBUTE
*/

// It's not very pretty; I was trying to put everything into one readable file, and C just felt faster.

// Possible future features:
//	Save file decryption (it's very similar)
//	Quest encryption (decrypt is done, encrypt is next)
//	LZSS (further optimized) quest compression
//	Custom password hash overwrite (enter new pass) - useless though.


#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>

#include <fcntl.h>
#include <limits.h>
#include <string.h>

#include <sys/types.h>									// Needed on some UNIX distros
#include <sys/stat.h>



#ifdef __linux__
#	define O_BINARY 0								// Text format is binary on linux
#endif

#if __STDC_VERSION__ < 199901L
#	if defined(__GNUC__) && ((__GNUC__ > 3) || (__GNUC__ == 3 && __GNUC_MINOR__ >= 1))
#		define restrict __restrict
#	elif defined(_MSC_VER) && _MSC_VER >= 1400
#		define restrict __restrict
#	else
#		define restrict
#	endif
#endif

//#if _MSC_VER && !__INTEL_COMPILER
#ifdef _WIN32
#	include <io.h>
#	pragma warning(disable: 4996)
#	define open		_open
#	define read		_read
#	define write	_write
#	define close	_close
#endif


#define RELEASE_VER		"v0.2"
#define RELEASE_DATE	"Sep 10th 2015"

#define MIN(a,b) (((a)<(b))?(a):(b))
#define MAX(a,b) (((a)>(b))?(a):(b))




// ---- Globals (I'm not proud of it) -----------------------------

const uint8_t cHeaderOff	= 24;							// Where things get interesting (23 for saves)
const uint8_t cKeyNum		= 5;							// Modify if more are added...

const uint16_t cKeyPartsA[] = {0x62E9, 0x7D14, 0x1A82, 0x02BB, 0xE09C};			// If cKeyNum is changed, update these
const uint16_t cKeyPartsB[] = {0x3619, 0xA26B, 0xF03C, 0x7B12, 0x4E8F};
const uint32_t cCryptKeys[] = {0x4C358938, 0x91B2A2D1, 0x4A7C1B87, 0xF93941E6, 0xFD095E94};

uint8_t gKeyIndex;									// Used to determine the key parts (<cKeyNum)
uint32_t gDecryptKey;									// Changes on every decrypted word



// ---- Function declairations ------------------------------------

uint32_t fLZSSUndo(uint8_t* lIn, uint8_t *lOut, int32_t lInLen);			// (http://wikipedia.org/wiki/LZSS)

uint8_t fCryptKey(uint8_t lBytes[32]);							// Gets the decryption key (before undo)
void fCryptUndo(uint8_t* lBytes, uint32_t lLen);					// Decrypts lBytes, up to lLen



// ---- This is actually the password removal stuff ---------------

void fRemovePass(uint8_t* lBytes) {

	const uint8_t cHash[] = {							// It's just an MD5.
		0xd4,0x1d,0x8c,0xd9,0x8f,0x00,0xb2,0x04,
		0xe9,0x80,0x09,0x98,0xec,0xf8,0x42,0x7e					// This is an MD5 of ''.
	};

	memcpy(lBytes+46, cHash, sizeof(cHash));					// This was the "password protection"...

}



// ---- Entrypoint ------------------------------------------------

int main(int lArgC, char **lArgV) {

	char* lProgName	= lArgV[0];							// Name of the program
	char* lInName	= lArgV[1];							// Input file (to decrypt)
	char* lOutName	= lArgV[2];							// Output file (to write)

	if (lArgC != 3) {
		fputs("USAGE: ", stdout);						// fputs doesn't append '\n'
		fputs(lProgName, stdout);
		puts(" <INPUTFILE> <OUTPUTFILE>");					// The usage parameters
		return 0;														// Nothing to do
	}

	puts("Mitch's quest decrypter "RELEASE_VER" ("RELEASE_DATE")");
	puts("Input: 1 encrypted quest (qst) for ZC version 1.92 to 2.50");
	puts("Output: 1 decrypted, decompressed, (password removed) quest (qsu)\n");


	{	// Open file, read, remove pass, write,
		int lRdFile = open(lInName, O_RDONLY|O_BINARY);				// File for reading
		struct stat lInfo;							// File to read metadata
		uint32_t lReadLen;							// Length of the data read
		uint8_t *lRead;								// Data read from the file

		if (lRdFile < 0) {
			puts("File could not be opened!");
			puts(lInName);
			return 1;
		}

		puts("File opened");

		if (fstat(lRdFile, &lInfo) < 0) {					// Get the file metadata (for allocation)
			puts("fstat ERROR!");
			return 1;
		}

		{									// Make sure file is a valid quest
			uint32_t lZeldID;
			read(lRdFile, &lZeldID, 4);					// Comparing first four bytes ("Zeld")
			if (lZeldID != 0x646C655A) {					// NOTE: This is little endian dependant
				puts("Not a valid quest?");
				return 1;
			}
		}

		{
			uint8_t lKeyDat[32];
			lseek(lRdFile, cHeaderOff, SEEK_SET);				// Skip the header data (what is this anyways)
			read(lRdFile, lKeyDat, 32);					// Next 4 bytes are encryption key info
			if (fCryptKey(lKeyDat)) {					// Get the decryption key
				puts("Couldn't find decryption key!");
				return 1;
			}
		}

		lReadLen = lInfo.st_size-cHeaderOff-8;					// 8: First 4 (key), last 4 (junk)
		lseek(lRdFile, cHeaderOff+4, SEEK_SET);					// Earlier I read 32 for samples, so must reseek
		lRead = (uint8_t*)malloc(lReadLen);					// VC may complain without cast

		if (read(lRdFile, lRead, lReadLen) != lReadLen) {			// Read the data from the file
			puts("Couldn't read quest!");
			return 1;
		}

		close(lRdFile);

		fCryptUndo(lRead, lReadLen);						// Decrypt the quest
		puts("Quest decrypted");

		{																// Uses a lot of memory (for demonstration only)
			int lWrFile = open(lOutName, O_WRONLY|O_BINARY|O_CREAT|O_TRUNC, 640);
			uint8_t* lWrite = (uint8_t*)malloc(lReadLen*32);		// Allocate for decompressed buffer
			uint32_t lSize = fLZSSUndo(lRead+4, lWrite, lReadLen);		// Decompress the data (skip first four bytes)
			free(lRead);							// Free old compressed data
			fRemovePass(lWrite);						// Remove password from decompressed quest
			write(lWrFile, lWrite, lSize-3);				// Write the decrypted quest (encrypt with ZQ), -3 clips uneeded bytes.
			close(lWrFile);
			free(lWrite);
		}

		puts("Decrypted qsu quest written");

	}

	return 0;

}



// ---- LZSS Compression ------------------------------------------

// ARGS[lIn: Input bytes, lOut: Output bytes, lInLen: lIn length] RETURN[lOut len]
uint32_t fLZSSUndo(uint8_t* lIn, uint8_t *lOut, int32_t lInLen) {

	const uint8_t *cOutSt = lOut;							// LZSS is alredy highly documented
	const uint8_t *cInEnd = lIn + lInLen;

	uint8_t lDictionary[4096+17] = {0};

	uint_fast32_t lFlags = 0;
	int_fast16_t lRingBuf = 4096-18;						// Upper limit for match length

	uint_fast8_t lChar;

	for (;;) {

		if (((lFlags >>= 1) & 0x100) == 0) {
			if (lIn < cInEnd) {
				lFlags = (*lIn++) | 0xFF00;
			} else {
				break;
			}
		}

		if (lFlags & 1) {

			if (lIn >= cInEnd)
				break;

			lChar = *lIn++;
			*lOut++ = lChar;
			lDictionary[lRingBuf++] = lChar;
			lRingBuf &= (4096 - 1);

		} else {

			int32_t lPos, lCnt, lOff;

			if (lIn+2 >= cInEnd)
				break;

			{
				const uint8_t lLow = *lIn++;
				const uint8_t lHigh = *lIn++;
				lPos = lLow | ((lHigh & 0xF0) << 4);			// Upper 12 bits are offset
				lCnt =  (lHigh & 0x0F) + 2;				// Lower 4 are compression
			}

			for (lOff = 0; lOff <= lCnt; ++lOff) {

				lChar = lDictionary[(lPos + lOff) & (4096 - 1)];

				*lOut++ = lChar;
				lDictionary[lRingBuf] = lChar;
				lRingBuf = (lRingBuf+1) & (4096 - 1);

			}

		}

	}
    
	return lOut-cOutSt;

}



// ---- Encryption ------------------------------------------------

uint8_t fCryptKey(uint8_t lBytes[32]) {							// Input offset header length (24), 32 bytes to sample

	// I'm not sure exactly how ZC comes up with this key for decryption...
	// I loop through the five possibilities, perhaps disassembly would shed some light.
	for (gKeyIndex = 0; gKeyIndex < cKeyNum; ++gKeyIndex) {

		uint8_t lTmpBytes[28];
		memcpy(lTmpBytes, lBytes+4, 28);					// First four bytes are encryption key

		gDecryptKey = (lBytes[0]<<24)|(lBytes[1]<<16)|(lBytes[2]<<8)|(lBytes[3]);
		gDecryptKey ^= cCryptKeys[gKeyIndex];					// Test this encryption key

		fCryptUndo(lTmpBytes, 28);						// Decrypt the data

		if ((*(int32_t*)(lTmpBytes+5)) == 0x5a204741)				// Did it decrypt (compare "AG Z", little endian)
			return 0;							// This must the be right key- SUCCESS!

	}

	return 1;									// Failure.

}



// ARGS[lBytes: Input bytes (skip header +4), lLen: Size of lBytes]
void fCryptUndo(uint8_t* lBytes, uint32_t lLen) {

	// I'm looking into making this more legible; it's mostly disassembly.
	const char cXORKey[] = {'l','o','n','g','t','a','n'};				// If this were 8 chars, I'd &7 it.

	const uint32_t lKeyPieceA = cKeyPartsA[gKeyIndex];
	const uint32_t lKeyPieceB = cKeyPartsB[gKeyIndex];

	uint32_t lDecryptKey = gDecryptKey;
	uint32_t lLoop = 0;

	while (lLoop < lLen) {								// Prepare yourself; it needs work.

		int32_t HiWord, MidWord, LoWord;					// Names are based on observation only
		int32_t Flip_A, Flip_B;							// This needs deobfuscated, and better naming

		MidWord = ((lDecryptKey>>8)&0xFFFF);

		LoWord = lDecryptKey>>16;
		Flip_A = Flip_B = 0;

		if (MidWord & 0x8000) {							// if (((int16_t)midWord) < 0)
			MidWord |= 0xFFFF0000;						// Fill upper two bytes
			Flip_A = 0xFFFFFFFF;						// 0xFFFFFFFF is -1
		}

		if (lDecryptKey & 0x80000000) {						// if (((int32_t)lDecryptKey) < 0)
			LoWord |= 0xFFFF0000;						// Fill upper two bytes
			Flip_B = 0xFFFFFFFF;						// 0xFFFFFFFF is -1
		}

		HiWord = (((lDecryptKey<<9)|Flip_A)+lDecryptKey+lKeyPieceA)&0xFFFF;
		LoWord = ((LoWord+Flip_A+Flip_B+lKeyPieceB)+(Flip_B|(MidWord<<1)))&0xFFFF;

		if (LoWord & 0x8000)							// if (((int16_t)LoWord) < 0)
			LoWord |= 0xFFFF0000;

		if (HiWord & 0x8000) {							// if (((int16_t)HiWord) < 0)
			lDecryptKey = ((LoWord<<16)+HiWord+0xFFFF0000);
		} else {
			lDecryptKey = ((LoWord<<16)+HiWord);
		}

		lBytes[lLoop] = ((lBytes[lLoop]^((HiWord<<16)+LoWord))&0xFF)^cXORKey[lLoop%7];
		++lLoop;
		lBytes[lLoop] = (((lBytes[lLoop])-((HiWord<<16)+LoWord))&0xFF)^cXORKey[lLoop%7];
		++lLoop;

	}

}
