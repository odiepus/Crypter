// Main.cpp
//
#include <windows.h>
#include <stdio.h>
#include <stdlib.h>
#include <io.h>
#include <fcntl.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <iostream>

using namespace std;

//#define TEST_CODE

// Global Variables
unsigned char gkey[65537];
unsigned char *gptrKey = gkey;			// used for inline assembly routines, need to access this way for Visual Studio
char gPassword[256] = "password";
unsigned char gPasswordHash[32];
unsigned char *gptrPasswordHash = gPasswordHash;	// used for inline assembly routines, need to access this way for Visual Studio

FILE *gfptrIn = NULL;
FILE *gfptrOut = NULL;
FILE *gfptrKey = NULL;
char gInFileName[256];
char gOutFileName[256];
char gKeyFileName[256];
int gOp = 0;			// 1 = encrypt, 2 = decrypt
int gNumRounds = 1;


// Prototypes
int sha256(char *fileName, char *dataBuffer, DWORD dataLength, unsigned char sha256sum[32]);

// assembly language to count the number of ASCII letters in a data array
//	numC = number of capital letters
//	numL = number of lowercase letters
//	numO = number of characters that are not a letter
void exCountLetters(char *data, int dataLength, int *numC, int *numL, int *numO)
{
	__asm {
		cld;					// 
		push esi;				// 
		push ecx;				// 
		push ebx;
		mov esi, data;			// 
		mov ecx, dataLength;	// 

	LOOP_X1:
		lodsb;					// 
		mov bl, al				// 
			push eax;				// 
		call isLetter;			// function returns a 1 in al if the character passed in is a letter, otherwise al = 0
		add esp, 4				// 
			test al, al;				// 
		je lbl_OTHER;			// 

		mov al, bl				// 
			and al, 0x20;			// already know it's a letter, if al == 0, then CAP
		je lbl_CAP;

		mov	ebx, numL;			// 
		add[ebx], 1;			// 
		jmp lbl_NEXT;			// 

	lbl_CAP:
		mov ebx, numC;			// 
		add[ebx], 1;			// 
		jmp lbl_NEXT;			// 

	lbl_OTHER:
		mov ebx, numO			// 
			add[ebx], 1				// 
			lbl_NEXT :
			dec ecx;				// 
		jne LOOP_X1;			// 

		pop ebx;				// 
		pop ecx;				// 
		pop esi;				// 
		jmp EXIT_C_EXAMPLE;		// let C handle whatever it did upon entering this function

	isLetter:
		push ebp;				// 
		mov ebp, esp;			// 
		mov al, [ebp + 8];			// 
		cmp al, 0x40;			// 
		ja lbl_CHK_ZU;			// check Uppercase 'Z'

	lbl_RET_FALSE:
		xor eax, eax;			// 
	lbl_RET:
		mov esp, ebp;			// 
		pop ebp;				// 
		ret;					// 

	lbl_RET_TRUE:
		mov eax, 1;				// 
		jmp lbl_RET;			// 

	lbl_CHK_ZU:
		cmp al, 0x5B;			// 
		jb lbl_RET_TRUE;		// 

		cmp al, 0x61;			// 
		jb lbl_RET_FALSE;		// check lowercase 'z'

		cmp al, 0x7A;			// 
		jbe lbl_RET_TRUE;		// 
		jmp lbl_RET_FALSE;		// 

	} // end assembly block

EXIT_C_EXAMPLE:					// 
	return;
} // exCountLetters

  //////////////////////////////////////////////////////////////////////////////////////////////////
  // code to encrypt the data as specified by the project assignment
void encryptData(char *data, int lengths)
{
	// you can not declare any local variables in C, set up the stack frame and 
	// assign them in assembly
	//gnumrounds = global = 4 byte size = eax,ebx,ecx,edx 16bit size
	//

	__asm {

		// you will need to reference these global variables
		// gptrPasswordHash, gptrKey

		/*
		mov esi,gptrKey;
		mov al,[esi+2];		// access 3rd byte in keyfile
		mov edi,data
		mov [edi],al
		*/

		// simple example that replaces first byte of data with third byte in teh key filewhich is 0x7A == 'z'
		push eax
		push ebx
		push ecx
		push edx
		push esi
		push edi

		xor eax, eax
		mov[esp - 4], eax //initiate round counter to 0



		ROUNDS :
		mov eax, [esp - 4]				//if rounder counter < number of rounds continue loop, else we are done and jump to finish
			cmp eax, gNumRounds
			jge FINISH

			mov ecx, gptrPasswordHash		//get the start of the password hash to setup the indexes and hops

			mov ebx, [esp - 4]				//get the round counter and multiply by 4 to calculate the index
			shl ebx, 2
			add ecx, ebx

			mov bx, [ecx]					//store first 2 bytes (index1) the if statement in the for loop says it could be
			movzx edx, bx					//65536 so we use a full 4 bytes instead of 2 to store these values
			mov[esp - 8], edx				//likewise with the hopcount 
			add ecx, 2						//incremenet by two to get the next 2 bytes to get the hopcount
			mov bx, [ecx]
			movzx edx, bx
			cmp edx, 0
			jnz HOP1
			mov edx, 65536



			HOP1:
		mov[esp - 0Ch], edx

			add ecx, 2						//follow the same logic incrementing by two each time to get index2 and hop2
											//if the hopcount is 0 we set it to 65536 as per specification
			mov bx, [ecx]
			movzx edx, bx
			mov[esp - 10h], edx
			add ecx, 2
			mov bx, [ecx]
			movzx edx, bx

			cmp edx, 0
			jnz HOP2
			mov edx, 65536



			HOP2:
		mov[esp - 14h], edx

			add eax, 1
			mov[esp - 4], eax                 //add 1 to the count here and jump to the encryption section

			mov ecx, 0
			mov esi, gptrKey
			mov edi, data      //set pointers to look at the data to be encrypted



			CRYPTION :

		cmp ecx, lengths
			jge ROUNDS

			mov al, [edi + ecx]
			mov ebx, [esp - 8]
			mov ah, [esi + ebx]
			xor al, ah

			add ebx, [esp - 0Ch]

			cmp ebx, 65537
			jl INDEX1_FINISH
			sub ebx, 65537



			INDEX1_FINISH:

		mov[esp - 8], ebx

			// rotate 1 bit to the right
			ror al, 1

			// swap nibbles
			ror al, 4
			
			

			// ror al, 5 will take care of both of these, use for optimization		

			// reverse bit order, crude, needs optimization
			xor ebx, ebx
			push ecx
			push edx
			xor ecx, ecx
			xor edx, edx
			mov ch, 1
			mov cl, 1


			REVERSING:
				add ch, bl
				mov ah, al
				and ah, ch
				xor ebx, ebx
				shrd ebx, ah, 7
			
				add dh, bl
				xor bl, bl
				add cl, 2
				mov bl, ch
				cmp cl, 17
			jne REVERSING

			
			

			/*mov ah, al
			and ah, 00000001b
			shl ah, 7
			add bl, ah

			mov ah, al
			and ah, 00000010b
			shl ah, 5
			add bl, ah

			mov ah, al
			and ah, 00000100b
			shl ah, 3
			add bl, ah

			mov ah, al
			and ah, 00001000b
			shl ah, 1
			add bl, ah

			mov ah, al
			and ah, 00010000b
			shr ah, 1
			add bl, ah

			mov ah, al
			and ah, 00100000b
			shr ah, 3
			add bl, ah

			mov ah, al
			and ah, 01000000b
			shr ah, 5
			add bl, ah

			mov ah, al
			and ah, 10000000b
			shr ah, 7
			add bl, ah

			mov al, bl*/


			// swaps half nibbles
			mov ah, al
			shl al, 2
			and al, 11001100b
			shr ah, 2
			and ah, 00110011b
			add al, ah

			// rotate 1 bit to the left
			rol al, 1


			mov ebx, [esp - 10h]
			mov ah, [esi + ebx]
			xor al, ah

			add ebx, [esp - 14h]

			cmp ebx, 65537
			jl INDEX2_FINISH
			sub ebx, 65537



			INDEX2_FINISH:

		mov[esp - 10h], ebx
			mov[edi + ecx], al
			add ecx, 1
			jmp CRYPTION



			FINISH :

		pop edi
			pop esi
			pop edx
			pop ecx
			pop ebx
			pop eax


	}

EXIT_C_ENCRYPT_DATA:
	return;
} // encryptData

  // code to read the file to encrypt
int encryptFile(FILE *fptrIn, FILE *fptrOut)
{
	char *buffer;
	unsigned int filesize;

	filesize = _filelength(_fileno(fptrIn));	// Linux???
	if (filesize > 0x1000000)					// 16 MB, file too large
	{
		fprintf(stderr, "Error - Input file too large.\n\n");
		return -1;
	}

	// use the password hash to encrypt
	buffer = (char *)malloc(filesize);
	if (buffer == NULL)
	{
		fprintf(stderr, "Error - Could not allocate %d bytes of memory on the heap.\n\n", filesize);
		return -1;
	}

	fread(buffer, 1, filesize, fptrIn);	// read entire file
	encryptData(buffer, filesize);
	fwrite(buffer, 1, filesize, fptrOut);
	free(buffer);

	return 0;
} // encryptFile

  //////////////////////////////////////////////////////////////////////////////////////////////////
  // code to decrypt the data as specified by the project assignment
void decryptData(char *data, int lengths)
{
	// you can not declare any local variables in C, set up the stack frame and 
	// assign them in assembly

	__asm {

		// you will need to reference these global variables
		// gptrPasswordHash, gptrKey

		push eax
		push ebx
		push ecx
		push edx
		push esi
		push edi

		xor eax, eax
		mov[esp - 4], eax //initiate round counter to 0



		DROUNDS :

		mov eax, [esp - 4]				//if rounder counter < number of rounds continue loop, else we are done and jump to finish
			cmp eax, gNumRounds
			jge DFINISH

			mov ecx, gptrPasswordHash		//get the start of the password hash to setup the indexes and hops

			mov ebx, [esp - 4]				//get the round counter and multiply by 4 to calculate the index
			shl ebx, 2
			add ecx, ebx

			mov bx, [ecx]					//store first 2 bytes (index1) the if statement in the for loop says it could be
			movzx edx, bx					//65536 so we use a full 4 bytes instead of 2 to store these values
			mov[esp - 8], edx				//likewise with the hopcount 
			add ecx, 2						//incremenet by two to get the next 2 bytes to get the hopcount
			mov bx, [ecx]
			movzx edx, bx
			cmp edx, 0
			jnz DHOP1
			mov edx, 65536



			DHOP1:

		mov[esp - 0Ch], edx

			add ecx, 2						//follow the same logic incrementing by two each time to get index2 and hop2
											//if the hopcount is 0 we set it to 65536 as per specification
			mov bx, [ecx]
			movzx edx, bx
			mov[esp - 10h], edx
			add ecx, 2
			mov bx, [ecx]
			movzx edx, bx

			cmp edx, 0
			jnz DHOP2
			mov edx, 65536



			DHOP2:
		mov[esp - 14h], edx

			add eax, 1
			mov[esp - 4], eax                 //add 1 to the count here and jump to the encryption section

			mov ecx, 0
			mov esi, gptrKey
			mov edi, data      //set pointers to look at the data to be encrypted



			DCRYPTION :

		cmp ecx, lengths
			jge DROUNDS

			mov al, [edi + ecx]

			mov ebx, [esp - 10h]
			mov ah, [esi + ebx]
			xor al, ah

			add ebx, [esp - 14h]

			cmp ebx, 65537
			jl DINDEX2_FINISH
			sub ebx, 65537



			DINDEX2_FINISH:

		mov[esp - 10h], ebx

			// undoing rotate 1 bit to the left
			ror al, 1

			// swaps half nibbles
			mov ah, al
			shl al, 2
			and al, 11001100b
			shr ah, 2
			and ah, 00110011b
			add al, ah

			// ror al, 5 will take care of both of these, use for optimization		

			// reverse bit order, crude, needs optimization
			xor bl, bl

			mov ah, al
			and ah, 00000001b
			shl ah, 7
			add bl, ah

			mov ah, al
			and ah, 00000010b
			shl ah, 5
			add bl, ah

			mov ah, al
			and ah, 00000100b
			shl ah, 3
			add bl, ah

			mov ah, al
			and ah, 00001000b
			shl ah, 1
			add bl, ah

			mov ah, al
			and ah, 00010000b
			shr ah, 1
			add bl, ah

			mov ah, al
			and ah, 00100000b
			shr ah, 3
			add bl, ah

			mov ah, al
			and ah, 01000000b
			shr ah, 5
			add bl, ah

			mov ah, al
			and ah, 10000000b
			shr ah, 7
			add bl, ah

			mov al, bl

			// swap nibbles
			ror al, 4

			// rotate 1 bit to the left
			rol al, 1

			mov ebx, [esp - 8]
			mov ah, [esi + ebx]
			xor al, ah

			add ebx, [esp - 0Ch]

			cmp ebx, 65537
			jl DINDEX1_FINISH
			sub ebx, 65537



			DINDEX1_FINISH:

		mov[esp - 8], ebx

			mov[edi + ecx], al
			add ecx, 1
			jmp DCRYPTION



			DFINISH :

		pop edi
			pop esi
			pop edx
			pop ecx
			pop ebx
			pop eax

	}

EXIT_C_DECRYPT_DATA:
	return;
} // decryptData

  // code to read in file and prepare for decryption
int decryptFile(FILE *fptrIn, FILE *fptrOut)
{
	char *buffer;
	unsigned int filesize;

	filesize = _filelength(_fileno(fptrIn));	// Linux???
	if (filesize > 0x1000000)					// 16 MB, file too large
	{
		fprintf(stderr, "Error - Input file too large.\n\n");
		return -1;
	}

	// use the password hash to encrypt
	buffer = (char *)malloc(filesize);
	if (buffer == NULL)
	{
		fprintf(stderr, "Error - Could not allocate %d bytes of memory on the heap.\n\n", filesize);
		return -1;
	}

	fread(buffer, 1, filesize, fptrIn);	// read entire file
	decryptData(buffer, filesize);
	fwrite(buffer, 1, filesize, fptrOut);
	free(buffer);

	return 0;
} // decryptFile

  //////////////////////////////////////////////////////////////////////////////////////////////////
FILE *openInputFile(char *filename)
{
	FILE *fptr;

	fptr = fopen(filename, "rb");
	if (fptr == NULL)
	{
		fprintf(stderr, "\n\nError - Could not open input file %s!\n\n", filename);
		exit(-1);
	}
	return fptr;
} // openInputFile

FILE *openOutputFile(char *filename)
{
	FILE *fptr;

	fptr = fopen(filename, "wb+");
	if (fptr == NULL)
	{
		fprintf(stderr, "\n\nError - Could not open output file %s!\n\n", filename);
		exit(-1);
	}
	return fptr;
} // openOutputFile


void usage(char *argv[])	//   cryptor.exe -e -i <input file> –k <keyfile> -p <password> [–r <#rounds>]
{
	printf("\n\nUsage:\n\n");
	printf("%s -<e=encrypt or d=decrypt> -i <message_filename> -k <keyfile> -p <password> [-r <#rounds>]\n\n", argv[0]);
	printf("-e				:encrypt the specified file\n");
	printf("-d				:decrypt the specified file\n");
	printf("-i filename		:the name of the file to encrypt or decrypt\n");
	printf("-p password		:the password to be used for encryption [default='password']\n");
	printf("-r <#rounds>	:number of encryption rounds (1 - 3)  [default = 1]\n");
	printf("-o filename		:name of the output file [default='encrypted.txt' or 'decrypted.txt'\n\n");
	exit(0);
} // usage

void parseCommandLine(int argc, char *argv[])
{
	int cnt;
	char ch;
	bool i_flag, o_flag, k_flag, p_flag, err_flag;

	i_flag = k_flag = false;				// these must be true in order to exit this function
	err_flag = p_flag = o_flag = false;		// these will generate different actions

	cnt = 1;	// skip program name
	while (cnt < argc)
	{
		ch = *argv[cnt];
		if (ch != '-')
		{
			fprintf(stderr, "All options must be preceeded by a dash '-'\n\n");
			usage(argv);
		}

		ch = *(argv[cnt] + 1);
		if (0)
		{
		}

		else if (ch == 'e' || ch == 'E')
		{
			if (gOp != 0)
			{
				fprintf(stderr, "Error! Already specified encrypt or decrypt.\n\n");
				usage(argv);
			}
			gOp = 1;	// encrypt
		}

		else if (ch == 'd' || ch == 'D')
		{
			if (gOp != 0)
			{
				fprintf(stderr, "Error! Already specified encrypt or decrypt.\n\n");
				usage(argv);
			}
			gOp = 2;	// decrypt
		}

		else if (ch == 'i' || ch == 'I')
		{
			if (i_flag == true)
			{
				fprintf(stderr, "Error! Already specifed an input file.\n\n");
				usage(argv);
			}
			i_flag = true;
			cnt++;
			if (cnt >= argc)
			{
				fprintf(stderr, "Error! Must specify a filename after '-i'\n\n");
				usage(argv);
			}
			strncpy(gInFileName, argv[cnt], 256);
		}

		else if (ch == 'o' || ch == 'O')
		{
			if (o_flag == true)
			{
				fprintf(stderr, "Error! Already specifed an output file.\n\n");
				usage(argv);
			}
			o_flag = true;
			cnt++;
			if (cnt >= argc)
			{
				fprintf(stderr, "Error! Must specify a filename after '-o'\n\n");
				usage(argv);
			}
			strncpy(gOutFileName, argv[cnt], 256);
		}

		else if (ch == 'k' || ch == 'K')
		{
			if (k_flag == true)
			{
				fprintf(stderr, "Error! Already specifed a key file.\n\n");
				usage(argv);
			}
			k_flag = true;
			cnt++;
			if (cnt >= argc)
			{
				fprintf(stderr, "Error! Must specify a filename after '-k'\n\n");
				usage(argv);
			}
			strncpy(gKeyFileName, argv[cnt], 256);
		}

		else if (ch == 'p' || ch == 'P')
		{
			if (p_flag == true)
			{
				fprintf(stderr, "Error! Already specifed a password.\n\n");
				usage(argv);
			}
			p_flag = true;
			cnt++;
			if (cnt >= argc)
			{
				fprintf(stderr, "Error! Must enter a password after '-p'\n\n");
				usage(argv);
			}
			strncpy(gPassword, argv[cnt], 256);
		}

		else if (ch == 'r' || ch == 'R')
		{
			int x;

			cnt++;
			if (cnt >= argc)
			{
				fprintf(stderr, "Error! Must enter number between 1 and 3 after '-r'\n\n");
				usage(argv);
			}
			x = atoi(argv[cnt]);
			if (x < 1 || x > 3)
			{
				fprintf(stderr, "Warning! Entered bad value for number of rounds. Setting it to one.\n\n");
				x = 1;
			}
			gNumRounds = x;
		}

		else
		{
			fprintf(stderr, "Error! Illegal option in argument. %s\n\n", argv[cnt]);
			usage(argv);
		}

		cnt++;
	} // end while

	if (gOp == 0)
	{
		fprintf(stderr, "Error! Encrypt or Decrypt must be specified.\n\n)");
		err_flag = true;
	}

	if (i_flag == false)
	{
		fprintf(stderr, "Error! No input file specified.\n\n");
		err_flag = true;
	}

	if (k_flag == false)
	{
		fprintf(stderr, "Error! No key file specified.\n\n");
		err_flag = true;
	}

	if (p_flag == false)
	{
		fprintf(stderr, "Warning! Using default 'password'.\n\n");
	}

	if (o_flag == false && err_flag == false)	// no need to do this if we have errors
	{
		strcpy(gOutFileName, gInFileName);
		if (gOp == 1)	// encrypt
		{
			strcat(gOutFileName, ".enc");
		}
		if (gOp == 2)	// decrypt
		{
			strcat(gOutFileName, ".dec");
		}
	}

	if (err_flag)
	{
		usage(argv);
	}
	return;
} // parseCommandLine


void main(int argc, char *argv[])
{
#ifdef TEST_CODE
	char testData[] = "The big lazy brown FOX jumped 123 the 987 dog. Then he 8 a CHICKEN.";
	int numCAPS, numLow, numNonLetters;
	numCAPS = numLow = numNonLetters = 0;
	exCountLetters(testData, strlen(testData), &numCAPS, &numLow, &numNonLetters);
	printf("numCAPS=%d, numLow=%d, numNonLetters=%d\n", numCAPS, numLow, numNonLetters);
	exit(0);
#endif

	int length, resulti;

	// parse command line parameters
	//parseCommandLine(argc, argv);		// sets global variables, checks input options for errors

	string f1 = "C:\\Users\\odiep\\Documents\\Visual Studio 2015\\Projects\\Crypter\\Debug\\testin.txt";
	string f2 = "C:\\Users\\odiep\\Documents\\Visual Studio 2015\\Projects\\Crypter\\Debug\\Key.dat";
	string f3 = "C:\\Users\\odiep\\Documents\\Visual Studio 2015\\Projects\\Crypter\\Debug\\outPut.txt";

	strcpy(gInFileName, f1.c_str());
	strcpy(gKeyFileName, f2.c_str());
	strcpy(gOutFileName, f3.c_str());



										// open the input and output files
	gfptrIn = openInputFile(gInFileName);
	gfptrKey = openInputFile(gKeyFileName);
	gfptrOut = openOutputFile(gOutFileName);

	/*gfptrKey = fopen("C:\\Users\\odiep\\Documents\\Visual Studio 2015\\Projects\\Crypter\\Debug\\Key.dat", "r");
	gfptrIn = fopen("C:\\Users\\odiep\\Documents\\Visual Studio 2015\\Projects\\Crypter\\Debug\\testin.txt", "r");
	gfptrOut = fopen("C:\\Users\\odiep\\Documents\\Visual Studio 2015\\Projects\\Crypter\\Debug\\outPut.txt", "w");
*/
	length = (size_t)strlen(gPassword);

	resulti = sha256(NULL, gPassword, length, gPasswordHash);		// get sha-256 hash of password
	if (resulti != 0)
	{
		fprintf(stderr, "Error! Password not hashed correctly.\n\n");
		exit(-1);
	}

	cout << sizeof(gfptrKey) << endl;
	
	length = fread(gkey, 1, 65537, gfptrKey);
	if (length != 65537)
	{
		fprintf(stderr, "Error! Length of key file is not at least 65537.\n\n");
		exit(-1);
	}
	fclose(gfptrKey);
	gfptrKey = NULL;

	gOp = 1;

	if (gOp == 1)	// encrypt
	{
		encryptFile(gfptrIn, gfptrOut);
	}
	else
	{
		decryptFile(gfptrIn, gfptrOut);
	}

	fclose(gfptrIn);
	fclose(gfptrOut);
	return;
} // main