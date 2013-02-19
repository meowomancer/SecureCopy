#include<stdio.h>
#include<errno.h>
#include<gcrypt.h>
#include<gcrypt-module.h>

#include<stdlib.h>
#include<unistd.h>
#include<arpa/inet.h>
#include<sys/types.h>
#include<netinet/in.h>
#include<sys/socket.h>

#define DEBUG 0
#define PORT 11169

//Create crypto handler at global scope
gcry_cipher_hd_t crypto;

int main(int argc, char * argv[]){

	char * file = malloc(128);
	char * destFile = malloc(131);
	char password[128];	//Need in high scope
	FILE * out;	//Always be used
	int local;	//Mode designator
	
	if(argc >3){
		printf("\n\nUsage: uodec [-n] [-1 <input file>]\n");
		return 1;
	}else{	
		//Set proper mode
		if(!strcmp(argv[1], "-l")){
			local = 1;
		}else if(!strcmp(argv[1], "-n")){
			local = 0;
		}else{
			local = -1;
		}
		
		//Exit if tag != -l or -n
		if(local == -1){
			printf("\n\nUsage: uodec [-n] [-1 <input file>]*\n");
			return 1;
		}
		
		if(local){
			//Get in file name from args
			file = argv[2];
			
			//Make sure the file is in the right .uo format
			if(file[strlen(file)-1] == 'o' && file[strlen(file)-2] == 'u' && file[strlen(file)-3] == '.'){
				strcpy(destFile, file);
				destFile[strlen(file)-1] = 0;
				destFile[strlen(file)-2] = 0;
				destFile[strlen(file)-3] = 0;
			}else{
				printf("\n\nIncorrect file format/extension.\n");
			}
		}
	}
	
	if(local){
		//Prompt user for PW
		printf("Password: ");
		fgets(password, sizeof password, stdin);
		
		if(crypt_init(password)){printf("Error configuring libgcrypt.\n");return 1;}
		
		//Create file handler and file buffer
		FILE * in;
		
		//Open the file
		in = fopen(file, "r");
		out = fopen(destFile, "w");
		
		//File opening error detection
		if (in == NULL || out == NULL) {
		    printf ("Error opening ");
		    if(in == NULL){printf("in");}
		    if(out == NULL){printf("out");}
		    printf(" file.\n");
		}else if(DEBUG){
		    printf("Files opened.\n");
		}
		
		//Unencrypt the data from file
		char * fileBuffer = malloc(2048);
		int fRead;
		
		while(fRead = fread(fileBuffer, 1 , 1040, in)) {
			//Buffer for unencrypted data
			size_t unOutSize = 2048;
			char * unOutBuffer = malloc(2048);
			
			if(!decrypt(crypto, unOutBuffer, unOutSize, fileBuffer, 2048)){
			    printf("Read %d bytes of data. Writing %i bytes of Data.\n",fRead,fRead-16);	
			    fwrite(unOutBuffer, fRead-16, 1, out);
			}
			
			free(unOutBuffer);
		}
		
		//Close the file
		fclose(in);
		fclose(out);
		
		//Free memory
		free(fileBuffer);
	}else{
		if(DEBUG){printf("Configuring networking.\n");}
		
		//Create sockets structs
		struct sockaddr_in client;
		struct sockaddr_in server;
		if(DEBUG){printf("Sockets structs created.\n");}
		
		//Create socket aand listener
		int netSocket;		
		int listener;
		if(DEBUG){printf("netSocket and listener created.\n");}
		
		//Set socketsize to struct size
		socklen_t socketsize = sizeof(struct sockaddr_in);
		if(DEBUG){printf("Sockets size set.\n");}
		
		//Set connection type
		server.sin_family = AF_INET;
		if(DEBUG){printf("Connection type set.\n");}
		
		//Bind to an interface
		server.sin_addr.s_addr = INADDR_ANY;		
		if(DEBUG){printf("Bound to interface.\n");}
		
		//Set portnumber
		server.sin_port = htons(PORT);
		if(DEBUG){printf("Port number set.\n");}
		
		//Bind to socket
		netSocket = socket(AF_INET, SOCK_STREAM, 0);
		bind(netSocket, (struct sockaddr *)&server, sizeof(struct sockaddr));
		if(DEBUG){printf("Bound to socket.\n");}
		
		//Start listening
		listen(netSocket, 1);
		printf("Waiting for connection.\n");
		listener = accept(netSocket, (struct sockaddr *)&client, &socketsize);
		
		if(listener == -1){printf("Error accepting connection");}
		
		if(DEBUG){printf("Connection made.");}
		
		//Create incoming buffer and file handler
		unsigned char * netInBuffer = malloc(1041);
		int netInLength;		
		int mode = 0;
		int netOut;
		int total = 0;
		
		while(listener){
			if(mode == 0){
				//Handshake on connection, just to be safe
				if(DEBUG){printf("Incoming connection establed\n");};
				char ack[] = "ACK";
				send(listener, ack, strlen(ack), 0);				
				if(DEBUG){printf("ACK Sent\n");}
				mode = 1;
			}
			
			if(mode == 1){
				//Recieve data & add terminator
				netInLength = recv(listener, destFile, 127, 0);
				destFile[netInLength] = '\0';
				
				//More handshaking
				if(DEBUG){printf("Filename recieved: %s\n", destFile);}
				
				printf("Inbound file. Password: ");
				fgets(password, sizeof password, stdin);
				if(DEBUG){printf("Password is: %s\n", password);}
				
				//Configure glib and file handler
				crypt_init(password);
				if(out = fopen(destFile, "r")){
					printf("File %s already exists. Exiting.\n", destFile);
					return 1;
				}else{
					out = fopen(destFile, "w");
				}
				
				//Send password ack
				char pwd[] = "PWD";
				send(listener, pwd, strlen(pwd), 0);
				if(DEBUG){printf("PWD ACK Sent. Waiting for data\n");}
				mode = 2;

			}
			
			if(mode == 2){				
				//Recieve data & add terminator
				netInLength = recv(listener, netInBuffer, 1040, 0);
				netInBuffer[netInLength+1] = '\0';
				if(DEBUG){printf("-->Recieved %d bytes of Data\n", netInLength);}
				if(DEBUG){printf("%s (%d bytes)\n", netInBuffer, netInLength);}
				
				//Unencrypt the data
				size_t unOutSize = 2048;
				unsigned char * unOutBuffer = malloc(2048);


				if(netInLength > 0 && !decrypt(crypto, unOutBuffer, unOutSize, netInBuffer, 2048)){
					if(DEBUG){printf("Decrypted.\n");}
					if(netInLength < 1024){
						unOutBuffer[netInLength-19] = '\0';
						fwrite(unOutBuffer, netInLength-19, 1, out);
						netOut = netInLength - 19;
					}else{
						unOutBuffer[netInLength-16] = '\0';
						fwrite(unOutBuffer, netInLength-16, 1, out);
						netOut = netInLength - 16;
					}
					fflush(out);
					printf("Recieved %d bytes of data. Writing %i bytes of Data.\n",netInLength,netOut);	
					total += netOut;
				}
				
				free(unOutBuffer);
				
				if(netInLength < 1024){
					printf("Transfer successful. %d bytes written.\n", total);
					break;
				}
			}
		}
	}

	//Close the crypto handler
	gcry_cipher_close(crypto);
	
	return 0;
}

int decrypt(gcry_cipher_hd_t h, unsigned char *out, size_t outsize, unsigned char *in, size_t inlen){
	if(DEBUG){printf("Method called successfully\n");}
	
	gcry_error_t cryptoError = gcry_cipher_decrypt(
		h,	 	//gcry_cipher_hd_t h
		out,	//unsigned char *out
		outsize,	        //size_t outsize
		in,	        //const unsigned char *in
		inlen);	        //size_t inlen	
	
	if(cryptoError){
		printf("%s: %s\n", gcry_strsource(cryptoError), gcry_strerror(cryptoError));
		return 1;
	}else{
		return 0;
	}
}

int crypt_init(char * password){
	char * key[32];
	unsigned int keyLength = 32;
	
	//Hash the Password
	gcry_error_t cryptoError =
        gcry_kdf_derive(
            password,
            strlen(password),
            GCRY_KDF_PBKDF2,
            GCRY_MD_SHA256,
            password,
            strlen(password),
            1024,
            keyLength,
            key
	);
	
	if(cryptoError){
		printf("Error.\n");
	}else if(DEBUG){
		printf("Password hashed\n");
	}
	
	cryptoError =
	gcry_cipher_open(
	    &crypto,
	    GCRY_CIPHER_AES256,
	    GCRY_CIPHER_MODE_ECB,
	    0);
	
	if(cryptoError){
		printf("%s: %s\n", gcry_strsource(cryptoError), gcry_strerror(cryptoError));
		return 1;
	}else if(DEBUG){
		printf("Handler created.\n");	
	}

	/*
	 *set cipher key
	 */
	cryptoError = gcry_cipher_setkey(crypto, key, keyLength);
	if(cryptoError){
		printf("%s: %s\n", gcry_strsource(cryptoError), gcry_strerror(cryptoError));
		return 1;
	}else if(DEBUG){
		printf("Key set.\n");
	}
	
	/*
	 * Initialize the vector(???)
	 */
	char * vector = "athenstiromni"; //TODO: Random init vector;
	size_t vLength = gcry_cipher_get_algo_blklen(GCRY_CIPHER_AES256);
	cryptoError =
		gcry_cipher_setiv(crypto, vector, vLength);
	
	if(cryptoError){
		printf("%s: %s\n", gcry_strsource(cryptoError), gcry_strerror(cryptoError));
		return 1;
	}else if(DEBUG){
		printf("IV Set.\n");
	}
	
	return 0;
}