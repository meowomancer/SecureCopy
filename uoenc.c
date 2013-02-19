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

int main(int argc, char * argv[]){
        const int DEBUG = 0;
	
	int local;
	
	char * file = malloc(128);
	char * destFile = malloc(131);
	char * tag = malloc(4);
	char * dest = malloc(16);
	int totalSent = 0;	
	char * ip;
	char * port;	

	if(argc <= 2){
		printf("\n\nUsage: uoenc <input file> [-d <output IP-addr:port>] [-l] (One argument required)\n");
		return 1;
	}else{
		//Pull input file out of args
		file = argv[1];
		
		//Pull tag
		tag = argv[2];		

		//Set proper mode
		local = (!strcmp(tag, "-d")) ? 0 : 1;
		
		//Get ip and port
		char * combined = argv[3];
		
		ip = strtok(combined, ":");
		port = strtok(NULL, ":");
		
		if(DEBUG){printf("ip: %s port: %d\n", ip, atoi(port));}
		
		//Set new filename if local mode
		if(local){
			strcpy(destFile, file);
			strcat(destFile, ".uo");
		}
	}
	
	//Prompt user for PW
	char password[128];
	printf("Password: ");
	fgets(password, sizeof password, stdin);
	
	//Hash the PW
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
	}else if (DEBUG){
		printf("Password hashed\n");
	}
   
	
	//Create crypto handler
	gcry_cipher_hd_t crypto;
	
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
	char * vector = "pewpewlazors";
	size_t vLength = gcry_cipher_get_algo_blklen(GCRY_CIPHER_AES256);
	cryptoError =
		gcry_cipher_setiv(crypto, vector, vLength);
	
	if(cryptoError){
		printf("%s: %s\n", gcry_strsource(cryptoError), gcry_strerror(cryptoError));
		return 1;
	}else if(DEBUG){
		printf("IV Set.\n");
	}
	
        //Create file handler and file buffer
	FILE * in;
	FILE * out;

	//Open the file
	in = fopen(file, "r");
	if(local){
		if(out = fopen(destFile, "r")){
			printf("File %s already exists. Exiting.\n", destFile);
			return 1;
		}else{
			out = fopen(destFile, "w");
		}
	}
	
	//Error detection
	if (in == NULL ||(out == NULL && local)) {
	    printf ("Error opening ");
	    if(in == NULL){printf("in");}
	    if(out == NULL){printf("out");}
	    printf(" file.\n");
	    return 1;
	}else if(DEBUG){
	    printf("Files opened.\n");
	}
	
	//Print file contents to another file
        int fRead;
	int total = 0;
	char * fileBuffer = malloc(1024);
        
	if(local){
		while(fRead = fread(fileBuffer, 1 , 1024, in)) {
			//Buffer for encrypted data
			size_t outSize = fRead+1024;
			char * enOutBuffer = malloc(fRead+1024);
					
			//Encrypt the data
			cryptoError = gcry_cipher_encrypt(
			    crypto,	 	//gcry_cipher_hd_t h
			    enOutBuffer,		//unsigned char *out
			    outSize,		//size_t outsize
			    fileBuffer,		//const unsigned char *in
			    1024);		//size_t inlen
			
			if(cryptoError){
			    printf("%s: %s\n", gcry_strsource(cryptoError), gcry_strerror(cryptoError));
			    return 1;
			}else{
				fwrite(enOutBuffer, fRead+16, 1, out);
				printf("Read %d bytes of data. Writing %i bytes of Data.\n",fRead,fRead+16);
			}
			
			free(enOutBuffer);
		}
	}else{
		if(DEBUG){printf("Configuring networking.\n");}
	
		//Set incoming buffer & size
		char netInBuffer[1041];
		int netInLength;
		if(DEBUG){printf("Buffer created.\n");}
	
		//Create socket
		int netSocket;			
		if(DEBUG){printf("Socket created.\n");}
		
		//Create socket struct
		struct sockaddr_in server;
		if(DEBUG){printf("Structs created.\n");}
	
		//Bind
		netSocket = socket(AF_INET, SOCK_STREAM, 0);
		if(DEBUG){printf("Socket created.\n");}
		
		//Set interface
		server.sin_family = AF_INET;
		if(DEBUG){printf("Interface chosen.\n");}
		
		//Set server's IP
		server.sin_addr.s_addr = inet_addr(ip);
		if(DEBUG){printf("IP Set.\n");}
	
		//Set destination port
		server.sin_port = htons(atoi(port));
		if(DEBUG){printf("Port set.\n");}
		
		//Connect to socket
		if(connect(netSocket, (struct sockaddr *)&server, sizeof(struct sockaddr)) == -1){
			printf("ERROR");
			return 1;
		}
		if(DEBUG){printf("Bound to socket.\n");}
		
		//Recieve data & add null terminator
		netInLength = recv(netSocket, netInBuffer, 1040, 0);			
		if(DEBUG){printf("Data recieved.\n");}
		netInBuffer[netInLength] = '\0';
		
		if(!strcmp(netInBuffer, "ACK")){
			if(DEBUG){printf("ACK Recieved\n");}
			char ack[] = "ACK";
			send(netSocket, file, strlen(file), 0);
			if(DEBUG){printf("ACK Returned\n");}
		}
		
		//Recieve data
		netInLength = recv(netSocket, netInBuffer, 1040, 0);
		netInBuffer[netInLength] = '\0';
		
		if(!strcmp(netInBuffer, "PWD")){
			while(fRead = fread(fileBuffer, 1 , 1024, in)) {
				if(fRead == 0){printf("CRASHING\n");}
				//Buffer for encrypted data
				size_t outSize = fRead+1024;
				char * enOutBuffer = malloc(fRead+1024);
			
				if(DEBUG){printf("PWD ACK Recieved. Encrypting\n");}
			
				//Encrypt the data
				cryptoError = gcry_cipher_encrypt(
				    crypto,	 	//gcry_cipher_hd_t h
				    enOutBuffer,		//unsigned char *out
				    outSize,		//size_t outsize
				    fileBuffer,		//const unsigned char *in
				    1024);		//size_t inlen
				
				if(cryptoError){
				    printf("%s: %s\n", gcry_strsource(cryptoError), gcry_strerror(cryptoError));
				    return 1;
				}else{
					send(netSocket, enOutBuffer, fRead+16, 0);
					printf("Read %d bytes of data. Transmitting %i bytes of Data.\n",fRead,fRead+16);
					totalSent += fRead+16;
				}
				
				//free(enOutBuffer);
			}
			printf("Successfully transfered %d bytes.\n", totalSent);
			
			//Tell server the transfer is done
			char don[] = "DON";
			send(netSocket, don, strlen(don), 0);
			
			if(DEBUG){printf("Sent DC packet");}
		}
		close(netSocket);
	}
	
	//Close the file
	fclose(in);
	if(local){fclose(out);}

	//Close the crypto handler
	gcry_cipher_close(crypto);

	//Free memory
	free(fileBuffer);
	
	//Take me out later	
	return 0;
}