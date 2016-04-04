#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include <openssl/evp.h>
#include <openssl/aes.h>
#include "../library/littleWire.h"
#include "../library/littleWire_util.h"

unsigned char version, myBuffer[4], text[32], rc = 0;
littleWire *littlewire = NULL;

int aes_init(unsigned char *key_data, int key_data_len, unsigned char *salt, EVP_CIPHER_CTX *e_ctx, EVP_CIPHER_CTX *d_ctx)
{
    int i, nrounds = 5;
    unsigned char key[32], iv[32];
    i = EVP_BytesToKey(EVP_aes_256_cbc(), EVP_sha1(), salt, key_data, key_data_len, nrounds, key, iv);
    if (i != 32) return -1;
    EVP_CIPHER_CTX_init(e_ctx);
    EVP_EncryptInit_ex(e_ctx, EVP_aes_256_cbc(), NULL, key, iv);
    EVP_CIPHER_CTX_init(d_ctx);
    EVP_DecryptInit_ex(d_ctx, EVP_aes_256_cbc(), NULL, key, iv);
    return 0;
}

unsigned char *aes_encrypt(EVP_CIPHER_CTX *e, unsigned char *plaintext, int *len)
{
    int c_len = *len + AES_BLOCK_SIZE, f_len = 0;
    unsigned char *ciphertext = malloc(c_len);

    EVP_EncryptInit_ex(e, NULL, NULL, NULL, NULL);

    EVP_EncryptUpdate(e, ciphertext, &c_len, plaintext, *len);

    EVP_EncryptFinal_ex(e, ciphertext+c_len, &f_len);
    *len = c_len + f_len;
    return ciphertext;
}

void i2c_eeprom_write_byte(littleWire *lw, int deviceaddress, unsigned int eeaddress, unsigned char data)
{
	int rdata = data;
	i2c_start(lw, deviceaddress, WRITE);
	myBuffer[0] = (int)(eeaddress >> 8);
	myBuffer[1] = (int)(eeaddress & 0xFF);
	myBuffer[2] = rdata;
	i2c_write(lw, myBuffer, 3, END_WITH_STOP);
}

void i2c_eeprom_write_page(littleWire *lw, int deviceaddress, unsigned int eeaddresspage, unsigned char *data, int length)
{
	i2c_start(lw, deviceaddress, WRITE);
	myBuffer[0] = (int)(eeaddresspage >> 8);
	myBuffer[1] = (int)(eeaddresspage & 0xFF);
	i2c_write(lw, myBuffer, 2, NO_STOP);
	int c;
	for(c=0;c<length;c++)
	{
		myBuffer[0] = data[c];
		if(c!=(length-1))
			i2c_write(lw, myBuffer, 1, NO_STOP);
		else
			i2c_write(lw, myBuffer, 1, END_WITH_STOP);
	}
}

unsigned char i2c_eeprom_read_byte(littleWire *lw, int deviceaddress, unsigned int eeaddress)
{
	unsigned char rdata = 0xFF;
	unsigned char response[1];
	i2c_start(lw, deviceaddress, WRITE);
	myBuffer[0] = (int)(eeaddress >> 8);
	myBuffer[1] = (int)(eeaddress & 0xFF);
	i2c_write(lw, myBuffer, 2, END_WITH_STOP);
	i2c_start(lw, deviceaddress, READ);
	i2c_read(lw, response, 1, END_WITH_STOP);
	rdata = response[1];
	return rdata;
}

void i2c_eeprom_read_buffer(littleWire *lw, int deviceaddress, unsigned int eeaddress, unsigned char *buffer, int length)
{
	unsigned char response[1];
	int i,j = 0;
	for(i=0;i<length;i++)
	{
		i2c_start(lw, deviceaddress, WRITE);
		myBuffer[0] = (int)(eeaddress >> 8);
		myBuffer[1] = (int)(eeaddress & 0xFF);
		i2c_write(lw, myBuffer, 2, END_WITH_STOP);
		i2c_start(lw, deviceaddress, READ);
		i2c_read(lw, response, 1, END_WITH_STOP);
		buffer[j+i] = response[0];
		eeaddress++;
	}
}

int main(int argc, char **argv)
{
   	EVP_CIPHER_CTX en, de;
    unsigned int salt[] = {12345, 54321};
    unsigned char *key_data;
    FILE *fp;
    int key_data_len, i;
    char *input[] = {"Welcome Back Master! Unlocking.",NULL};
    char *plaintext;
    unsigned char *ciphertext;
    int len, olen;

    littlewire = littleWire_connect();
    if(littlewire == NULL)
    {
        printf("> Little Wire could not be found!\n");
        exit(EXIT_FAILURE);
    }

    version = readFirmwareVersion(littlewire);
    printf("> Little Wire firmware version: %d.%d\n",((version & 0xF0)>>4),(version&0x0F));
    if(version==0x10)
    {
        printf("> Requires the new 1.1 version firmware. Please update soon.\n");
        return 0;
    }

    i2c_init(littlewire);
    i2c_updateDelay(littlewire,0);

    if (argc != 2)
    {
        printf("Please enter a 32-byte key string as parameter\n");
        return -1;
    }
    if (strlen(argv[1]) != 32)
    {
        printf("Please enter a 32-byte key string as parameter\n");
        return -1;
    }

    key_data = (unsigned char *)argv[1];
    key_data_len = strlen(argv[1]);

    if (aes_init(key_data, key_data_len, (unsigned char *)&salt, &en, &de))
    {
        printf("Couldn't initialize AES cipher\n");
        return -1;
    }

    olen = len = strlen(input[0])+1;
    ciphertext = aes_encrypt(&en, (unsigned char *)input[0], &len);

    fp = fopen("/etc/MyAuth", "w");
    if (!fp)
    {
        printf("Failed to open MyAuth file. Are you running as root?\n");
        return -1;
    }

    fwrite(ciphertext, 1, 48, fp);
    fclose(fp);

    printf("> MyAuth file has been created successfully\n");

    for (i=0; i<32; i++)
        text[i] = argv[1][i];

    rc = i2c_start(littlewire, 0x50, WRITE);
    
    if(rc == 1)
    	printf("> FOUND device at 0x50\n");
    else
    {
    	printf("> Device not found, please check connection to eeprom or USB Key exist\n> Exitting..\n");
    	exit(-1);
    }
    
    printf("\n> Writing data to EEPROM...\n");
    i2c_eeprom_write_page(littlewire, 0x50, 0, text, sizeof(text));
    printf("\n> Done.\n");
    printf("\n> Now verify data writen to eeprom...\n");
    unsigned char somedata[32];
    i2c_eeprom_read_buffer(littlewire, 0x50, 0, somedata, 32);
    for(i=0;i<32;i++)
    {
    	if(somedata[i] != text[i])
    	{
    		printf("\n> Writing data to EEPROM failed check for bad connections or hardware defect.\n");
    		exit(-1);
    	}
    }
    printf("\n> Data written to EEPROM successfully. Now compile and install pam module.\n");
    
    free(ciphertext);

    EVP_CIPHER_CTX_cleanup(&en);
    EVP_CIPHER_CTX_cleanup(&de);
    return 0;
}

