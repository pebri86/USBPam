#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include <openssl/evp.h>
#include <openssl/aes.h>
#include <security/pam_appl.h>
#include <security/pam_modules.h>
#include "../library/littleWire.h"
#include "../library/littleWire_util.h"

unsigned char version, myBuffer[4], text[32], rc = 0;
littleWire *littlewire = NULL;

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

unsigned char *aes_decrypt(EVP_CIPHER_CTX *e, unsigned char *ciphertext, int *len)
{
    int p_len = *len, f_len = 0;
    unsigned char *plaintext = malloc(p_len + AES_BLOCK_SIZE);

    EVP_DecryptInit_ex(e, NULL, NULL, NULL, NULL);
    EVP_DecryptUpdate(e, plaintext, &p_len, ciphertext, *len);
    EVP_DecryptFinal_ex(e, plaintext+p_len, &f_len);

    *len = p_len + f_len;
    return plaintext;
}


int CheckUSBkey()
{
    EVP_CIPHER_CTX en, de;
    unsigned int salt[] = {12345, 54321};
    unsigned char *key_data;
    FILE *fp;
    int key_data_len;
    char secrettext[] = "Welcome Back Master! Unlocking.";
    char *plaintext;
    long i;
    uint8_t DataBufH[16], DataBufL[16];
    char printable[32];
    unsigned char ciphertext[48];
    int len;

    littlewire = littleWire_connect();
    if(littlewire == NULL)
    {
        //printf("> Little Wire could not be found!\n");
        //exit(EXIT_FAILURE);
        return 1;
    }

    version = readFirmwareVersion(littlewire);
    if(version==0x10)
    {
        printf("> Requires the new 1.1 version firmware. Please update soon.\n");
        return 1;
    }

    i2c_init(littlewire);
    i2c_updateDelay(littlewire,0);
    
    rc = i2c_start(littlewire, 0x50, WRITE);
    if(rc != 1)
    {
    	printf("> Device not found, please check connection to eeprom or USB Key exist\n> Exitting..\n");
    	return 2;
    }
    
    i2c_eeprom_read_buffer(littlewire, 0x50, 0, printable, 32);

    if (aes_init(printable, strlen(printable), (unsigned char *)&salt, &en, &de)) return 2;

    fp = fopen("/etc/MyAuth", "r");
    if (!fp)
    {
        EVP_CIPHER_CTX_cleanup(&en);
        EVP_CIPHER_CTX_cleanup(&de);
        return 3;
    }
    int fr;
    fr = fread(ciphertext, 1, 48, fp);
    if(!fr)
        return 4;
    fclose(fp);
    len =48;
    plaintext = (char *)aes_decrypt(&de, ciphertext, &len);

    if (strcmp(plaintext, secrettext) == 0)
        return 0;
    else
    {

        free(plaintext);
        EVP_CIPHER_CTX_cleanup(&en);
        EVP_CIPHER_CTX_cleanup(&de);
        return 5;
    }


}


PAM_EXTERN int pam_sm_setcred( pam_handle_t *pamh, int flags, int argc, const char **argv ) {
    return PAM_SUCCESS;
}

PAM_EXTERN int pam_sm_acct_mgmt(pam_handle_t *pamh, int flags, int argc, const char **argv) {
    return PAM_SUCCESS;
}

PAM_EXTERN int pam_sm_authenticate( pam_handle_t *pamh, int flags,int argc, const char **argv ) {

    int retval = CheckUSBkey();
    if (retval != 0)
    {
    	if(retval !=1)
        	printf("\n> USBkey Auth Err: %d\n", retval);
        return PAM_AUTH_ERR;
    }
    else
    {
    	printf("\n> USBkey Auth success.\n");
        return PAM_SUCCESS;
    }
}
