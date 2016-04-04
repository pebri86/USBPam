/*
 * mfrc522.c
 *
 * Copyright 2013 Shimon <shimon@monistit.com>
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston,
 * MA 02110-1301, USA.
 *
 *
 */
#include "mfrc522.h"

//key default A and B
uint8_t keyA_default[6] = {0xff,0xff,0xff,0xff,0xff,0xff};
uint8_t keyB_default[6] = {0xff,0xff,0xff,0xff,0xff,0xff};

/*
initialize rc522
*/
void mfrc522_init(littleWire *lwHandle)
{
    uint8_t byte;
    mfrc522_reset(lwHandle);
    pinMode(lwHandle, PIN3, OUTPUT);

    mfrc522_write(lwHandle, TModeReg, 0x8D);
    mfrc522_write(lwHandle, TPrescalerReg, 0x3E);
    mfrc522_write(lwHandle, TReloadReg_1, 30);
    mfrc522_write(lwHandle, TReloadReg_2, 0);
    mfrc522_write(lwHandle, TxASKReg, 0x40);
    mfrc522_write(lwHandle, ModeReg, 0x3D);

    // antenna on
    byte = mfrc522_read(lwHandle, TxControlReg);
    if(!(byte&0x03))
    {
        mfrc522_write(lwHandle, TxControlReg,byte|0x03);
    }
}

/*
spi transmit over LittleWire
*/
uint8_t spi_transmit(littleWire *lwHandle, uint8_t data)
{
    unsigned char sBuffer[1];
    unsigned char rBuffer[1];
    sBuffer[0] = data;
    spi_rw(lwHandle, sBuffer, rBuffer, 1);
    return rBuffer[0];
}

/*
write data to rc522 register
*/
void mfrc522_write(littleWire *lwHandle, uint8_t reg, uint8_t data)
{
    //ENABLE_CHIP();
    digitalWrite(lwHandle, PIN3, LOW);
    spi_transmit(lwHandle, (reg<<1)&0x7E);
    spi_transmit(lwHandle, data);
    //DISABLE_CHIP();
    digitalWrite(lwHandle, PIN3, HIGH);
}

/*
read data from rc522 register
*/
uint8_t mfrc522_read(littleWire *lwHandle, uint8_t reg)
{
    uint8_t data;
    //ENABLE_CHIP();
    digitalWrite(lwHandle, PIN3, LOW);
    spi_transmit(lwHandle, ((reg<<1)&0x7E)|0x80);
    data = spi_transmit(lwHandle, 0x00);
    //DISABLE_CHIP();
    digitalWrite(lwHandle, PIN3, HIGH);
    return data;
}

/*
soft reset rc522
*/
void mfrc522_reset(littleWire *lwHandle)
{
    mfrc522_write(lwHandle,CommandReg,SoftReset_CMD);
}

/*
make command request to rc522
*/
uint8_t	mfrc522_request(littleWire *lwHandle, uint8_t req_mode, uint8_t * tag_type)
{
    uint8_t  status;
    uint32_t backBits;//The received data bits

    mfrc522_write(lwHandle,BitFramingReg, 0x07);//TxLastBists = BitFramingReg[2..0]	???

    tag_type[0] = req_mode;
    status = mfrc522_to_card(lwHandle,Transceive_CMD, tag_type, 1, tag_type, &backBits);

    if ((status != CARD_FOUND) || (backBits != 0x10))
    {
        status = ERROR;
    }

    return status;
}

/*
send command to rc522 to card
*/
uint8_t mfrc522_to_card(littleWire *lwHandle, uint8_t cmd, uint8_t *send_data, uint8_t send_data_len, uint8_t *back_data, uint32_t *back_data_len)
{
    uint8_t status = ERROR;
    uint8_t irqEn = 0x00;
    uint8_t waitIRq = 0x00;
    uint8_t lastBits;
    uint8_t n;
    uint8_t	tmp;
    uint32_t i;

    switch (cmd)
    {
    case MFAuthent_CMD:		//Certification cards close
    {
        irqEn = 0x12;
        waitIRq = 0x10;
        break;
    }
    case Transceive_CMD:	//Transmit FIFO data
    {
        irqEn = 0x77;
        waitIRq = 0x30;
        break;
    }
    default:
        break;
    }

    //mfrc522_write(ComIEnReg, irqEn|0x80);	//Interrupt request
    n=mfrc522_read(lwHandle,ComIrqReg);
    mfrc522_write(lwHandle,ComIrqReg,n&(~0x80));//clear all interrupt bits
    n=mfrc522_read(lwHandle,FIFOLevelReg);
    mfrc522_write(lwHandle,FIFOLevelReg,n|0x80);//flush FIFO data

    mfrc522_write(lwHandle,CommandReg, Idle_CMD);	//NO action; Cancel the current cmd???

    //Writing data to the FIFO
    for (i=0; i<send_data_len; i++)
    {
        mfrc522_write(lwHandle,FIFODataReg, send_data[i]);
    }

    //Execute the cmd
    mfrc522_write(lwHandle,CommandReg, cmd);
    if (cmd == Transceive_CMD)
    {
        n=mfrc522_read(lwHandle,BitFramingReg);
        mfrc522_write(lwHandle,BitFramingReg,n|0x80);
    }

    //Waiting to receive data to complete
    i = 2000;	//i according to the clock frequency adjustment, the operator M1 card maximum waiting time 25ms???
    do
    {
        //CommIrqReg[7..0]
        //Set1 TxIRq RxIRq IdleIRq HiAlerIRq LoAlertIRq ErrIRq TimerIRq
        n = mfrc522_read(lwHandle,ComIrqReg);
        i--;
    }
    while ((i!=0) && !(n&0x01) && !(n&waitIRq));

    tmp=mfrc522_read(lwHandle,BitFramingReg);
    mfrc522_write(lwHandle,BitFramingReg,tmp&(~0x80));

    if (i != 0)
    {
        if(!(mfrc522_read(lwHandle,ErrorReg) & 0x1B))	//BufferOvfl Collerr CRCErr ProtecolErr
        {
            status = CARD_FOUND;
            if (n & irqEn & 0x01)
            {
                status = CARD_NOT_FOUND;			//??
            }

            if (cmd == Transceive_CMD)
            {
                n = mfrc522_read(lwHandle,FIFOLevelReg);
                lastBits = mfrc522_read(lwHandle,ControlReg) & 0x07;
                if (lastBits)
                {
                    *back_data_len = (uint32_t)(n-1)*8 + (uint32_t)lastBits;
                }
                else
                {
                    *back_data_len = (uint32_t)n*8;
                }

                if (n == 0)
                {
                    n = 1;
                }
                if (n > MAX_LEN)
                {
                    n = MAX_LEN;
                }

                //Reading the received data in FIFO
                for (i=0; i<n; i++)
                {
                    back_data[i] = mfrc522_read(lwHandle,FIFODataReg);
                }
            }
        }
        else
        {
            status = ERROR;
        }

    }

    //SetBitMask(ControlReg,0x80);           //timer stops
    //mfrc522_write(cmdReg, PCD_IDLE);

    return status;
}

/*
get card serial
*/
uint8_t mfrc522_get_card_serial(littleWire *lwHandle, uint8_t * serial_out)
{
    uint8_t status;
    uint8_t i;
    uint8_t serNumCheck=0;
    uint32_t unLen;

    mfrc522_write(lwHandle,BitFramingReg, 0x00);		//TxLastBists = BitFramingReg[2..0]

    serial_out[0] = PICC_ANTICOLL;
    serial_out[1] = 0x20;
    status = mfrc522_to_card(lwHandle,Transceive_CMD, serial_out, 2, serial_out, &unLen);

    if (status == CARD_FOUND)
    {
        //Check card serial number
        for (i=0; i<4; i++)
        {
            serNumCheck ^= serial_out[i];
        }
        if (serNumCheck != serial_out[i])
        {
            status = ERROR;
        }
    }
    return status;
}

/*
set bit mask
*/
void mfrc522_setBitMask(littleWire *lwHandle, uint8_t reg, uint8_t mask)
{
    uint8_t tmp;
    tmp = mfrc522_read(lwHandle,reg);
    mfrc522_write(lwHandle,reg, tmp | mask);  // set bit mask
}

/*
clear bit mask
*/
void mfrc522_clearBitMask(littleWire *lwHandle, uint8_t reg, uint8_t mask)
{
    uint8_t tmp;
    tmp = mfrc522_read(lwHandle,reg);
    mfrc522_write(lwHandle,reg, tmp & (~mask));  // clear bit mask
}

/*
calculate crc using rc522 chip
*/
void mfrc522_calculateCRC(littleWire *lwHandle, uint8_t *pIndata, uint8_t len, uint8_t *pOutData)
{
    uint8_t i, n;

    mfrc522_clearBitMask(lwHandle,DivIrqReg, 0x04);			//CRCIrq = 0
    mfrc522_setBitMask(lwHandle,FIFOLevelReg, 0x80);			//Claro puntero FIFO
    //Write_MFRC522(CommandReg, PCD_IDLE);

    //Escribir datos en el FIFO
    for (i=0; i<len; i++)
    {
        mfrc522_write(lwHandle,FIFODataReg, *(pIndata+i));
    }
    mfrc522_write(lwHandle,CommandReg, PCD_CALCCRC);

    // Esperar a la finalización de cálculo del CRC
    i = 0xFF;
    do
    {
        n = mfrc522_read(lwHandle,DivIrqReg);
        i--;
    }
    while ((i!=0) && !(n&0x04));			//CRCIrq = 1

    //Lea el cálculo de CRC
    pOutData[0] = mfrc522_read(lwHandle,CRCResultReg_2);
    pOutData[1] = mfrc522_read(lwHandle,CRCResultReg_1);
}

/*
halt the card (release it to be able to read again)
*/
uint8_t mfrc522_halt(littleWire *lwHandle)
{
    uint8_t status;
    uint32_t unLen;
    uint8_t buff[4];

    buff[0] = PICC_HALT;
    buff[1] = 0;
    mfrc522_calculateCRC(lwHandle,buff, 2, &buff[2]);

    mfrc522_clearBitMask(lwHandle,Status2Reg, 0x08); // turn off encryption

    status = mfrc522_to_card(lwHandle,Transceive_CMD, buff, 4, buff,&unLen);

    return status;
}

/*
get reader version
*/
uint8_t mfrc522_get_version(littleWire *lwHandle)
{
    return mfrc522_read(lwHandle,VersionReg);
}

/*
check if card is in range
*/
uint8_t mfrc522_is_card(littleWire *lwHandle, uint16_t *card_type)
{
    uint8_t buff_data[MAX_LEN],
            status = mfrc522_request(lwHandle,PICC_REQIDL,buff_data);
    if(status == CARD_FOUND)
    {
        *card_type = (buff_data[0]<<8)+buff_data[1];
        return 1;
    }
    else
    {
        return 0;
    }
}

/*
 * Function Name : MFRC522_Auth
 * Description : Verify card password
 * Input parameters : authMode - Password Authentication Mode
                 0x60 = A key authentication
                 0x61 = B key authentication
             BlockAddr - block address
             Sectorkey - Sector password
             serNum - card serial number, 4-byte
 * Return value: the successful return CARD_FOUND
 */
uint8_t mfrc522_auth(littleWire *lwHandle, uint8_t authMode, uint8_t BlockAddr, uint8_t *Sectorkey, uint8_t *serNum)
{
    uint8_t status;
    uint32_t recvBits;
    uint8_t i;
    uint8_t buff[12];

    // Validate instruction block address + sector + password + card serial number
    buff[0] = authMode;
    buff[1] = BlockAddr;
    for (i=0; i<6; i++)
    {
        buff[i+2] = *(Sectorkey+i);
    }
    for (i=0; i<4; i++)
    {
        buff[i+8] = *(serNum+i);
    }
    status = mfrc522_to_card(lwHandle,PCD_AUTHENT, buff, 12, buff, &recvBits);
    i = mfrc522_read(lwHandle,Status2Reg);

    if ((status != CARD_FOUND) || (!(i & 0x08)))
    {
        status = ERROR;
    }

    return status;
}

/*
 * Function Name : MFRC522_Write
 * Description : Write block data
 * Input parameters : blockAddr - block address ; writeData - to 16-byte data block write
 * Return value: the successful return CARD_FOUND
 */
uint8_t mfrc522_write_block(littleWire *lwHandle, uint8_t blockAddr, uint8_t *writeData)
{
    uint8_t status;
    uint32_t recvBits;
    uint8_t i;
    uint8_t buff[18];

    buff[0] = PICC_WRITE;
    buff[1] = blockAddr;
    mfrc522_calculateCRC(lwHandle,buff, 2, &buff[2]);
    status = mfrc522_to_card(lwHandle,PCD_TRANSCEIVE, buff, 4, buff, &recvBits);

    //cek
    //printf("w1 = %d\t%d\t%.2X\n", status, recvBits, buff[0]);

    if ((status != CARD_FOUND) || (recvBits != 4) || ((buff[0] & 0x0F) != 0x0A))
    {
        status = ERROR;
    }

    if (status == CARD_FOUND)
    {
        for (i=0; i<16; i++)		//?FIFO?16Byte??
        {
            buff[i] = *(writeData+i);
        }
        mfrc522_calculateCRC(lwHandle,buff, 16, &buff[16]);
        status = mfrc522_to_card(lwHandle,PCD_TRANSCEIVE, buff, 18, buff, &recvBits);

        //cek
        //printf("w2 = %d\t%d\t%.2X\n", status, recvBits, buff[0]);

        if ((status != CARD_FOUND) || (recvBits != 4) || ((buff[0] & 0x0F) != 0x0A))
        {
            status = ERROR;
        }
    }

    return status;
}

/*
 * Function Name : MFRC522_Read
 * Description : Read block data
 * Input parameters : blockAddr - block address ; recvData - read block data
 * Return value: the successful return MI_OK
 */
uint8_t mfrc522_read_block(littleWire *lwHandle, uint8_t blockAddr, uint8_t *recvData)
{
    uint8_t status;
    uint32_t unLen;

    recvData[0] = PICC_READ;
    recvData[1] = blockAddr;
    mfrc522_calculateCRC(lwHandle,recvData,2, &recvData[2]);
    status = mfrc522_to_card(lwHandle,PCD_TRANSCEIVE, recvData, 4, recvData, &unLen);

    //cek
//    printf("read block #%d = %.2X %.4X\n", blockAddr, status, unLen);

    if ((status != CARD_FOUND) || (unLen != 0x90))
    {
        status = ERROR;
    }

    return status;
}

/*
 * Function Name : MFRC522_SelectTag
 * Description: election card , read the card memory capacity
 * Input parameters : serNum - Incoming card serial number
 * Return value: the successful return of card capacity
 */
uint8_t mfrc522_select_tag(littleWire *lwHandle, uint8_t *serNum)
{
    uint8_t i;
    uint8_t status;
    uint8_t size;
    uint32_t recvBits;
    uint8_t buffer[9];

    //ClearBitMask(Status2Reg, 0x08);			//MFCrypto1On=0

    buffer[0] = PICC_SElECTTAG;
    buffer[1] = 0x70;
    for (i=0; i<5; i++)
    {
        buffer[i+2] = *(serNum+i);
    }
    mfrc522_calculateCRC(lwHandle,buffer, 7, &buffer[7]);		//??
    status = mfrc522_to_card(lwHandle,PCD_TRANSCEIVE, buffer, 9, buffer, &recvBits);

    if ((status == CARD_FOUND) && (recvBits == 0x18))
    {
        size = buffer[0];
    }
    else
    {
        size = 0;
    }

    return size;
}
