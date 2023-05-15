/* Quansheng UV-K5 emulator v0.1 
 * (c) 2023 Jacek Lipkowski <sq5bpf@lipkowski.org>
 *
 * This program connects to a unix socket (default /tmp/sock1 )
 * and looks like a UV-K5 radio to radio programming software.
 *
 * The radio eeprom is simulated by the file k5_eeprom_test.raw
 *
 * This can be used to reverse engineer the eeprom contents by
 * observing how the original radio programming software changes them.
 *
 * This can also be used to debug third party programming software,
 * like for example k5prog https://github.com/sq5bpf/k5prog
 *
 * Note: this is a one-off hack which i wrote for my own purpose, 
 * horrible code which will cause your eyes to bleed, with no error
 * checking etc. 
 *
 *
 * This program is licensed under the GNU GENERAL PUBLIC LICENSE v3
 * License text avaliable at: http://www.gnu.org/copyleft/gpl.html 
 */

/*
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
 *
 */


#include <sys/socket.h>
#include <sys/un.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <ctype.h>
#include <stdint.h>
#include <fcntl.h>


int verbose=0;

struct k5_command {
	unsigned char *cmd;
	int len;
	unsigned char *obfuscated_cmd;
	int obfuscated_len;
	int crcok;
};




void hdump(unsigned char *buf,int len)
{
	int tmp1;
	char adump[80];
	int tmp2=0;
	int tmp3=0;
	unsigned char sss;
	char hexz[]="0123456789abcdef";

	int lasttmp;

	printf("\n0x%6.6x |0 |1 |2 |3 |4 |5 |6 |7 |8 |9 |a |b |c |d |e |f |\n",len);
	printf("---------+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+------------\n");

	memset(&adump,' ',78);
	adump[78]=0;

	for (tmp1=0; tmp1<len; tmp1++)
	{
		tmp2=tmp1%16;
		if (tmp2==0) {
			if (tmp1!=0)  { printf("0x%6.6x: %.69s\n",tmp3,adump); lasttmp=tmp1; }
			memset(&adump,' ',78);
			adump[78]=0;
			tmp3=tmp1;
		}
		sss=buf[tmp1];
		adump[tmp2*3]=hexz[sss/16];
		adump[tmp2*3+1]=hexz[sss%16];

		if (isprint(sss)) { adump[tmp2+50]=sss; } else adump[tmp2+50]='.';
	}
	//if (((tmp1%16)!=0)||(len==16)) printf("0x%6.6x: %.69s\n",tmp3,adump);
	if (lasttmp!=tmp1) printf("0x%6.6x: %.69s\n",tmp3,adump);
}

/* hexdump a k5_command struct */
void k5_hexdump(struct k5_command *cmd) {
	printf ("********  k5 command hexdump [obf_len:%i clear_len:%i crc_ok:%i **********\n",cmd->obfuscated_len,cmd->len,cmd->crcok);
	if (cmd->obfuscated_cmd) {
		printf("## obfuscated ##\n");
		hdump(cmd->obfuscated_cmd,cmd->obfuscated_len);
	}
	if (cmd->cmd) {
		printf("## cleartext ##\n");
		hdump(cmd->cmd,cmd->len);
	}
	printf("*****************\n");
}

/* read with timeout */      
int read_timeout(int fd, unsigned char *buf, int maxlen, int timeout)
{
	fd_set rfd;
	int len=0;
	int ret;
	struct timeval tv;
	int nr;
	unsigned char *buf2;
	buf2=buf;
	FD_ZERO(&rfd); 

	while(1) {
		FD_SET(fd,&rfd);

		if (timeout<0) {
			ret=select(fd+1,&rfd,0,0,0);
		} else {
			tv.tv_sec=timeout/1000;
			tv.tv_usec=(timeout%1000)/1000;
			ret=select(fd+1,&rfd,0,0,&tv);
		}
		if (FD_ISSET(fd,&rfd)) {
			nr=read(fd,buf,maxlen);

			len=len+nr;
			buf=buf+nr;
			if (nr>=0) maxlen=maxlen-nr;
			if (maxlen==0) break;
		} 


		if (ret==0)  {
			fprintf(stderr,"read_timeout\n");
			/* error albo timeout */
			break;
		}

	}
	if (verbose>2) {
		printf("RXRXRX:\n");
		hdump(buf2,len);
	}

	return(len);
}       


void destroy_k5_struct(struct k5_command *cmd)
{
	if (cmd->cmd) { free(cmd->cmd); }
	if (cmd->obfuscated_cmd) { free(cmd->obfuscated_cmd); }
	free(cmd);
}

/* ripped from https://mdfs.net/Info/Comp/Comms/CRC16.htm */
uint16_t crc16xmodem(char *addr, int num, int crc)
{
#define poly 0x1021
	int i;

	for (; num>0; num--)               /* Step through bytes in memory */
	{
		crc = crc ^ (*addr++ << 8);      /* Fetch byte from memory, XOR into CRC top byte*/
		for (i=0; i<8; i++)              /* Prepare to rotate 8 bits */
		{
			crc = crc << 1;                /* rotate */
			if (crc & 0x10000)             /* bit 15 was set (now bit 16)... */
				crc = (crc ^ poly) & 0xFFFF; /* XOR with XMODEM polynomic */
			/* and ensure CRC remains 16-bit value */
		}                              /* Loop for 8 bits */
	}                                /* Loop until num=0 */

	return(crc);                     /* Return updated CRC */
}


/* (de)obfuscate the string using xor */
void xorarr(unsigned char *inarr,int len)
{
	int len2=0;
	unsigned char k5_xor_array[16]= {
		0x16 , 0x6c , 0x14 , 0xe6 , 0x2e , 0x91 , 0x0d , 0x40 ,
		0x21 , 0x35 , 0xd5 , 0x40 , 0x13 , 0x03 , 0xe9 , 0x80 };

	while (len2<len) {
		*inarr=*inarr^k5_xor_array[len2%sizeof(k5_xor_array)];
		len2++;
		inarr++;
	}
}



/* obfuscate a k5 datagram */
int k5_obfuscate(struct k5_command *cmd)
{
	uint16_t c;
	if (!cmd->cmd) return(0);
	if (cmd->obfuscated_cmd) { free (cmd->obfuscated_cmd); }
	cmd->obfuscated_len=cmd->len+8; /* header  + length + data + crc + footer */
	cmd->obfuscated_cmd=calloc(cmd->obfuscated_len,1);
	cmd->obfuscated_cmd[0]=0xab;
	cmd->obfuscated_cmd[1]=0xcd;
	cmd->obfuscated_cmd[2]=cmd->len;
	cmd->obfuscated_cmd[3]=0; /* or maybe more significant byte of length? */
	memcpy((cmd->obfuscated_cmd)+4,cmd->cmd,cmd->len);
	c=crc16xmodem((cmd->obfuscated_cmd)+4,cmd->len,0);
/*
  cmd->obfuscated_cmd[cmd->len+4]=c&0xff;
	cmd->obfuscated_cmd[cmd->len+5]=(c>>8)&0xff;
*/
cmd->obfuscated_cmd[cmd->len+4]=0xff;
cmd->obfuscated_cmd[cmd->len+5]=0xff;

	xorarr((cmd->obfuscated_cmd)+4,cmd->len+2);
	cmd->obfuscated_cmd[cmd->len+6]=0xdc;
	cmd->obfuscated_cmd[cmd->len+7]=0xba;
	cmd->crcok=1;
	return(1);
}


/* deobfuscate a k5 datagram and verify it */
int k5_deobfuscate(struct k5_command *cmd)
{
	uint16_t c,d;

	if (!cmd->obfuscated_cmd) return(0);
	if (cmd->cmd) { free (cmd->cmd); }
	/* check the obfuscated datagram */
	if ((cmd->obfuscated_cmd[0]!=0xab)||(cmd->obfuscated_cmd[1]!=0xcd)) {
		//bad header
		if (verbose>2)  { printf("bad header\n"); k5_hexdump(cmd); }
		return(0);
	}
	if ((cmd->obfuscated_cmd[cmd->obfuscated_len-2]!=0xdc)||(cmd->obfuscated_cmd[cmd->obfuscated_len-1]!=0xba)) {
		//bad footer
		if (verbose>2)  { printf("bad footer\n"); k5_hexdump(cmd); }
		return(0);
	}
	cmd->len=cmd->obfuscated_len-6; /* header  + length + data + crc + footer */
	cmd->cmd=calloc(cmd->len,1);
	memcpy(cmd->cmd,cmd->obfuscated_cmd+4,cmd->len);
	xorarr(cmd->cmd,cmd->len);
	c=crc16xmodem(cmd->cmd,cmd->len-2,0);
	d=(cmd->cmd[cmd->len-2])|(cmd->cmd[cmd->len-1]<<8);
	//if ((*cmd->cmd[*cmd->cmd-2]==(c&0xff))&&(*cmd->cmd[*cmd->cmd-2]==((c<<8)&0xff)))
	/* the protocol looks like it would use crc from the radio to the pc, but instead the radio sends 0xffff */
	if (d==0xffff)
	{
		cmd->crcok=1;
		cmd->len=cmd->len-2; /* skip crc */
	} else {
	/*	if (d==c) {
			printf("** the protocol actually uses proper crc on datagrams from the radio, please inform the author of the radio/firmware version\n");
			k5_hexdump(cmd);
		}
	*/
		cmd->crcok=0;
		if (verbose>2)  { printf("bad crc 0x%4.4x (should be 0x%4.4x)\n",d,c); k5_hexdump(cmd); }
		cmd->len=cmd->len-2; /* skip crc */
		return(0);

	}
	return(1);
}


/* obfuscate a command, send it */
int k5_send_cmd(int fd,struct k5_command *cmd) {
	int l;

	if (!k5_obfuscate(cmd)) {
		fprintf(stderr,"obfuscate error!\n");
		return(0);
	}

	if (verbose>1) k5_hexdump(cmd);

	l=write(fd,cmd->obfuscated_cmd,cmd->obfuscated_len);
	if (verbose>2) printf("write %i\n",l);
	return(1);
}

int k5_send_buf(int fd,unsigned char *buf,int len) {
	int l;
	struct k5_command *cmd;

	cmd=calloc(sizeof(struct k5_command),1);
	cmd->len=len;
	cmd->cmd=malloc(cmd->len);
	memcpy(cmd->cmd,buf,len);
	l=k5_send_cmd(fd,cmd);
	destroy_k5_struct(cmd);
	return(l);
}

/* receive a response, deobfuscate it */
struct k5_command *k5_receive(int fd) {
	unsigned char buf[4];
	unsigned char buf2[2048];
	struct k5_command *cmd;
	int len;

	len=read_timeout(fd,(unsigned char *)&buf,sizeof(buf),-1); /* wait 500ms */

	if (len>0) {
		if (verbose>2)  { printf("magic:\n"); hdump((unsigned char *)&buf,len); }
	} else
	{
		fprintf(stderr,"k5_receive: err read1\n");
		return(0);
	}


	if ((buf[0]!=0xab)||(buf[1]!=0xcd)) {
		fprintf(stderr,"k5_receive: bad magic number\n");
		return(0);
	}

	if (buf[3]!=0) {
		fprintf(stderr,"k5_receive: it seems that byte 3 can be something else than 0, please notify the author\n");
		return(0);
	}

	cmd=calloc(sizeof(struct k5_command),1);
	cmd->obfuscated_len=buf[2]+8;
	cmd->obfuscated_cmd=calloc(cmd->obfuscated_len,1);
	memcpy(cmd->obfuscated_cmd,buf,4);
	len=read_timeout(fd,cmd->obfuscated_cmd+4,buf[2]+4,10000); /* wait 500ms */
	if ((len+4)!=(cmd->obfuscated_len)) {
		fprintf(stderr,"k5_receive err read1 len=%i wanted=%i\n",len,cmd->obfuscated_len);
		return(0);
	}


	/* deobfuscate */
	k5_deobfuscate(cmd);
	if (verbose>2)  k5_hexdump(cmd);
	return(cmd);
}
/*
   int k5_send_buf(int fd,unsigned char *buf,int len) {
   int l;
   struct k5_command *cmd;

   cmd=calloc(sizeof(struct k5_command),1);
   cmd->len=len;
   cmd->cmd=malloc(cmd->len);
   memcpy(cmd->cmd,buf,len);
   l=k5_send_cmd(fd,cmd);
   destroy_k5_struct(cmd);
   return(l);
   }

*/

#define EEPROMFILE "k5_eeprom_test.raw"

int handle_cmd(int fd,struct k5_command *cmd) {
	unsigned char command,len,memlen;
	uint16_t addr;
	unsigned char sendbuf[512];
			int fd2;
	/* byte3 - command length, byte6 - data to be written length, byte4 - (lsb) byte5( msb) address, byte12-end data */
	command=cmd->cmd[0];
	len=cmd->cmd[3];
	memlen=cmd->cmd[6];
	addr=(cmd->cmd[4])|(cmd->cmd[5]<<8);

if (verbose>1) {
	printf("XXXXXXXXXXXXXXXXXXXXXXXX   command=0x%2.2x len=0x%2.2x addr=0x%4.4x memlen=0x%2.2x\n",command,len,addr,memlen);


	k5_hexdump(cmd);



	printf("xxxxxxxxxxxxx   response   xxxxxxxxxxxxxxxxx\n\n\n");
}
	memcpy((void *)&sendbuf,cmd->cmd,8);
sendbuf[0]=command+1; /* response is 1 higher than reqest */

	switch(command) {

		case 0x14:
			printf("HELLO REQUEST\n");
			/* hello */
			//unsigned char hello[]={ 0x15,  0x5,  0x24,  0x0,  0x6b,  0x35,  0x5f,  0x32,  0x2e,  0x30,  0x31,  0x2e,  0x32,  0x33,  0x0,  0x0,  0x3c,  0xe2,  0x0,  0x0,  0x0,  0x0,  0x0,  0x0,  0x66,  0x35,  0x73,  0x74,  0xc1,  0xf,  0x1a,  0x3,  0x49,  0x9b,  0x2b,  0x73,  0x68,  0x9b,  0x3a,  0x17 };
			unsigned char hello[]={ 0x15,  0x5,  0x24,  0x0,  'S',  'Q',  '5',  'B',  'P',  'F',  '-',  'K',  '5',  'e',  'm',  'u',  0x00,  0xff,  0xff,  0xff,  0xff,  0xff,  0xff,  0xff,  0xff,  0xff,  0xff,  0xff,  0xff,  0xff,  0xff,  0xff,  0xff,  0xff,  0xff,  0xff,  0xff,  0xff,  0xff,  0xff };
			k5_send_buf(fd,hello,sizeof(hello));
			//	memcpy(void *)&sendbuf+8,(void *)&hello+8,sizeof(hello)-8);
			//			k5_send_buf(fd,sendbuf,sizeof(hello));

			break;
		case 0x1b:
			printf("READ REQUEST addr=0x%4.4x len=0x%2.2x\n",addr,memlen);
			// 1c 05 04 00 c0 0b 00 00 

			unsigned char readmem[512]={0x1c, 0x5, 0x14, 0x0, 0xc0, 0xb, 0x10, 0x0 };
			sendbuf[2]=memlen+4;

			/* data at 08 */
			fd2=open(EEPROMFILE,O_RDONLY);
			lseek(fd2,addr,SEEK_SET);
			read(fd2,(void *)&sendbuf+8,memlen);
			close(fd2);

			k5_send_buf(fd,sendbuf,memlen+8);
			break;
		case 0x1d:
			printf("WRITE REQUEST addr=0x%4.4x len=0x%2.2x\n",addr,memlen);
			// request:  0x1d  0x5  0x18  0x0  0x50  0xf  0x10  0x0  0x14  0xad  0x5c  0x64  0x43  0x48  0x30  0x30  0x31  0x0  0x0  0x0  0x0  0x0  0x0  0x0  0x0  0x0  0x0  0x0
			// reply:    0x1e  0x5  0x02  0x0  0x50  0xf

			unsigned char writemem[6]={ 0x1e,  0x5,  0x02,  0x0,  0x50,  0xf };
			sendbuf[2]=0x2;

			/* data at 08 */
			fd2=open(EEPROMFILE,O_WRONLY);
			lseek(fd2,addr,SEEK_SET);
			write(fd2,(void *)cmd->cmd+12,memlen);
			close(fd2);

			k5_send_buf(fd,sendbuf,6);
			break;
		case 0xdd:
			printf("RESET REQUEST\n");
			break;
		default:
			printf("Unknown command=0x%2.2x len=0x%2.2x addr=0x%4.4x memlen=0x%2.2x\n",command,len,addr,memlen);
	}
if (verbose>2)
	printf("xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx\n\n\n");
}


char *socket_path = "/tmp/sock1";

int main(int argc, char *argv[]) {
	struct sockaddr_un addr;
	char buf[256];
	int fd,rc;
	struct k5_command *cmd;

	if (argc > 1) socket_path=argv[1];

	if ( (fd = socket(AF_UNIX, SOCK_STREAM, 0)) == -1) {
		perror("socket error");
		exit(-1);
	}

	memset(&addr, 0, sizeof(addr));
	addr.sun_family = AF_UNIX;
	if (*socket_path == '\0') {
		*addr.sun_path = '\0';
		strncpy(addr.sun_path+1, socket_path+1, sizeof(addr.sun_path)-2);
	} else {
		strncpy(addr.sun_path, socket_path, sizeof(addr.sun_path)-1);
	}

	if (connect(fd, (struct sockaddr*)&addr, sizeof(addr)) == -1) {
		perror("connect error");
		exit(-1);
	}

	while(1) {
		cmd=k5_receive(fd);
		if (cmd) {
			handle_cmd(fd,cmd);
			destroy_k5_struct(cmd);

		}


	}

	/*	while( (rc=read(fd, buf, sizeof(buf))) > 0) {
		hdump(buf,rc);
		}
		*/	/*
			   while( (rc=read(STDIN_FILENO, buf, sizeof(buf))) > 0) {
			   if (write(fd, buf, rc) != rc) {
			   if (rc > 0) fprintf(stderr,"partial write");
			   else {
			   perror("write error");
			   exit(-1);
			   }
			   }
			   }
			   */
	return 0;
}
