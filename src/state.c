#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <stdint.h>
#include <termios.h>
#include <unistd.h>
#include <time.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <ctype.h>
#include <errno.h>

#include "log.h"
#include "serial.h"
#include "lora.h"
#include "rn2483.h"
#include "fuota.h"

#define	RETRY_OPEN_DELAY  10	/*!< Delay in seconds to wait before retry to open serial device */
#define RETRY_RESET_DELAY 10 	/*!< Delay in seconds to wait before retry to reset RN2483 */
#define	MAX_RESET_COUNT	  20	/*!< Number of maximum software reset after which an hardware reset is needed */

typedef enum {
  START=0,		/*!< Starting point */
  HWRESET,    	/*!< RN2483 needs to be reset: at process start and after every fault condition */
  SWRESET,		/*!< Do a software reset and set baud rate */
  INIT,		    /*!< Initialization completed */
  JOIN,		    /*!< Module has joined the network */
  LISTEN,		/*!< Continuous listening */
  TRANSMITTING, /*!< Module is transmitting data */
  RECEIVING     /*!< Module is receiving data */
}	STATE;

int RN2483_process_status(uint32_t status){
	switch(status & 0b1111){
		case 0: printf("Mac State: IDLE\n"); break;
		case 1: printf("Mac State: TRANSMITTING\n"); break;
		case 2: printf("Mac State: B4 RX1\n"); break;
		case 3: printf("Mac State: RX1\n"); break;
		case 4: printf("Mac State: B4 RX2\n"); break;
		case 5: printf("Mac State: RX2\n"); break;
		case 6: printf("Mac State: RX DELAY\n"); break;
		case 7: printf("Mac State: ABP DELAY\n"); break;
		case 8: printf("Mac State: C RX2 1\n"); break;
		case 9: printf("Mac State: C RX2 2\n"); break;
		}
	if( status & 0b0000000000000010000) printf("Network:   Joined\n");
	else return RN2483_ERR_NOT_JOINED;

	if( status & 0b0000000000000100000) printf("AR:        Enabled\n");
	if( status & 0b0000000000001000000) printf("ADR:       Enabled\n");
	if( status & 0b0000000000010000000) printf("Silent Imm:Enabled\n");
	if( status & 0b0000000000100000000){printf("Mac:       Paused\n" );
		return RN2483_ERR_STATE;
		}								
	if( status & 0b0000000001000000000){printf("Rx Data:   Ready\n"  );
		return RN2483_MAC_RX;
		}
	if( status & 0b0000000010000000000) printf("Link Check:Enabled\n");
	if( status & 0b0000000100000000000) printf("Channels:  Updated\n");
	if( status & 0b0000001000000000000) printf("Output Pwr:Updated\n");
	if( status & 0b0000010000000000000) printf("NbRep:     Updated\n");
	if( status & 0b0000100000000000000) printf("Prescaler: Updated\n");
	if( status & 0b0001000000000000000) printf("RX2 Params:Updated\n");
	if( status & 0b0010000000000000000) printf("RX Timing: Updated\n");
	if( status & 0b0100000000000000000){printf("Rejoin:    Needed\n" );
		return RN2483_ERR_NOT_JOINED; 
		}
	if( status & 0b1000000000000000000) printf("Multicast: Enabled\n");
	return RET_OK;
	}

void* state(/*void* unused*/){

	//struct timespec	now;
  	//struct timespec	t;

    STATE state=START;
	int retries=0;

    while(1){
        switch (state){
			case START:{
				RN2483_init_serial();
				retries=0;
				state=HWRESET;
			} break;

			case HWRESET:{
				printf("HWRESET\n");
				//TODO HWRESET
				state=SWRESET;
				} break;
			
			case SWRESET:{
				printf("SWRESET\n");
				if(retries>=MAX_RESET_COUNT) exit(EXIT_FAILURE);
				//TODO SWRESET
				state=INIT;
				} break;

			case INIT:{
				printf("INIT\n");
				if( RN2483_initMAC()!=RN2483_OK){
					sleep(2);
					retries++;
					state=HWRESET; break;
					}
				else state=JOIN;
			} break;

			case JOIN:{
				printf("JOIN\n");
				if( RN2483_join(RN2483_ABP)!=RN2483_OK){
					sleep(2);
					retries++;
					state=HWRESET; break;
					}
				else state=TRANSMITTING;
			} break;

			case TRANSMITTING:{
				printf("TRANSMITTING\n");
				char buff[RN2483_MAX_BUFF]="online";
				char downlink[RN2483_MAX_BUFF]={0};

				int ret=RN2483_tx(buff, LoRaWAN_CNF, downlink);
				if(ret==RN2483_NODOWN){ state=LISTEN; /*no downlink*/ }
				else if( ret!=RN2483_OK){
					sleep(2);
					retries++;
					state=HWRESET; break;
					}
				else{ state=LISTEN;	   /*do something with downlink*/ }
				
			} break;

			case LISTEN:{
				printf("LISTEN\n");
				char resp[RN2483_MAX_BUFF]={'\0'};
				if(RN2483_read(resp)!=RET_OK ){
					state=HWRESET;
					break;
					}
				}

			default:
			break;
			}

    	}
	}

int main(){
	state();
	return RET_OK;
}

