#include <termios.h>
#include <unistd.h>
#include <stdlib.h>
#include <stdint.h>
#include <time.h>
#include <limits.h>
#include <errno.h>
#include "config.h"
#include "rn2483.h"
#include "lora.h"
#include "serial.h"
#include "log.h"
#include "fuota.h"

SERIAL_PORT RN2483_port;

//PRIVATE=====================================================================//

/**
 * @brief Converts buff into a string representation of it hexadecimal representation
 * @param buff
 * @param buff_len 
 * @param ret 
 */
static void get_hex_string(uint8_t *buff, int buff_len, char *ret){
    int j;  //index of buff
    int i;  //index of string
    uint8_t nibble;
    const char hex_map[16] = {'0', '1', '2', '3', '4', '5', '6', '7', '8', '9', 'A', 'B', 'C', 'D', 'E', 'F'};

    for (i = 0, j = 0; i < buff_len*2; i++){
        nibble = 20;    // out of bounds of hex_map

        if (i % 2 == 0)
            nibble = (buff[j] >> 4) & 0x0F;
        else{
            nibble = buff[j] & 0x0F;
            j++;
            }

        ret[i] = hex_map[nibble];
        }

    return;
    }


/**
 * @brief Checks if the string represents a number or not
 * 
 * @param str 
 * @return 0 if string is NaN, 1 otherwise
 */
static inline int isNumber( char* str){
char* e=NULL;
errno=0;
long int val=strtol(str, &e,10); 	//dont care about converted value rn
if( e==NULL || !(*e=='\n' || *e=='\0') ){
    fprintf(stderr, "Error: string %s is NaN\n", str);
    return 0;
    }
if( errno == ERANGE && (val == LONG_MAX || val == LONG_MIN) ){
    fprintf(stderr, "Error: string %s is an out of range number\n", str);
    return 0;
    }
if( errno != 0 && val == 0){
    fprintf(stderr, "Error: the string si empty\n");
    return 0;
    }
return 1;
}

//PUBLIC======================================================================//

void RN2483_init_serial(){
    //Skipped the conf setup, giving default values manually
    snprintf(RN2483_port.device, sizeof(RN2483_port.device), "/dev/ttyS2");
    RN2483_port.speed=B57600;
    RN2483_port.num_bits=8;
    RN2483_port.parity=NONE;
    RN2483_port.stop_bits=1;

    lora_open_channel(&RN2483_port);
    }

void RN2483_shut_serial(){
    lora_close_channel(&RN2483_port);
    }

RN2483_RC RN2483_read(char *response){
    size_t len=RN2483_MAX_BUFF;
    struct timespec to;
    to.tv_nsec=0;
    to.tv_sec=5;

    int ret;

    switch(lora_read_channel(&RN2483_port, response, &len, &to)){
        case RET_OK:{
            ret=RN2483_OK;
            } break;
        case RET_WARNING:{
            len=0;
            ret=RN2483_OK;
            } break;
        default:{
            return RN2483_ERR_PANIC;
            } break;
        }
    //get_hex_string(buf, len, response); //NO
    if(len!=0) printf("\tRSP: %s\n", response);
    return ret;
    }

RN2483_RC RN2483_process_rx(char *rx){
	char* mac_rx=strtok_r(rx," ",&rx);
	char* port_str=strtok_r(rx," ",&rx);
	char* cont=strtok_r(rx," ",&rx);
	int port=-1;

    if( strcmp(mac_rx,"mac_rx")!=0 ){
        log_error("Rx message wrong syntax");
        return RN2483_ERR_PANIC;
        }

	if( !isNumber(port_str)){
		log_error("Rx port field is NaN");
		return RN2483_ERR_RX_PORT;
		}
	else port=atoi(port_str);

	if(port<0 || port>223){
		log_error("Rx port field is not a valid value [0-223]");
		return RN2483_ERR_RX_PORT;	
		}
	else if( port==200){
		if( handleMulticastControlCommand(cont, sizeof(cont))!=FUOTA_OK ){                  // /!\ CHAR -> UINT*_T
            log_error("Something went wrong while handling Multicast packet");
            //RET? Errors in application level arent errors for the MAC layer
            }
		}
	else if( port==201){
		if( handleFragmentationCommand(cont, sizeof(cont))!=FUOTA_OK ){                     // /!\ CHAR -> UINT*_T
            log_error("Something went wrong while handling Fragmentation packet");
            //RET?
            }
		}
    
    return RN2483_OK;
	}

RN2483_RC RN2483_process_resp( char *resp) {
	char ret;
	//printf("%s\n", resp);
	if(      strcmp(resp,"ok\r\n")==0 )			    ret=RN2483_OK;
	else if( strcmp(resp,"invalid_param\r\n")==0)	ret=RN2483_ERR_PARAM;
	else if( strcmp(resp,"not_joined\r\n")==0)		ret=RN2483_ERR_NOT_JOINED;
	else if( strcmp(resp,"no_free_ch\r\n")==0)		ret=RN2483_ERR_NO_FREE_CH;
	else if( strcmp(resp,"silent\r\n")==0)			ret=RN2483_ERR_BUSY;
	else if( strcmp(resp,"frame_counter_err_rejoin_needed\r\n")==0) ret=RN2483_ERR_FR_CNT;
	else if( strcmp(resp,"busy\r\n")==0)			ret=RN2483_ERR_STATE;
	else if( strcmp(resp,"mac_err\r\n")==0)     	ret=RN2483_MAC_ERR;
	else if( strcmp(resp,"invalid_data_len\r\n")==0) ret=RN2483_ERR_LENGTH;
    else if( strcmp(resp,"accepted\r\n")==0)	    ret=RN2483_ACCEPTED;
	else if( strcmp(resp,"denied\r\n")==0) 	        ret=RN2483_ERR_DENIED;
	else if( strcmp(resp,"mac_tx_ok\r\n")==0)   	ret=RN2483_MAC_TX_OK;
	else if(strncmp(resp,"mac_rx\r\n", 6)==0){
		ret=RN2483_process_rx(resp);
        if(ret!=RN2483_OK) return ret;
        else ret=RN2483_MAC_RX;
		}
	else ret=RN2483_OTHER;
    return ret;
	}

RN2483_RC RN2483_command(char *command, char *response){
	//check command ends with \r\n (easy to forget)
	int end = strlen(command);
	if (command[end-2] != '\r' || command[end-1] != '\n')
		return RN2483_ERR_PARAM;

    printf("\tCMD: %s\n", command);
	
	//send command
	lora_write_channel( &RN2483_port, command, strlen(command));

	//recv response
	if ( RN2483_read(response) == RN2483_ERR_PANIC) return RN2483_ERR_PANIC;
    //process response
    return RN2483_process_resp(response);  
    }

RN2483_RC RN2483_get(char *command, char *response){
    int end = strlen(command);
	if (command[end-2] != '\r' || command[end-1] != '\n')
		return RN2483_ERR_PARAM;

    printf("\tCMD: %s\n", command);
	
	//send command
	lora_write_channel( &RN2483_port, command, strlen(command));

	//recv response (no need to process it bc the response can be a value)
	if ( RN2483_read(response) == RN2483_ERR_PANIC) return RN2483_ERR_PANIC;
    else if( strcmp(response, "")==0 ) return RN2483_ERR_PANIC;
    else return RN2483_OK;
    }

RN2483_RC RN2483_initMAC(){
	int ret = RN2483_ERR_PANIC;
    int i=0;
    char response[RN2483_MAX_BUFF];

	do{
        response[0] = '\0';
		switch(i){
			case 0:	//reset MAC
				ret = RN2483_command("mac reset " LoRaWAN_Frequency "\r\n", response);	    break;
			case 1:	//set DevAddr
				ret = RN2483_command("mac set devaddr " LoRaWAN_DevAddr "\r\n", response);	break;
			case 2:	//set DevEui
				ret = RN2483_command("mac set deveui " LoRaWAN_DevEUI "\r\n", response);    break;
			case 3:	//set AppEui
				ret = RN2483_command("mac set appeui " LoRaWAN_AppEUI "\r\n", response);	break;
            case 4:
                ret = RN2483_command("mac set nwkskey " LoRaWAN_NwkSKey "\r\n", response);  break;
			case 5:	//set AppKey
				ret = RN2483_command("mac set appskey " LoRaWAN_AppSKey "\r\n", response);  break;
			case 6:	//set DataRate
				ret = RN2483_command("mac set dr " LoRaWAN_DataRate "\r\n", response);		break;
            case 7:
                ret = RN2483_command("mac set adr " LoRaWAN_ADR "\r\n", response);          break;
            case 8:
                ret = RN2483_command("mac set linkchk " LoRaWAN_LinkCheck "\r\n", response);break;
            case 9:
                ret = RN2483_command("mac set retx " LoRaWAN_UpRetries "\r\n", response);   break;
            case 10:
                ret = RN2483_command("mac set rxdelay1 " LoRaWAN_Rx1Delay "\r\n", response);break;
            case 11:
                ret = RN2483_command("mac set rx2 " LoRaWAN_Rx2DR " " LoRaWAN_Rx2Freq "\r\n", response); break;
            case 12:
                ret = RN2483_command("mac set upctr " LoRaWAN_FrameCntUp "\r\n", response); break;
            case 13:
                ret = RN2483_command("mac set dnctr " LoRaWAN_FrameCntDwn "\r\n", response);break;
            case 14:
                ret = RN2483_command("mac set class c\r\n", response);                      break;
            case 15:
                ret = RN2483_command("mac save\r\n", response);                             break;
            default: break;
		    }
            i++;
	    } while (ret == RN2483_OK && strcmp(response, "ok\r\n") == 0);

	return ret;
    }

RN2483_RC RN2483_join(int mode){
	RN2483_RC ret = RN2483_ERR_PANIC;
    char response[RN2483_MAX_BUFF];
    char reply[RN2483_MAX_BUFF];

    // send command & recv initial response
	if (mode == RN2483_OTAA)
		ret = RN2483_command("mac join otaa\r\n", response);
	else if (mode == RN2483_ABP)
		ret = RN2483_command("mac join abp\r\n", response);
	else
		ret = RN2483_ERR_PARAM;

    if (ret != RN2483_OK) return ret;
    
    // if initial response success, wait for network response
    if (strcmp(response, "ok\r\n") == 0){
        //@todo add delay here? -testing
        //response[0] = '\0';
        if (RN2483_read(reply) != RN2483_ERR_PANIC){
            ret =  (strncmp(reply, "accepted\r\n", 8)==0)? RN2483_OK : RN2483_ERR_DENIED;
            }
        else ret = RN2483_ERR_PANIC;
        }
    // else return err code
    else if (strcmp(response, "keys_not_init\r\n") == 0)
        ret = RN2483_ERR_KIDS;
    else if (strcmp(response, "no_free_ch\r\n") == 0)
        ret = RN2483_ERR_BUSY;
    else if (strcmp(response, "silent\r\n") == 0 || strcmp(response, "busy\r\n") == 0 || strcmp(response, "mac_paused\r\n") == 0)
        ret = RN2483_ERR_STATE;
    else
        ret=RN2483_OTHER;
	    
    return ret;
    }

RN2483_RC RN2483_tx(char *buff, int confirm, char *downlink){
    int ret = RN2483_ERR_PANIC;
    char response[RN2483_MAX_BUFF];
    char reply[RN2483_MAX_BUFF];

    // figure out max payload length based on data rate
    int max_len = 0;
	if (strcmp(LoRaWAN_DataRate, "0") == 0 || strcmp(LoRaWAN_DataRate, "1") == 0 || strcmp(LoRaWAN_DataRate, "2") == 0)
		max_len = 59;
	else if (strcmp(LoRaWAN_DataRate, "3") == 0)
		max_len = 123;
	else if (strcmp(LoRaWAN_DataRate, "4") == 0 || strcmp(LoRaWAN_DataRate, "5") == 0 || strcmp(LoRaWAN_DataRate, "6") == 0 || strcmp(LoRaWAN_DataRate, "7") == 0)
		max_len = 230;
	else
		max_len = 230;

    // get payload
    char payload[strlen(buff)*2];   //1byte = 2hex
    get_hex_string((uint8_t *)buff, strlen(buff), payload); // see documentation notes on this

    // send command
    char cmd[max_len];
    if (confirm)
        sprintf(cmd, "mac tx cnf %s %s\r\n", LoRaWAN_Port, payload);
    else
        sprintf(cmd, "mac tx uncnf %s %s\r\n", LoRaWAN_Port, payload);
    
    ret = RN2483_command(cmd, response);
    if(ret != RN2483_OK)  return ret;

   
    ret=RN2483_read(reply);
    if(ret!=RN2483_OK) return ret;
    ret=RN2483_process_resp(reply);

    if (strcmp(reply, "mac_tx_ok\r\n") == 0)
        ret = RN2483_NODOWN;
    else if (strcmp(reply, "mac_err\r\n") == 0 || strcmp(reply, "invalid_data_len\r\n") == 0)
        ret = RN2483_ERR_PANIC;
    else{ //assume downlink data
        memcpy(downlink, reply, strlen(reply));
        ret = RN2483_OK;
        }
    
    return ret;
    }

//UNUSED======================================================================//

/**
 * @brief Resets serial port, and tests 
 * 
 * @return RN2483_RC 
 */
RN2483_RC RN2483_swreset(){
    char response[RN2483_MAX_BUFF];

    if(RN2483_port.fd != -1) lora_close_channel(&RN2483_port);

    lora_open_channel(&RN2483_port);

    if( (RN2483_command("sys reset\r\n", response)) != RN2483_OK){
        lora_close_channel(&RN2483_port);
        return RET_ERROR;
        }

    if (strncmp(response, "invalid_param", 13) == 0) return(RET_WARNING);

    if( (strlen(response)<7) || (strncmp(response, "RN2483 ", 7)!=0) ) return(RET_WARNING);

    return RET_OK;
}

/**
 * @brief Retrieves the firmware version of the RN2483 module and stores it in buff.
 * @param buff 
 * @return RN2483 return code
 */
RN2483_RC RN2483_firmware(char *buff){
	return RN2483_command("sys get ver\r\n", buff);
    }

/**
 * @brief Resets the RN2483 by toggling the RESET pin
 * @todo
 */
RN2483_RC RN2483_hwreset(){
    /*
        implementation depends on platform?
        
        set RN2483 RESET pin HIGH
        set RN2483 RESET pin LOW
        set RN2483 RESET pin HIGH

        RN2483_read() to check response == success
    */
   return 0;
    }

/**
 * @brief Attempts to trigger the auto-baud detection sequence
 * @param baud baud rate to set
 * @todo
 */
RN2483_RC RN2483_autobaud(int baud){
    /*
        implementation depends on platform?

        send break to RN2483
        set baud rate
        send 0x55

        check success with "sys get ver\r\n"
    */
    baud++;
    return 0;
    }

