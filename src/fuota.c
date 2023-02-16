#include <stdint.h>
#include <stddef.h>
#include <stdlib.h>
#include <stdbool.h>
#include <string.h>
#include "log.h"
#include "tiny-aes.h"
#include "fuota.h"

#define CONF_SLOT0_FW_ADDRESS 0    // Place in flash where the final binary needs to be placed
#define CONF_MAX_REDUNDANCY 20      // Max. number of redundancy packets we'll receive

#define MCCONTROL_PORT   200
#define FRAGSESSION_PORT 201
#define CLOCKSYNC_PORT   202

#define PACKAGE_VERSION_REQ 0x0
#define PACKAGE_VERSION_ANS 0x0

#define MC_GROUP_STATUS_REQ 0x01
#define MC_GROUP_STATUS_ANS 0x01
#define MC_GROUP_SETUP_REQ  0x02
#define MC_GROUP_SETUP_ANS  0x02
#define MC_GROUP_DELETE_REQ 0x03
#define MC_GROUP_DELETE_ANS 0x03
#define MC_CLASSC_SESSION_REQ  0x04
#define MC_CLASSC_SESSION_ANS  0x04

#define MC_GROUP_SETUP_REQ_LENGTH 29
#define MC_GROUP_SETUP_ANS_LENGTH 2
#define MC_GROUP_DELETE_REQ_LENGTH 1
#define MC_GROUP_DELETE_ANS_LENGTH 2
#define MC_GROUP_STATUS_REQ_LENGTH 1
#define MC_CLASSC_SESSION_REQ_LENGTH 10
#define MC_CLASSC_SESSION_ANS_LENGTH 5

#define FRAG_SESSION_STATUS_REQ 0x01
#define FRAG_SESSION_STATUS_ANS 0x01
#define FRAG_SESSION_SETUP_REQ  0x02
#define FRAG_SESSION_SETUP_ANS  0x02
#define FRAG_SESSION_DELETE_REQ 0x03
#define FRAG_SESSION_DELETE_ANS 0x03
#define DATA_BLOCK_AUTH_REQ  0x05
#define DATA_BLOCK_AUTH_ANS  0x05
#define DATA_FRAGMENT  0x08

#define PACKAGE_VERSION_REQ_LENGTH 0
#define PACKAGE_VERSION_ANS_LENGTH 3
#define FRAG_SESSION_SETUP_REQ_LENGTH 10
#define FRAG_SESSION_SETUP_ANS_LENGTH 2
#define FRAG_SESSION_DELETE_REQ_LENGTH 1
#define FRAG_SESSION_DELETE_ANS_LENGTH 2
#define FRAG_SESSION_STATUS_REQ_LENGTH 1
#define FRAG_SESSION_STATUS_ANS_LENGTH 5

#define CLOCK_APP_TIME_REQ 0x1
#define CLOCK_APP_TIME_ANS 0x1
#define CLOCK_APP_TIME_PERIODICITY_REQ 0x2
#define CLOCK_APP_TIME_PERIODICITY_ANS 0x2
#define CLOCK_FORCE_RESYNC_REQ 0x3

#define CLOCK_APP_TIME_REQ_LENGTH 6
#define CLOCK_APP_TIME_ANS_LENGTH 5
#define CLOCK_APP_TIME_PERIODICITY_REQ_LENGTH 1
#define CLOCK_APP_TIME_PERIODICITY_ANS_LENGTH 6
#define CLOCK_FORCE_RESYNC_REQ_LENGTH 1

#define FRAGMENTATION_ON_GOING 0xFFFFFFFF
#define FRAGMENTATION_NOT_STARTED 0xFFFFFFFE
#define FRAGMENTATION_FINISH 0x0

#define NB_MC_GROUPS 4
#define NB_FRAG_GROUPS 4

//===================CLIENT===================================================//

uint8_t genAppKey[16];

void initClient(const uint8_t genAppKey_[16]){
    memcpy(genAppKey, genAppKey_, 16);
}

typedef struct {
    /**
     * Whether the group is active
     */
    bool active;

    /**
     * McAddr is the multicast group network address.
     * McAddr is negotiated off-band by the application server with the network server.
     */
    uint32_t mcAddr;

    /**
     * McKey_encrypted is the encrypted multicast group key from which McAppSKey and McNetSKey will be derived.
     * The McKey_encrypted key can be decrypted using the following operation to give the multicast group’s McKey.
     * McKey = aes128_encrypt(McKEKey, McKey_encrypted)
     */
    uint8_t mcKey_Encrypted[16];

    /**
     * Network session key (derived from mcKey_Encrypted)
     */
    uint8_t nwkSKey[16];

    /**
     * Application session key (derived from mcKey_Encrypted)
     */
    uint8_t appSKey[16];

    /**
     * The minMcFCount field is the next frame counter value of the multicast downlink to be sent by the server
     * for this group. This information is required in case an end-device is added to a group that already exists.
     * The end-device MUST reject any downlink multicast frame using this group multicast address if the frame
     * counter is < minMcFCount.
     */
    uint32_t minFcFCount;

    /**
     * maxMcFCount specifies the life time of this multicast group expressed as a maximum number of frames.
     * The end-device will only accept a multicast downlink frame if the 32bits frame counter value
     * minMcFCount ≤ McFCount < maxMcFCount.
     */
    uint32_t maxFcFCount;

    } McGroup;

McGroup mcGroups[NB_MC_GROUPS];

typedef struct {
    /**
     * Whether the session is active
     */
    bool active;

    /**
     * McGroupBitMask specifies which multicast group addresses are allowed as input to this
     * defragmentation session. Bit number X indicates if multicast group with McGroupID=X
     * is allowed to feed fragments to the defragmentation session.
     * Unicast can always be used as a source for the defragmentation session and cannot be disabled.
     * For example, 4’b0000 means that only Unicast can be used with this fragmentation session.
     * 4’b0001 means the defragmentation layer MAY receive packets from the multicast group with
     * McGroupID=0 and the unicast address. 4’b1111 means that any of the 4 multicast groups or unicast
     * may be used. If the end-device does not support multicast, this field SHALL be ignored.
     */
    uint8_t mcGroupBitMask;

    /**
     * specifies the total number of fragments of the data block to be transported during the
     * coming multicast fragmentation session.
     */
    uint16_t nbFrag;

    /**
     * is the size in byte of each fragment.
     */
    uint8_t fragSize;

    /**
     * encodes the type of fragmentation algorithm used.
     * This parameter is simply passed to the fragmentation algorithm.
     */
    uint8_t fragAlgo;

    /**
     * encodes the amplitude of the random delay that end-devices have to wait
     * between the reception of a downlink command sent using multicast and the
     * transmission of their answer.
     * This parameter is a function of the group size and the geographic spread
     * and is used to avoid too many collisions on the uplink due to many end-devices
     * simultaneously answering the same command.
     * The actual delay SHALL be rand().2^(BlockAckDelay+4) seconds where rand() is a
     * random number in the [0:1] interval.
     */
    uint8_t blockAckDelay;

    /**
     * The descriptor field is a freely allocated 4 bytes field describing the file that
     * is going to be transported through the fragmentation session.
     * For example, this field MAY be used by the end-device to decide where to store the
     * defragmented file, how to treat it once received, etc...
     * If the file transported is a FUOTA binary image, this field might encode the version
     * of the firmware transported to allow end-device side compatibility verifications.
     * The encoding of this field is application specific.
     */
    uint32_t descriptor;

    /**
     * The maximum number of redundancy packets that can be expected
     * (not part of the incoming protocol, but will derive from a macro)
     */
    uint16_t redundancy;

    /**
     * The binary data block size may not be a multiple of FragSize.
     * Therefore, some padding bytes MUST be added to fill the last fragment.
     * This field encodes the number of padding byte used. Once the data block has been reconstructed
     * by the receiver, it SHALL remove the last "padding" bytes in order to get the original binary file.
     */
    uint8_t padding;

    /**
     * The blob will be stored here, space will be allocated during the setup req. 
     */
    uint8_t *blob;

    bool *recvdFrags;

    int nbMissing;
    int nbReceived;

    bool outOfMemory;

    } FragSession;

FragSession fragSession[NB_FRAG_GROUPS];

//===================PRINT====================================================//

void print_uint8_t(uint8_t n) {
    for (int i = 7; i >= 0; i--)
        printf("%d", (n & (1<<i)) >> i);
    putchar(' ');
}

void print_byte_array(uint8_t *buffer, int length){
    for(int i=0; i<length; i++)
        print_uint8_t(buffer[i]);
    putchar('\n');
}

void print_char_array(uint8_t *buffer, int length){
    for(int i=0; i<length; i++)
        printf("%c", buffer[i]);
    putchar('\n');
}

char* get_hex_string(uint8_t *buff, int buff_len){  // Converts buff into a string representation of it hexadecimal representation

    int j;  //index of buff
    int i;  //index of string
    uint8_t nibble;
    const char hex_map[16] = {'0', '1', '2', '3', '4', '5', '6', '7', '8', '9', 'A', 'B', 'C', 'D', 'E', 'F'};

    char *ret;
    if( (ret=(char *)calloc(buff_len*2, sizeof(char)))==NULL ) return NULL;

    for (i = 0, j = 0; i < buff_len*2; i++)
    {
        nibble = 20;    // out of bounds of hex_map

        if (i % 2 == 0)
            nibble = (buff[j] >> 4) & 0x0F;
        else
        {
            nibble = buff[j] & 0x0F;
            j++;
        }

        ret[i] = hex_map[nibble];
    }

    return ret;
}

//===================FRAGMENTATION============================================//

void sendFragSessionSetupAns(uint8_t fId, FRAG_FLAGS error){
    uint8_t response = fId;
    response = response << 6;

    switch (error) {
        case FLAG_WrongDescriptor: response |= 0b1000; break;
        case FLAG_IndexNotSupported: response |= 0b0100; break;
        case FLAG_NotEnoughMemory: response |= 0b0010; break;
        case FLAG_EncodingUnsupported: response |= 0b0001; break;
        case FLAG_None: response |= 0b0000; break;
    }

    

    uint8_t buffer[FRAG_SESSION_SETUP_ANS_LENGTH];
    buffer[0] = FRAG_SESSION_SETUP_ANS;
    buffer[1] = response;
	
    print_byte_array(buffer, FRAG_SESSION_SETUP_ANS_LENGTH);
    //TODO
    //send(FRAGSESSION_PORT, buffer, 2, true);
}

FUOTA_RC handleFragSessionSetupReq(uint8_t *buffer, size_t length){
    if (length != FRAG_SESSION_SETUP_REQ_LENGTH) return FUOTA_INVALID_PACKET_LENGTH;

    uint8_t fId = (buffer[0] >> 4) & 0b11;

    /*  USING 4 FRAG SESSION LIMIT which is the max allowable, 2 bits can never express something >4
        no future checks will be made
    if (fId > NB_FRAG_GROUPS - 1) {
        log_debug("FLAG_IndexNotSupported");
        sendFragSessionSetupAns(fId, FLAG_IndexNotSupported);
        return FUOTA_OK;
    } */

    if (fragSession[fId].active==true) fragSession[fId].active=false;

    //FLAG_EncodingUnsupported when should it be sent?

    fragSession[fId].mcGroupBitMask = buffer[0] & 0b1111;
    fragSession[fId].nbFrag = (buffer[1] << 8) + buffer[2];
    fragSession[fId].fragSize = buffer[3];
    fragSession[fId].fragAlgo = (buffer[4] >> 3) & 0b111;
    fragSession[fId].blockAckDelay = buffer[4] & 0b111;
    fragSession[fId].padding = buffer[5];
    fragSession[fId].descriptor = (buffer[6] << 24) + (buffer[7] << 16) + (buffer[8] << 8) + buffer[9];

    log_debug("FragmentationSessionSetupReq");
    log_debug("\tFragSession:      %u", fId);
    log_debug("\tMcGroupBitMask:   %u", fragSession[fId].mcGroupBitMask);
    log_debug("\tNbFrag:           %u", fragSession[fId].nbFrag);
    log_debug("\tFragSize:         %u", fragSession[fId].fragSize);
    log_debug("\tFragAlgo:         %u", fragSession[fId].fragAlgo);
    log_debug("\tBlockAckDelay:    %u", fragSession[fId].blockAckDelay);
    log_debug("\tPadding:          %u", fragSession[fId].padding);
    log_debug("\tDescriptor:       %lu",fragSession[fId].descriptor);

    fragSession[fId].active = true;
    fragSession[fId].outOfMemory=false;


    //Allocating space for this session's expected blob
    if( (fragSession[fId].blob=calloc(fragSession[fId].nbFrag, fragSession[fId].fragSize)) == NULL){
        fragSession[fId].outOfMemory=true;
        sendFragSessionSetupAns(fId, FLAG_NotEnoughMemory);
        return FUOTA_OUT_OF_MEMORY;
    }

    //Allocating space for this session's fragments checklist
    if( (fragSession[fId].recvdFrags=calloc(fragSession[fId].nbFrag, sizeof(bool))) == NULL){
        fragSession[fId].outOfMemory=true;
        sendFragSessionSetupAns(fId, FLAG_NotEnoughMemory);
        return FUOTA_OUT_OF_MEMORY;
    }
    for(int i=0; i<fragSession[fId].nbFrag; i++) fragSession[fId].recvdFrags[i]=false;

    //Initializing missing fragments number (at setup all frags are missing)
    fragSession[fId].nbMissing=fragSession[fId].nbFrag;
    fragSession[fId].nbReceived=0;

    sendFragSessionSetupAns(fId, FLAG_None);
    return FUOTA_OK;
}

FRAG_RC processFrame(uint8_t fId, uint16_t fragN, uint8_t *buffer, size_t length){
    if(length!=fragSession[fId].fragSize) return FRAG_SIZE_INCORRECT;
    if( fragN>(fragSession[fId].nbFrag-1) ) return FRAG_OUT_OF_BOUND_FRAME;


    memcpy( fragSession[fId].blob+(fragN*length), buffer, length);
    if( memcmp(fragSession[fId].blob+(fragN*length), buffer, length)!=0)  return FRAG_FLASH_WRITE_ERROR;
    //TODO: INTEGRITY CHECK?

    fragSession[fId].recvdFrags[fragN]=true;
    fragSession[fId].nbMissing--;
    fragSession[fId].nbReceived++;

    if( fragN==fragSession[fId].nbFrag ){  

        bool complete=true;

        for( int i=0; i<fragSession[fId].nbFrag; i++)
            if(fragSession[fId].recvdFrags[i]==false) complete=false;

        if(complete) return FRAG_COMPLETE;
        else {} //could ask for missing fragments
    }

    return FRAG_OK;    
}

FUOTA_RC handleDataFragment( /*uint32_t devAddr,*/ uint8_t *buffer, size_t length){
    // always need at least 2 bytes for the indexAndN
    if (length<2) return FUOTA_INVALID_PACKET_LENGTH;

    uint8_t fId=buffer[0] >> 6;
    uint16_t fragN=((buffer[0] << 8) + buffer[1] ) & 16383; // 16383 = 2^14-1 = 00111111 11111111

    log_debug("DataFragment");
    log_debug("\tFragNumber:       %u", fragN);
    log_debug("\tFragSession:      %u", fId);

    /*TODO: devAddr should be used to check if it's a member of a multicast group*/

    if(fragSession[fId].active==false) return FUOTA_FRAG_SESSION_NOT_ACTIVE;

    int rc=processFrame(fId, fragN, buffer+2, length-2 );
    printf("Frame RC: %d\n", rc);
    if(rc==FRAG_OK)   return FUOTA_OK;
    if(rc==FRAG_COMPLETE) return FUOTA_OK;
            /*TODO: integrity check, revert back to normal operation*/
    return FUOTA_PROCESS_FRAME_FAILED;       
}

FUOTA_RC sendFragSessionStatusAns(uint8_t fId){

    uint16_t fId_nbReceived=fragSession[fId].nbReceived & 16383;
    fId_nbReceived += fId<<14;

    uint8_t response[FRAG_SESSION_STATUS_ANS_LENGTH] = {
            FRAG_SESSION_STATUS_ANS,
            (uint8_t) fId_nbReceived >> 8 & 0xff,
            (uint8_t) fId_nbReceived & 0xff,
            (uint8_t) fragSession[fId].nbMissing,
            (uint8_t) fragSession[fId].outOfMemory
        };

    print_byte_array( response, FRAG_SESSION_STATUS_ANS_LENGTH);
    //TODO: SEND RESPONSE
    return FUOTA_OK;
}

FUOTA_RC handleFragStatusReq(uint8_t *buffer, size_t length){
    if (length != FRAG_SESSION_STATUS_REQ_LENGTH) return FUOTA_INVALID_PACKET_LENGTH;

    uint8_t fId=buffer[0] & 0b110;
    // The “participants” bit signals if all the fragmentation receivers should answer or only the ones still missing fragments.
        // 0 = Only the receivers still missing fragments MUST answer the request
        // 1 = All receivers MUST answer, even those who already successfully reconstructed the data block
    uint16_t participants=buffer[0] & 0b1;

    log_debug("FragmentationStatusReq");
    log_debug("\tFragSession:      %u", fId);

    if(fragSession[fId].active==false) return FUOTA_FRAG_SESSION_NOT_ACTIVE;

    if(fragSession[fId].nbMissing==0){
        //receivers who completed shouldnt answer
        if(participants==0) return FUOTA_OK;
    }
    //the response is sent by: receivers who didnt complete
    //                         receivers who completed but are asked to answer anyways
    return sendFragSessionStatusAns(fId);
}

FUOTA_RC handleFragSessionDeleteReq(uint8_t *buffer, size_t length){
    if(length!=FRAG_SESSION_DELETE_REQ_LENGTH) return FUOTA_INVALID_PACKET_LENGTH;

    uint8_t fId = buffer[0] & 0b11;
    log_debug("SessionDeleteReq");
    log_debug("\tFragSession:      %u", fId);

    uint8_t response[FRAG_SESSION_DELETE_ANS_LENGTH]={FRAG_SESSION_DELETE_ANS, fId};

    if(fragSession[fId].active==false) response[1]+=0b100;
    else fragSession[fId].active=false;

    print_byte_array(response, FRAG_SESSION_DELETE_ANS_LENGTH);
    //TODO: SEND DELETE ANS
    return FUOTA_OK;
}

/*//  FRAGMENTATION TEST MAIN
int main(){
    uint8_t setup[]={0x00,0x00,0x02,0x0c,0x00,0x00,0x00,0x00,0x00,0x01};    //1 fragment, 12B, rest is default (descriptor: 00 00 00 01)
    printf("Setup RC: %d\n", handleFragSessionSetupReq(setup, 10));

    uint8_t msg[]={0x00,0x00,0x48,0x65,0x6c,0x6c,0x6f,0x20,0x77,0x6f,0x72,0x6c,0x64,0x21};  //Hello world!
    printf("Frag RC:  %d\n", handleDataFragment(msg, 14) );

    uint8_t req[]={0x00};   //group 0, only non complete receivers must respond
    printf("Status RC:%d\n", handleFragStatusReq(req, 1));

    uint8_t msg2[]={0x00,0x01,0x48,0x65,0x6c,0x6c,0x6f,0x20,0x77,0x6f,0x72,0x6c,0x64,0x21};  //Hello world!
    printf("Frag RC:  %d\n", handleDataFragment(msg2, 14) );

    printf("Status RC:%d\n", handleFragStatusReq(req, 1)); //same as before, should be silent bc the frag session should be complete

    uint8_t del[]={0x00};   //group 0
    handleFragSessionDeleteReq(del, 1);

    print_char_array(fragSession[0].blob, 24);     //Prints the saved fw blob
    return 0;
}
//*/

//===================MULTICAST================================================//

FUOTA_RC sendMcGroupSetupAns(bool idError, uint8_t mcId){
    uint8_t response=mcId;
    response+=idError ? 0b100 : 0;
    uint8_t buffer[MC_GROUP_SETUP_ANS_LENGTH]={MC_GROUP_SETUP_ANS, response};

	printf("McGroupSetupAns: ");
    print_byte_array(buffer, MC_GROUP_SETUP_ANS_LENGTH);
    //TODO: SEND MC SETUP ANS
	return FUOTA_OK;
}

FUOTA_RC handleMcGroupSetupReq(uint8_t *buffer, size_t length){
    if(length!=MC_GROUP_SETUP_REQ_LENGTH) return FUOTA_INVALID_PACKET_LENGTH;

    uint8_t mcId=buffer[0] & 0b11;
    //Check mcId is in bound
    log_debug("McGroupSetupReq");
    log_debug("\tMcGroup:      %u", mcId);

    mcGroups[mcId].mcAddr = (buffer[1] << 24) + (buffer[2] << 16) + (buffer[3] << 8) + buffer[4];
    memcpy(mcGroups[mcId].mcKey_Encrypted, buffer + 5, 16);
    mcGroups[mcId].minFcFCount = (buffer[21] << 24) + (buffer[22] << 16) + (buffer[23] << 8) + buffer[24];
    mcGroups[mcId].maxFcFCount = (buffer[25] << 24) + (buffer[26] << 16) + (buffer[27] << 8) + buffer[28];
    
    // Derived from the GenAppKey. This differs between LoRaWAN 1.0 and LoRaWAN 1.1,
    // but there's no knowledge in this library which version is used
    // McRootKey = aes128_encrypt(GenAppKey, 0x00 | pad16)
    const uint8_t mc_root_key_input[16] = { 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0 };
    uint8_t mc_root_key_output[16] = {};
    AES_ECB_encrypt(mc_root_key_input, genAppKey, mc_root_key_output, 16);

    // McKEKey = aes128_encrypt(McRootKey, 0x00 | pad16)
    const uint8_t mc_e_key_input[16] = { 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0 };
    uint8_t mc_e_key_output[16];
    AES_ECB_encrypt(mc_e_key_input, mc_root_key_output, mc_e_key_output, 16);

    // McKey = aes128_encrypt(McKEKey, McKey_encrypted)
    uint8_t mc_key[16];
    AES_ECB_encrypt(mcGroups[mcId].mcKey_Encrypted, mc_e_key_output, mc_key, 16);

    // The McAppSKey and the McNetSKey are then derived from the group’s McKey as follow:
    // McAppSKey = aes128_encrypt(McKey, 0x01 | McAddr | pad16)
    // McNetSKey = aes128_encrypt(McKey, 0x02 | McAddr | pad16)
    const uint8_t app_input[16] = { 0x01, buffer[1], buffer[2], buffer[3], buffer[4], 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0 };
    const uint8_t nwk_input[16] = { 0x02, buffer[1], buffer[2], buffer[3], buffer[4], 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0 };
    AES_ECB_encrypt(nwk_input, mc_key, mcGroups[mcId].nwkSKey, 16);
    AES_ECB_encrypt(app_input, mc_key, mcGroups[mcId].appSKey, 16);

    mcGroups[mcId].active=true;

    log_debug("\tmcAddr:         0x%08x", mcGroups[mcId].mcAddr);
    log_debug("\tNwkSKey:");
    printf("\t         ");
    for (size_t id = 0; id < 16; id++) {
        printf("%02x ", mcGroups[mcId].nwkSKey[id]);
    }
    printf("\n");
    log_debug("\tAppSKey:");
    printf("\t         ");
    for (size_t id = 0; id < 16; id++) {
        printf("%02x ", mcGroups[mcId].appSKey[id]);
    }
    printf("\n");
    log_debug("\tminFcFCount:    %lu", mcGroups[mcId].minFcFCount);
    log_debug("\tmaxFcFCount:    %lu", mcGroups[mcId].maxFcFCount);

    return sendMcGroupSetupAns(false, mcId);
}

FUOTA_RC handleMcGroupStatusReq(uint8_t *buffer, size_t length){
    if(length!=MC_GROUP_STATUS_REQ_LENGTH) return FUOTA_INVALID_PACKET_LENGTH;

    // max length of the response is 1 byte status + 5 bytes per group...
    uint8_t response[2 + (NB_MC_GROUPS * 5)];

    uint8_t reqGroupMask = buffer[0] & 0b1111;

    uint8_t ansGroupMask = 0;
	uint8_t totalGroups = 0;

	// iterate over the response
    uint8_t *resp_ptr = response + 2;

	for(size_t id=0; id<NB_MC_GROUPS; id++){
		bool requested = (reqGroupMask >> id) & 0b1;

		if (requested && mcGroups[id].active) {
			totalGroups++;
			ansGroupMask += (1 << id);

			resp_ptr[0] = id;
			resp_ptr[1] = mcGroups[id].mcAddr & 0xff;
			resp_ptr[2] = mcGroups[id].mcAddr >> 8 & 0xff;
			resp_ptr[3] = mcGroups[id].mcAddr >> 16 & 0xff;
			resp_ptr[4] = mcGroups[id].mcAddr >> 24 & 0xff;

			resp_ptr += 5;
		}
	}

	 // add the total groups to the mask
	ansGroupMask += (totalGroups << 4);

	response[0] = MC_GROUP_STATUS_ANS;
	response[1] = ansGroupMask;

	printf("McGroupStatusAns: ");
	print_byte_array(response, 2 + (NB_MC_GROUPS * 5));
    //TODO: SEND MC SETUP ANS
	return FUOTA_OK;
}

FUOTA_RC handleMcGroupDelete(uint8_t *buffer, size_t length){
    if(length!=MC_GROUP_DELETE_REQ_LENGTH) return FUOTA_INVALID_PACKET_LENGTH;

	uint8_t mcId=buffer[0] & 0b11;
	log_debug("McGroupdeleteReq");
    log_debug("\tMcGroup:      %u", mcId);
	
	uint8_t response[MC_GROUP_DELETE_ANS_LENGTH] = { MC_GROUP_DELETE_ANS, mcId };

	if (mcId > NB_MC_GROUPS-1 || mcGroups[mcId].active==false)
		response[1]+=0b100;		//set error flag

	mcGroups[mcId].active=false;

	 // clear potentially sensitive details
	mcGroups[mcId].mcAddr = 0x0;
	memset(mcGroups[mcId].mcKey_Encrypted, 0, 16);
	memset(mcGroups[mcId].nwkSKey, 0, 16);
	memset(mcGroups[mcId].appSKey, 0, 16);
	mcGroups[mcId].minFcFCount = 0;
	mcGroups[mcId].maxFcFCount = 0;
	
	printf("McGroupDeleteAns: ");
	print_byte_array(response, MC_GROUP_DELETE_ANS_LENGTH);
    //TODO: SEND MC DELETE ANS

	return FUOTA_OK;
}

/*//  MULTICAST TEST MAIN
int main(){
	uint8_t gkey[16]={0xf2,0x55,0xb7,0x74,0x8a,0x00,0xff,0x7c,0x22,0x34,0x4c,0x34,0x02,0xf6,0x35,0x6f};	//genAppKey
	initClient(gkey);

	uint8_t req[MC_GROUP_SETUP_REQ_LENGTH]={
		0x03, //mcId
		0xd2,0xff,0x61,0x3d,	//mcAddr
		0x8e,0x14,0x62,0x56,0x19,0x45,0xde,0xe2,0x16,0x8b,0x52,0xe1,0x28,0xef,0x7f,0x28,	//mcKey_Encrypted
		0x00,0x00,0x00,0x00,	//minFcCount
		0xff,0xff,0xff,0xff		//maxFcCount	};
	handleMcGroupSetupReq(req, MC_GROUP_SETUP_REQ_LENGTH);

	uint8_t status[1]={0x0b};	//ask info for channels 0-1-3
	handleMcGroupStatusReq(status,1);

	uint8_t del[1]={0x03};		//quit mc group 3
	handleMcGroupDelete(del,1);		//should work fine

	handleMcGroupDelete(del,1);		//should contain error

}
//*/

//============================================================================//
//#if 0
/**
 * Handle packets that came in on the fragmentation port (e.g. 201)
 *
 * @param devAddr The device address that received this message (or 0x0 in unicast)
 * @param buffer Data buffer
 * @param length Length of the data buffer
 */
FUOTA_RC handleFragmentationCommand(/*uint32_t devAddr,*/ uint8_t *buffer, size_t length) {
    if (length == 0) return FUOTA_INVALID_PACKET_LENGTH;

    // @todo: are we going to accept fragSession commands over multicast? That should be unsafe...

    switch (buffer[0]) {
        case FRAG_SESSION_SETUP_REQ:
            return handleFragSessionSetupReq(buffer + 1, length - 1);

        case DATA_FRAGMENT:
            return handleDataFragment(/*devAddr,*/ buffer + 1, length - 1);

        case FRAG_SESSION_DELETE_REQ:
            return handleFragSessionDeleteReq(buffer + 1, length - 1);

        case FRAG_SESSION_STATUS_REQ:
            return handleFragStatusReq(buffer + 1, length - 1);

        //case PACKAGE_VERSION_REQ:
        //    return handlePackageVersionReq(buffer + 1, length - 1);

        default:
            return FUOTA_UNKNOWN_COMMAND;
    }
}

/**
 * Handle packets that came in on the multicast control port (e.g. 200)
 */
FUOTA_RC handleMulticastControlCommand(uint8_t *buffer, size_t length) {
    if (length == 0) return FUOTA_INVALID_PACKET_LENGTH;

    switch (buffer[0]) {
        case MC_GROUP_SETUP_REQ:
            return handleMcGroupSetupReq(buffer + 1, length - 1);

        case MC_GROUP_DELETE_REQ:
            return handleMcGroupDelete(buffer + 1, length - 1);

        case MC_GROUP_STATUS_REQ:
            return handleMcGroupStatusReq(buffer + 1, length - 1);

        //case MC_CLASSC_SESSION_REQ:
        //    return handleMulticastClassCSessionReq(buffer + 1, length - 1);

        //case PACKAGE_VERSION_REQ:
        //    return handleMulticastPackageVersionReq(buffer + 1, length - 1);

        default:
            return FUOTA_UNKNOWN_COMMAND;
    }
}

//#endif

