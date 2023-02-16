#ifndef RN2483
#define RN2483

#include <stdio.h>      //fgetc, fprintf
#include <string.h>     //strlen, strcmp
#include <stdint.h>     //uint8_t
#include <stdbool.h>    //bool

#include "config.h"

#define RN2483_MAX_BUFF	512 /**< Maximum(+1) number of characters returned by RN2483 responses */

//! Values returned by RN2483_* functions
typedef enum{
	RN2483_OK=0,                    /**< Success */

    RN2483_ERR_BUSY,                /**< Error: tried to join/tx but all configured frequency channels were busy, wait and try again */
	RN2483_ERR_FR_CNT,
	RN2483_ERR_FR_CLASS,
	RN2483_ERR_LENGTH,
	RN2483_ERR_PARAM,               /**< Error: invalid parameter passed to function */
    RN2483_ERR_KIDS,                /**< Error: tried to join a LoraWAN network without the correct keys & ids (kids) configured */
    RN2483_ERR_STATE,               /**< Error: current state cannot perform action, see RN2483 documentation */
	RN2483_ERR_MC_KIDS,				
	RN2483_ERR_NO_FREE_CH,
    RN2483_ERR_NOT_JOINED,          /**< Error: tried to tx data without being joined to a LoRaWAN network */
	RN2483_ERR_PANIC,	            /**< Error: SOMETHING(???) went wrong. You found a bug! */
	RN2483_ERR_EOB,                	/**< Reached end of buffer passed to function */
    RN2483_ERR_DENIED,              /**< Join command went through, but the network denied your join request */
    RN2483_ERR_RX_PORT,

	RN2483_ACCEPTED,
	RN2483_MAC_TX_OK,
    RN2483_NODOWN,                  /**< tx succeeded and no downlink was received */
	RN2483_MAC_RX,
	RN2483_MAC_ERR,
	RN2483_OTHER
	} RN2483_RC;

//! Valid LoRaWAN join modes @see RN2483_join(int mode)
enum RN2483_JoinModes {
    RN2483_OTAA,	/**< Over-the-Air-Activation */
	RN2483_ABP		/**< Activation-By-Personalization */
};

/**
 * @brief Wraps the opening of the serial channel of the underlying lib
 */
void RN2483_init_serial();

/**
 * @brief Wraps the closing of the serial channel of the underlying lib
 */
void RN2483_shut_serial();

//! Write a command to the RN2483 and recieve it's response
/*!
    Send a command to the RN2483, if the command is valid the RN2483's response will be written 
    to response

    @return RN2483_ERR_PARAM if the command does not end in /r/n (required, see documentation),
    @return RN2483_OK command was successful and response was valid

    @see RN2483 LoRa Technology Module Command Reference User's Guide
*/

/**
 * @brief Reads from the RX buffer into response until '\n' or EOB
 * @param response buffer where response is stored
 * @return RN2483 return code (OK/PANIC)
 */
RN2483_RC RN2483_read(char *response);

/**
 * @brief Processing of rx message, checks the port and invokes FUOTA
 *        functions if the rx came in on port 200 or 201
 * @param rx 
 * @return RN2483_RC 
 */
RN2483_RC RN2483_process_rx(char *rx);

/**
 * @brief checks the content of the response against all possible responses of the RN2483
 *        and returns the relative code, if it's an rx it also gets processed
 * 
 * @param resp 
 * @return RN2483_RC 
 */
RN2483_RC RN2483_process_resp( char *resp);

/**
 * @brief Sends a command to the RN2483, porcesses and sets the response
 * @param command
 * @param response
 * @return RN2483 return code
 */
RN2483_RC RN2483_command(char *command, char *response);

/**
 * @brief Sends a get command and stores it in the response buffer
 * @param command 
 * @param response 
 * @return RN2483_RC 
 */
RN2483_RC RN2483_get(char *command, char *response);


//! Resets the RN2483 by toggling the RESET pin
/*!
	Toogles the reset pin (from HIGH -> LOW -> HIGH).

    The RN2483 module transmits it's firmware version upon being reset, so if the version is successful.

    @return RN2483_OK if version was succesfully retrieved after toggling the RESET pin
    @return RN2483_ERR_PANIC if version was not retrieved after toggling the RESET pin
*/
extern RN2483_RC RN2483_reset();
//! Attempts to trigger the auto-baud detection sequence.
/*!
    Triggers the autobaud detction sequence by sending a break, setting the baudrate and sending 0x55.

    The new baudrate is tested by attempting to retrieve the firmware version.

    @return RN2483_OK if RN2483_firmware() succeeded after autobaud.
    @return RN2483_ERR_PANIC if RN2483_firmware() failed after autobaud.
*/

/**
 * @brief Initialises all the RN2483 MAC settings required to run LoRa commands (join, tx, etc).
 * @return RN2483 return code
 */
extern RN2483_RC RN2483_initMAC();

/**
 * @brief Attempts to join a LoRa network using the specified mode.
 * @param mode OTAA or ABP
 * @see RN2483_JoinModes
 * @return RN2483 return code
 */
extern RN2483_RC RN2483_join(int mode);

/**
 * @brief Sends a confirmed/unconfirmed frame with an application payload of buff.
 * @param buff contains the msg to transmit
 * @param confirm true: confirmed, false: unconfirmed
 * @param downlink stores the server's response
 * @return RN2483 return code
 */
extern RN2483_RC RN2483_tx(char *buff, int confirm, char *downlink);

//UNUSED========================================================================

extern RN2483_RC RN2483_swreset();

extern RN2483_RC RN2483_autobaud(int baud);

extern RN2483_RC RN2483_firmware(char *buff);

#endif // RN2483

