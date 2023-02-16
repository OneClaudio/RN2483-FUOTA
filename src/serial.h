#if !defined(SERIAL_H)
#define	SERIAL_H	  1

#include <termios.h>
#include <unistd.h>
#include <stdint.h>

/*!< Serial line parity */
typedef	enum	_SERIAL_PORT_PARITY{
  NONE=0, /*!< No parity */
  ODD,		/*!< Odd parity */
  EVEN		/*!< Even parity */
  }	SERIAL_PORT_PARITY;

/*!< Serial line */
typedef struct	_SERIAL_PORT{
  char     device[32];/*!< Serial port device */
  speed_t	 speed;		  /*!< Serial line baud rate */
  uint16_t num_bits;	/*!< Serial line number of bits */
  uint16_t stop_bits;	/*!< Serial line number of stop bits */
  SERIAL_PORT_PARITY	parity;		/*!< Serial line parity */
  int      fd;		    /*!< Serial line file descriptor when open */
  }	SERIAL_PORT;

#endif
