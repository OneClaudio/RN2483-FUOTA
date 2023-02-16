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

/**
 * @brief Open serial channel and set its terminal attributes
 * @param port Serial port associated to channel
 */
void lora_open_channel(SERIAL_PORT	*port){
  struct termios  	tty_attributes;

  if ((port->fd = open(port->device, O_RDWR|O_NOCTTY)) < 0){
    log_warn("Cannot open serial channel %s", port->device);
    port->fd = -1;
    return;
    }

  /* Serial device is now open */
  log_info("Serial channel %s is now open", port->device);

  /* Get terminal attributes */
  if (tcgetattr(port->fd, &tty_attributes) != 0){
    log_warn("Error while getting terminal attributes");
    memset(&tty_attributes, 0, sizeof(tty_attributes));
    }

  switch (port->parity){
    case EVEN:
      tty_attributes.c_cflag |= PARENB;
      break;
    case ODD:
      tty_attributes.c_cflag |= PARENB;
      tty_attributes.c_cflag |= PARODD;
      break;
    case NONE:
    default:
      tty_attributes.c_cflag &= (tcflag_t)~PARENB;
      break;
    }

  switch (port->stop_bits){
    case 2:
      tty_attributes.c_cflag |= CSTOPB;
      break;
    case 1:
    default:
      tty_attributes.c_cflag &= (tcflag_t)~CSTOPB;
      break;
    }

  tty_attributes.c_cflag &= (tcflag_t)~CSIZE;		/* Character size mask */
  switch (port->num_bits){
    case 5 :
      tty_attributes.c_cflag |= CS5;
      break;
    case 6 :
      tty_attributes.c_cflag |= CS6;
      break;
    case 7 :
      tty_attributes.c_cflag |= CS7;
      break;
    case 8 :
    default :
      tty_attributes.c_cflag |= CS8;
      break;
    }
  tty_attributes.c_cflag &= (tcflag_t)~HUPCL;		/* No hangup */
  tty_attributes.c_cflag &= (tcflag_t)~CRTSCTS;		/* Disable hardware flow control */
  tty_attributes.c_cflag |= CLOCAL;  			/* Ignore modem control lines */
  tty_attributes.c_cflag |= CREAD;  			/* Enable receiver */

  tty_attributes.c_iflag &= (tcflag_t)~IXON;		/* Disable XON/XOFF flow control on input */
  tty_attributes.c_iflag &= (tcflag_t)~IXOFF;		/* Disable XON/XOFF flow control on input */
  tty_attributes.c_iflag &= (tcflag_t)~ICRNL;		/* Don't translate CR to NL */
  tty_attributes.c_iflag |= IGNBRK | IGNPAR;		/* Ignore BREAK condition on input & framing errors & parity errors */

  tty_attributes.c_oflag = 0;				/* Set serial device output mode (non-canonical, no echo,...) */
  tty_attributes.c_oflag &= (tcflag_t)~OPOST;		/* Enable output processing */

  tty_attributes.c_lflag = 0;

  tty_attributes.c_cc[VTIME] = 1;			/* Timeout in 1/10 sec intervals */
  tty_attributes.c_cc[VMIN] = 0;			/* Block until char or timeout */

  if (cfsetospeed(&tty_attributes, port->speed) != 0)
    log_warn(LOG_FMT_SYSERROR, "cfsetospeed");
  if (cfsetispeed(&tty_attributes, port->speed) != 0)
    log_warn(LOG_FMT_SYSERROR, "cfsetispeed");

  /* Flush unread data first */
  if (tcflush(port->fd, TCIFLUSH) != 0)
    log_warn(LOG_FMT_SYSERROR, "tcflush");

  /* Set terminal attributes */
  if (tcsetattr(port->fd, TCSANOW, &tty_attributes) != 0)
    log_warn(LOG_FMT_SYSERROR, "tcsetattr");

  /* Flush serial device */
  if (tcflush(port->fd, TCIOFLUSH) != 0)
    log_warn(LOG_FMT_SYSERROR, "tcflush");

  #ifdef DEBUG
  char *br;
  switch (port->speed){
    case B50 : br = "50"; break;
    case B75 : br = "75"; break;
    case B110 : br = "110"; break;
    case B134 : br = "134"; break;
    case B150 : br = "150"; break;
    case B200 : br = "200"; break;
    case B300 : br = "300"; break;
    case B600 : br = "600"; break;
    case B1200 : br = "1200"; break;
    case B1800 : br = "1800"; break;
    case B2400 : br = "2400"; break;
    case B4800 : br = "4800"; break;
    case B9600 : br = "9600"; break;
    case B19200 : br = "19200"; break;
    case B38400 : br = "38400"; break;
    case B57600 : br = "57600"; break;
    case B115200 : br = "115200"; break;
    case B230400 : br = "230400"; break;
    default : br = "unknown"; break;
    }
  printf("port settings: %s speed: %s nbits: %d stopbits: %d parity: %d fd: %d\n", port->device, br, port->num_bits, port->stop_bits, port->parity, port->fd);
  #endif
  }

/**
 * @brief Close serial channel
 * @param port Serial port associated to channel
 */
void
lora_close_channel(SERIAL_PORT *port){
  if (port->fd != -1){
    close(port->fd);
    port->fd = -1;
    log_info("Serial channel %s is now closed", port->device);
    }
  }

int lora_read_channel(SERIAL_PORT		*port, char	*buff, size_t	*len, struct timespec	*to){
  ssize_t 		n;
  struct timespec	now;
  struct timespec	begin;
  int			timeout;
  size_t		nc;
  long int		time_max;
  long int		time_elapsed;
  int			comp;

  memset(buff, 0, *len);
  if (port->fd == -1)
    return(RET_WARNING);

  clock_gettime(CLOCK_MONOTONIC, &begin);
  /* Add 1 second to receive timeout to be sure the message can be read */
  time_max = (((to->tv_sec + 1) * 1000) + (to->tv_nsec / 1000000));
  timeout = 0;
  nc = 0;
  comp = 0;
  while ((comp < 2) && (nc < *len) && !timeout)
  {
    n = read(port->fd, &buff[nc], 1);
    if (n < 0)
    {
      if ((errno == EBADF) || (errno == EINVAL) || (errno == EIO))
      {
	log_warn("Severe error reading from serial channel. Close channel");
	lora_close_channel(port);
      }
      else
	log_warn("Error reading from serial channel");
      return(RET_ERROR);
    }

    clock_gettime(CLOCK_MONOTONIC, &now);
    if (n > 0)
      begin = now; /* Reset timer every received character */
    else
    {
      time_elapsed = ((((now.tv_sec - begin.tv_sec) * 1000) + (now.tv_nsec / 1000000)) - (begin.tv_nsec / 1000000));
      if (time_elapsed > time_max)
	      timeout = 1;
  
    }
    if (n > 0)
    {
      switch (buff[nc])
      {
	case '\r' :
	{
	  if (comp == 0)
	    comp++;
	  break;
	}
	case '\n' :
	{
	  if (comp == 1)
	    comp++;
	  break;
	}
	default :
	{
	  break;
	}
      }
      /* MOTE with newer firmware releases can put a '\0' before the response string */
      if ((nc != 0) || (buff[nc] != '\0'))
	nc++;
    }
  }
  *len = nc;

  #ifdef DEBUG
  printf("response: %s timeout: %d\n", buff, timeout);
  #endif

  return(timeout ? RET_WARNING : RET_OK);
}


/**
 * @brief Write to serial channel
 * @param port Serial port
 * @param buff Buffer containing the characters to write
 * @param len  Number of characters to write
 * @param verbose Be verbose on logging (=1) or not (=0), dump also bytes (=2)
 * @return 
 */
int lora_write_channel(SERIAL_PORT	*port, char		*buff, size_t	len){
  ssize_t n;

  #ifdef DEBUG
  printf("writing command %s long %d bytes\n", buff, (int)len);
  #endif

  if (port->fd == -1)
    return(RET_WARNING);

  /*
   * Flush input and output buffer to prevent spurious data to get collected
   */
  tcflush(port->fd, TCIFLUSH);	/* Flush input */
  tcflush(port->fd, TCIOFLUSH);	/* Flush output before sending data */

  n = write(port->fd, buff, len);
  if (n != (ssize_t)len){

    if (n == -1){
      switch (errno){
        case EBADF :
        case EINVAL :
        case EIO :
        case EFBIG :
        case ENOSPC :
          log_warn("Severe error writing to serial channel. Close channel");
          lora_close_channel(port);
          break;
        default :
          log_warn("Error: written %d instead of %d characters", n, len);
          break;
        }
      }
    else log_warn("Error: written %d instead of %d characters", n, len);

    return(RET_WARNING);
    }

  #ifdef DEBUG
  printf("command: sent\n");
  #endif

  return(RET_OK);
  }