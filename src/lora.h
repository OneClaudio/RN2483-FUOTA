#ifndef LORA_H_
#define LORA_H_

#include <stdint.h>
#include <time.h>
#include "serial.h"

extern void lora_close_channel(SERIAL_PORT	*port);
extern void lora_dump_data(char	*descr, char *data, size_t len, int dump_bytes);
extern void lora_open_channel(SERIAL_PORT	*port);
extern	int	lora_read_channel(SERIAL_PORT *port, char *buff, size_t	*len, struct timespec *to);
extern	int	lora_write_channel(SERIAL_PORT	*port, char	*buff, size_t len);

#endif
