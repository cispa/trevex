#ifndef _MODULE_H
#define _MODULE_H

#define MODULE_DEVICE_NAME "fpdssvictim"
#define MODULE_DEVICE_PATH "/dev/" MODULE_DEVICE_NAME


#define MODULE_IOCTL_MAGIC_NUMBER (long)0xf00f00

#define MODULE_IOCTL_VICTIM_RUN \
  _IOR(MODULE_IOCTL_MAGIC_NUMBER, 1, size_t)
//       ^-- command name         ^-- unique command ID
  
#endif
