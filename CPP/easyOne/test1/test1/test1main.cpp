#include "log.h"


int main()
{
	Log_init(LOG_DEBUGEX, LOG_DEVICE_SCREEN_FILE, 0, NULL, NULL);
	CONSOLE("test1111111\n");
	CONSOLE("test1111112\n");
	CONSOLE("test1111113\n");
	CONSOLE("test1111114\n");
	Log_unInit();
	return 0;
}