#ifndef LOG_INCLUDED
#define LOG_INCLUDED

#include "stdio.h"

//#define LOG_NULL
#ifndef LOG_NULL


#ifdef _MSC_VER

#if _MSC_VER <= 1200

#define LOG_WIN_VC6
#define __LOGFUNC__				NULL

#else


#define LOG_FUNC_STR
#define __LOGFUNC__				__FUNCTION__


#endif

#else

#define LOG_FUNC_STR
#define __LOGFUNC__				(const char *)__func__

#endif





#define ID_DEFAULT				-1
#define SNTYPE_MAX				20
#define SNSTR_MAX				50


typedef enum 
{
	LOG_DEVICE_NULL = 0,		//无输出
	LOG_DEVICE_SCREEN,			//输出到屏幕（若是Windows, 同时输出到Dbgview）
	LOG_DEVICE_FILE,			//输出到文件
	LOG_DEVICE_SCREEN_FILE,		//同时输出到屏幕和文件
} LOGDEVICE;

typedef enum 
{
	LOG_CONSOLEEX = 0,			//终端
	LOG_ERROREX,				//错误
	LOG_WARNINGEX,				//警告
	LOG_DEBUGEX,				//调试
} LOGLEVEL;


extern int Log_init(const int level, 
					const int device,
					const int modid,
					char *const filepath, 
					char *const flagStr);
extern int Log_unInit();
extern int Log_setParams(const int level, const int device);
extern int Log_setSessionType(char sessionTypeStrs[][SNSTR_MAX], const int sessionTypeNum);

extern void Log_str(int level, const char *data, int len);
extern int Log_list(const int channel, 
					const char *file, 
					const char *func, 
					const int line,
					const char *userdata, 
					const int level, 
					const char *format,
					va_list marker);
extern int Log_out(const int channel, 
					const char *file, 
					const char *func, 
					const int line,
					const char *userdata, 
					const int level, 
					const char *fmt, ...);
extern int Log_session(const int channel, 
					const char *file, 
					const char *func, 
					const int line,
					const int type, 
					const int level, 
					const char *fmt, ...);

#define LOUT					Log_out
#define PCONSOLE				ID_DEFAULT, (__FILE__), __LOGFUNC__, __LINE__, NULL, LOG_CONSOLEEX
#define PERROR					ID_DEFAULT, (__FILE__), __LOGFUNC__, __LINE__, NULL, LOG_ERROREX
#define PWARNING				ID_DEFAULT, (__FILE__), __LOGFUNC__, __LINE__, NULL, LOG_WARNINGEX
#define PDEBUG					ID_DEFAULT, (__FILE__), __LOGFUNC__, __LINE__, NULL, LOG_DEBUGEX

#define LSN						Log_session
#define PSN_CONSOLE(id, type)	(id), (__FILE__), __LOGFUNC__, __LINE__, (type), LOG_CONSOLEEX
#define PSN_ERROR(id, type)		(id), (__FILE__), __LOGFUNC__, __LINE__, (type), LOG_ERROREX	
#define PSN_WARNING(id, type)	(id), (__FILE__), __LOGFUNC__, __LINE__, (type), LOG_WARNINGEX
#define PSN_DEBUG(id, type)		(id), (__FILE__), __LOGFUNC__, __LINE__, (type), LOG_DEBUGEX

#ifndef LOG_WIN_VC6
#define CONSOLE(fmt, ...)						Log_out(ID_DEFAULT, (__FILE__), __LOGFUNC__, __LINE__, NULL, LOG_CONSOLEEX, fmt, ##__VA_ARGS__)
#define ERROREX(fmt, ...)						Log_out(ID_DEFAULT, (__FILE__), __LOGFUNC__, __LINE__, NULL,	LOG_ERROREX, fmt, ##__VA_ARGS__)
#define WARNING(fmt, ...)						Log_out(ID_DEFAULT, (__FILE__), __LOGFUNC__, __LINE__, NULL, LOG_WARNINGEX, fmt, ##__VA_ARGS__)
#define DEBUGEX(fmt, ...)						Log_out(ID_DEFAULT, (__FILE__), __LOGFUNC__, __LINE__, NULL, LOG_DEBUGEX, fmt, ##__VA_ARGS__)

#define CONSOLE_SN(id, type, fmt, ...)			Log_session((id),  (__FILE__), __LOGFUNC__, __LINE__, (type), LOG_CONSOLEEX, fmt, ##__VA_ARGS__)
#define ERROREX_SN(id, type, fmt, ...)			Log_session((id),  (__FILE__), __LOGFUNC__, __LINE__, (type), LOG_ERROREX, fmt, ##__VA_ARGS__)	
#define WARNING_SN(id, type, fmt, ...)			Log_session((id),  (__FILE__), __LOGFUNC__, __LINE__, (type), LOG_WARNINGEX, fmt, ##__VA_ARGS__)
#define DEBUGEX_SN(id, type, fmt, ...)			Log_session((id),  (__FILE__), __LOGFUNC__, __LINE__, (type), LOG_DEBUGEX, fmt, ##__VA_ARGS__)
#endif


#else

#define Log_init(level, device, modid, filepath, flagStr)								NULL
#define Log_unInit()																	NULL
#define Log_setParams(level, device)													NULL
#define Log_setSessionType(sessionTypeStrs, sessionTypeNum)								NULL
#define Log_str(level, data, len)														NULL
#define Log_list(channel, file, func, line, userdata, level, format, marker)			NULL
#define Log_out(channel, file, func, line, userdata, level, fmt, ...)					NULL
#define Log_session(channel, file, func, line, type, level, fmt, ...)					NULL


#define LOUT																			Log_out
#define PCONSOLE																		NULL, NULL, NULL, NULL, NULL, NULL
#define PERROR																			NULL, NULL, NULL, NULL, NULL, NULL
#define PWARNING																		NULL, NULL, NULL, NULL, NULL, NULL
#define PDEBUG																			NULL, NULL, NULL, NULL, NULL, NULL

#define LSN																				Log_session
#define PSN_CONSOLE(id, type)															NULL, NULL, NULL, NULL, NULL, NULL, NULL
#define PSN_ERROR(id, type)																NULL, NULL, NULL, NULL, NULL, NULL, NULL
#define PSN_WARNING(id, type)															NULL, NULL, NULL, NULL, NULL, NULL, NULL
#define PSN_DEBUG(id, type)																NULL, NULL, NULL, NULL, NULL, NULL, NULL


#define CONSOLE(fmt, ...)																NULL
#define ERROREX(fmt, ...)																NULL
#define WARNING(fmt, ...)																NULL
#define DEBUGEX(fmt, ...)																NULL

#define CONSOLE_SN(id, type, fmt, ...)													NULL
#define ERROREX_SN(id, type, fmt, ...)													NULL
#define WARNING_SN(id, type, fmt, ...)													NULL
#define DEBUGEX_SN(id, type, fmt, ...)													NULL

#endif


#endif