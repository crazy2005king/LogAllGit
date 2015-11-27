#ifndef LOG_INCLUDED
#define LOG_INCLUDED

#include "stdio.h"
#include "tchar.h"


#ifdef _MSC_VER

#if _MSC_VER <= 1200

#define LOG_WIN_VC6
#define __LOGFUNC__ NULL

#else

#ifndef _UNICODE
#define LOG_FUNC_STR
#define __LOGFUNC__				__FUNCTION__
#endif

#endif

#else

#ifndef _UNICODE
#define LOG_FUNC_STR
#define __LOGFUNC__				(const GCHAR *)__func__
#endif

#endif





#define ID_DEFAULT				-1
#define SNTYPE_MAX				20
#define SNSTR_MAX				50

#ifdef _UNICODE
#define __LOGFUNC__			NULL
#define GCHAR				wchar_t	
#define G(str)				_T(str)
#else
#define GCHAR				char	
#define G(str)				str	
#endif

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
					GCHAR *const filepath, 
					GCHAR *const flagStr);
extern int Log_unInit();
extern int Log_setParams(const int level, const int device);
extern int Log_setSessionType(GCHAR sessionTypeStrs[][SNSTR_MAX], const int sessionTypeNum);

extern void Log_str(int level, const GCHAR *data, int len);
extern int Log_list(const int channel, 
					const GCHAR *file, 
					const GCHAR *func, 
					const int line,
					const GCHAR *userdata, 
					const int level, 
					const GCHAR *format,
					va_list marker);
extern int Log_out(const int channel, 
					const GCHAR *file, 
					const GCHAR *func, 
					const int line,
					const GCHAR *userdata, 
					const int level, 
					const GCHAR *fmt, ...);
extern int Log_session(const int channel, 
					const GCHAR *file, 
					const GCHAR *func, 
					const int line,
					const int type, 
					const int level, 
					const GCHAR *fmt, ...);

#define LOUT					Log_out
#define PCONSOLE				ID_DEFAULT, G(__FILE__), __LOGFUNC__, __LINE__, NULL, LOG_CONSOLEEX
#define PERROR					ID_DEFAULT, G(__FILE__), __LOGFUNC__, __LINE__, NULL,	LOG_ERROREX
#define PWARNING				ID_DEFAULT, G(__FILE__), __LOGFUNC__, __LINE__, NULL, LOG_WARNINGEX
#define PDEBUG					ID_DEFAULT, G(__FILE__), __LOGFUNC__, __LINE__, NULL, LOG_DEBUGEX

#define LSN						Log_session
#define PSN_CONSOLE(id, type)	(id), G(__FILE__), __LOGFUNC__, __LINE__, (type), LOG_CONSOLEEX
#define PSN_ERROR(id, type)		(id), G(__FILE__), __LOGFUNC__, __LINE__, (type), LOG_ERROREX	
#define PSN_WARNING(id, type)	(id), G(__FILE__), __LOGFUNC__, __LINE__, (type), LOG_WARNINGEX
#define PSN_DEBUG(id, type)		(id), G(__FILE__), __LOGFUNC__, __LINE__, (type), LOG_DEBUGEX

#ifndef LOG_WIN_VC6
#define CONSOLE(fmt, ...)						Log_out(ID_DEFAULT, G(__FILE__), __LOGFUNC__, __LINE__, NULL, LOG_CONSOLEEX, fmt, ##__VA_ARGS__)
#define ERRORLOG(fmt, ...)						Log_out(ID_DEFAULT, G(__FILE__), __LOGFUNC__, __LINE__, NULL,	LOG_ERROREX, fmt, ##__VA_ARGS__)
#define WARNING(fmt, ...)						Log_out(ID_DEFAULT, G(__FILE__), __LOGFUNC__, __LINE__, NULL, LOG_WARNINGEX, fmt, ##__VA_ARGS__)
#define DEBUGEX(fmt, ...)						Log_out(ID_DEFAULT, G(__FILE__), __LOGFUNC__, __LINE__, NULL, LOG_DEBUGEX, fmt, ##__VA_ARGS__)

#define CONSOLE_SN(id, type, fmt, ...)			Log_session((id),  G(__FILE__), __LOGFUNC__, __LINE__, (type), LOG_CONSOLEEX, fmt, ##__VA_ARGS__)
#define ERRORLOG_SN(id, type, fmt, ...)			Log_session((id),  G(__FILE__), __LOGFUNC__, __LINE__, (type), LOG_ERROREX, fmt, ##__VA_ARGS__)	
#define WARNING_SN(id, type, fmt, ...)			Log_session((id),  G(__FILE__), __LOGFUNC__, __LINE__, (type), LOG_WARNINGEX, fmt, ##__VA_ARGS__)
#define DEBUGEX_SN(id, type, fmt, ...)			Log_session((id),  G(__FILE__), __LOGFUNC__, __LINE__, (type), LOG_DEBUGEX, fmt, ##__VA_ARGS__)

#ifdef _UNICODE
extern int Log_listA(const int channel, 
					const GCHAR *file, 
					const GCHAR *func, 
					const int line,
					const GCHAR *userdata, 
					const int level, 
					const GCHAR *format,
					va_list marker);
extern int Log_outA(const int channel, 
				   const char *file, 
				   const char *func, 
				   const int line,
				   const char *userdata, 
				   const int level, 
				   const char *fmt, ...);
extern int Log_sessionA(const int channel, 
					const char *file, 
					const char *func, 
					const int line,
					const int type, 
					const int level, 
					const char *fmt, ...);
extern void Log_strA(int level, const char *data, int len);

#define CONSOLEA(fmt, ...)						Log_outA(ID_DEFAULT, __FILE__, __LOGFUNC__, __LINE__, NULL, LOG_CONSOLEEX, fmt, ##__VA_ARGS__)
#define ERRORLOGA(fmt, ...)						Log_outA(ID_DEFAULT, __FILE__, __LOGFUNC__, __LINE__, NULL,	LOG_ERROREX, fmt, ##__VA_ARGS__)
#define WARNINGA(fmt, ...)						Log_outA(ID_DEFAULT, __FILE__, __LOGFUNC__, __LINE__, NULL, LOG_WARNINGEX, fmt, ##__VA_ARGS__)
#define DEBUGEXA(fmt, ...)						Log_outA(ID_DEFAULT, __FILE__, __LOGFUNC__, __LINE__, NULL, LOG_DEBUGEX, fmt, ##__VA_ARGS__)
#define CONSOLE_SNA(id, type, fmt, ...)			Log_sessionA((id),  __FILE__, __LOGFUNC__, __LINE__, (type), LOG_CONSOLEEX, fmt, ##__VA_ARGS__)
#define ERRORLOG_SNA(id, type, fmt, ...)		Log_sessionA((id),  __FILE__, __LOGFUNC__, __LINE__, (type), LOG_ERROREX, fmt, ##__VA_ARGS__)	
#define WARNING_SNA(id, type, fmt, ...)			Log_sessionA((id),  __FILE__, __LOGFUNC__, __LINE__, (type), LOG_WARNINGEX, fmt, ##__VA_ARGS__)
#define DEBUGEX_SNA(id, type, fmt, ...)			Log_sessionA((id),  __FILE__, __LOGFUNC__, __LINE__, (type), LOG_DEBUGEX, fmt, ##__VA_ARGS__)
#else
#define Log_strA								Log_str
#define CONSOLEA								CONSOLE	
#define ERRORLOGA								ERRORLOG
#define WARNINGA								WARNING
#define DEBUGEXA								DEBUGEX
#define CONSOLE_SNA								CONSOLE_SN
#define ERRORLOG_SNA							ERRORLOG_SN
#define WARNING_SNA								WARNING_SN
#define DEBUGEX_SNA								DEBUGEX_SN
#endif
#endif



#endif