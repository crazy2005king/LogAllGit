#include "log.h"
#include "time.h"
#include "stdarg.h"
#include "string.h"
#include "io.h"
#ifdef WIN32
#include <winsock2.h>
#include <windows.h>
#else
#include <sys/time.h>

#include <unistd.h>
#include <dirent.h>
#include <dlfcn.h>
#include <sys/ipc.h>
#include <sys/shm.h>
#include <sys/time.h>
#include <sys/socket.h>
#include <sys/select.h>
#include <sys/ioctl.h>
#include <sys/types.h>
#include <sys/sem.h>
#include <sys/wait.h>
#include <sys/param.h>
#include <signal.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <net/if.h>
#include <pthread.h>
#include <errno.h>
#include <syslog.h>

#include<fcntl.h>

typedef struct
{ 
	unsigned short wYear; 
	unsigned short wMonth; 
	unsigned short wDayOfWeek; 
	unsigned short wDay; 
	unsigned short wHour; 
	unsigned short wMinute; 
	unsigned short wSecond; 
	unsigned short wMilliseconds; 
}SYSTEMTIME, *PSYSTEMTIME,*LPSYSTEMTIME; 

void GetLocalTime(LPSYSTEMTIME lpSystemTime)
{
	struct timeval tmv;	
	struct tm ptm;	
	gettimeofday(&tmv,NULL);
    localtime_r(&tmv.tv_sec,&ptm);
	lpSystemTime->wYear = (unsigned short)(1900+ptm.tm_year);
	lpSystemTime->wMonth = (unsigned short)(1+ptm.tm_mon);
	lpSystemTime->wDayOfWeek = (unsigned short)ptm.tm_wday;
	lpSystemTime->wDay = (unsigned short)ptm.tm_mday;
	lpSystemTime->wHour = ptm.tm_hour;
	lpSystemTime->wMinute = ptm.tm_min;
	lpSystemTime->wSecond = ptm.tm_sec;
	lpSystemTime->wMilliseconds = tmv.tv_usec/1000;
}
#endif

class LogLock
{
private:
#ifdef WIN32         
	CRITICAL_SECTION WinlCriticalSection; 
#else
	pthread_mutex_t mutex;
#endif
public:
	LogLock()
	{
#ifdef WIN32
		InitializeCriticalSection(&WinlCriticalSection);

#else
		pthread_mutex_init(&mutex,NULL);
#endif
	}
	~LogLock()
	{
#ifdef WIN32
		DeleteCriticalSection(&WinlCriticalSection);

#else
		pthread_mutex_destroy(&mutex);
#endif
	}
	int lock()
	{
#ifdef WIN32
	    EnterCriticalSection(&WinlCriticalSection);
#else
        pthread_mutex_lock(&mutex);
#endif
		return 0;
	}  
	int unLock()
	{
#ifdef WIN32
        LeaveCriticalSection(&WinlCriticalSection);
#else        
		pthread_mutex_unlock(&mutex);
#endif
		return 0;
	}
};

#ifdef WIN32
#define SEQ_FWHITE				FOREGROUND_RED | FOREGROUND_GREEN | FOREGROUND_BLUE | FOREGROUND_INTENSITY
#define SEQ_FRED				FOREGROUND_RED | FOREGROUND_INTENSITY
#define SEQ_FMAGEN				FOREGROUND_BLUE | FOREGROUND_RED
#define SEQ_FCYAN				FOREGROUND_GREEN | FOREGROUND_BLUE
#define SEQ_FGREEN				FOREGROUND_GREEN
#define SEQ_FYELLOW				FOREGROUND_RED | FOREGROUND_GREEN | FOREGROUND_INTENSITY
#define SEQ_DEFAULT_COLOR		SEQ_FWHITE
#else
#define SEQ_ESC "\033["
#define SEQ_HOME_CHAR			'H'
#define SEQ_HOME_CHAR_STR		"H"
#define SEQ_CLEARLINE_CHAR		'1'
#define SEQ_CLEARLINE_CHAR_STR	"1"
#define SEQ_CLEARLINEEND_CHAR	"K"
#define SEQ_CLEARSCR_CHAR0		'2'
#define SEQ_CLEARSCR_CHAR1		'J'
#define SEQ_CLEARSCR_CHAR		"2J"
#define SEQ_DEFAULT_COLOR		SEQ_ESC SEQ_END_COLOR	
#define SEQ_AND_COLOR			";"	
#define SEQ_END_COLOR			"m"	
#define SEQ_F_BLACK				"30"
#define SEQ_F_RED				"31"
#define SEQ_F_GREEN				"32"
#define SEQ_F_YELLOW			"33"
#define SEQ_F_BLUE				"34"
#define SEQ_F_MAGEN				"35"
#define SEQ_F_CYAN				"36"
#define SEQ_F_WHITE				"37"
#define SEQ_B_BLACK				"40"
#define SEQ_B_RED				"41"
#define SEQ_B_GREEN				"42"
#define SEQ_B_YELLOW			"43"
#define SEQ_B_BLUE				"44"
#define SEQ_B_MAGEN				"45"
#define SEQ_B_CYAN				"46"
#define SEQ_B_WHITE				"47"
#define SEQ_FBLACK				SEQ_ESC SEQ_F_BLACK SEQ_END_COLOR
#define SEQ_FRED				SEQ_ESC SEQ_F_RED SEQ_END_COLOR
#define SEQ_FGREEN				SEQ_ESC SEQ_F_GREEN SEQ_END_COLOR
#define SEQ_FYELLOW				SEQ_ESC SEQ_F_YELLOW SEQ_END_COLOR
#define SEQ_FBLUE				SEQ_ESC SEQ_F_BLUE SEQ_END_COLOR
#define SEQ_FMAGEN				SEQ_ESC SEQ_F_MAGEN SEQ_END_COLOR
#define SEQ_FCYAN				SEQ_ESC SEQ_F_CYAN SEQ_END_COLOR
#define SEQ_FWHITE				SEQ_ESC SEQ_F_WHITE SEQ_END_COLOR
#define SEQ_BBLACK				SEQ_ESC SEQ_B_BLACK SEQ_END_COLOR
#define SEQ_BRED				SEQ_ESC SEQ_B_RED SEQ_END_COLOR
#define SEQ_BGREEN				SEQ_ESC SEQ_B_GREEN SEQ_END_COLOR
#define SEQ_BYELLOW				SEQ_ESC SEQ_B_YELLOW SEQ_END_COLOR
#define SEQ_BBLUE				SEQ_ESC SEQ_B_BLUE SEQ_END_COLOR
#define SEQ_BMAGEN				SEQ_ESC SEQ_B_MAGEN SEQ_END_COLOR
#define SEQ_BCYAN				SEQ_ESC SEQ_B_CYAN SEQ_END_COLOR
#define SEQ_BWHITE				SEQ_ESC SEQ_B_WHITE SEQ_END_COLOR
#define SEQ_HOME				SEQ_ESC SEQ_HOME_CHAR_STR
#define SEQ_CLEARLINE			SEQ_ESC SEQ_CLEARLINE_CHAR_STR
#define SEQ_CLEARLINEEND		SEQ_ESC SEQ_CLEARLINEEND_CHAR
#define SEQ_CLEARSCR			SEQ_ESC SEQ_CLEARSCR_CHAR SEQ_HOME
#endif

static const int UNICODE_TXT_FLG = 0xFEFF;

#ifdef _UNICODE
#define LOGSPRINTF		swprintf_s
#define LOGSPRINTF_V	vswprintf
#define LOGOPENFILE		_wfopen_s
#define LOGSPRINTF_F	fwprintf
#define LOGACCESS		_waccess
#else
#define LOGSPRINTF		_snprintf
#define LOGSPRINTF_V	_vsnprintf
#define LOGSPRINTF_F	fprintf
#define LOGOPENFILE		fopen_s
#define LOGACCESS		_access
#endif


class Log
{
public:
	enum 
	{		
		LOG_BUF_MAXSIZE		= 256,
		LOG_PATH_MAXSIZE	= 256,
		LOG_STRMAXSIZE		= 2048,
		LOG_FILE_MAXSIZE	= 104857600,	//100M
	};
private:
	static Log g_log;	
#ifdef WIN32
	static const WORD COLORS[LOG_DEBUGEX+1];
#else
	static const GCHAR* COLORS[LOG_DEBUGEX+1];
#endif
	static const GCHAR *LEVELS[LOG_DEBUGEX+1];
	static int g_sessionTypeNum;
	static GCHAR g_sessionTypeStrs[SNTYPE_MAX][SNSTR_MAX];	
public:
	static Log* GLog(){return &g_log;}
	static int getLevel(const int level)
	{
		int currLevel = LOG_CONSOLEEX;
		switch(level)
		{
		case LOG_CONSOLEEX:
			currLevel = LOG_CONSOLEEX;
			break;
		case LOG_ERROREX:
			currLevel = LOG_ERROREX;
			break;
		case LOG_WARNINGEX:
			currLevel = LOG_WARNINGEX;
			break;
		case LOG_DEBUGEX:
			currLevel = LOG_DEBUGEX;
			break;
		default:
			currLevel = LOG_DEBUGEX;
			break;
		}		
		return currLevel;
	}
	static GCHAR *getSessionTypeStr(const int type)
	{
		if(!g_sessionTypeStrs 
			|| g_sessionTypeNum <= 0
			|| type < 0
			|| type >= g_sessionTypeNum)
		{
			return G("SN_UNKNOWN");
		}		
		return g_sessionTypeStrs[type];
	}
	static int log_setSessionType(GCHAR sessionTypeStrs[][SNSTR_MAX], const int sessionTypeNum)
	{
		if(!sessionTypeStrs 
			|| sessionTypeNum <= 0
			|| sessionTypeNum >= SNSTR_MAX)
		{
			return -1;
		}
		for(int i = 0; i < sessionTypeNum; i++)
		{
			memset(g_sessionTypeStrs[i], 0, sizeof(g_sessionTypeStrs[i]));
			memcpy(g_sessionTypeStrs[i], sessionTypeStrs[i], 
				lstrlen(sessionTypeStrs[i])*sizeof(sessionTypeStrs[i][0]));
		}
		g_sessionTypeNum = sessionTypeNum;
		return 0;
	}
private:	
	static const GCHAR* log_cutpath(const GCHAR *in)
	{
		if(!in)
		{
			return NULL;
		}
		const GCHAR *i = NULL;
		const GCHAR *p = NULL; 
		const GCHAR *name = in;
		const GCHAR delims[] = G("/\\");
		for(i = delims; *i; i++) 
		{
			p = in;
			while((p = _tcschr(p, *i)) != 0) 
			{
				name = ++p;
			}
		}
		return name;
	}
	static const GCHAR * log_level2str(int level)
	{
		if (level < LOG_CONSOLEEX || level > LOG_DEBUGEX) 
		{
			level = LOG_CONSOLEEX;
		}
		return LEVELS[level];
	}
	static int log_getCurrTimeStr(GCHAR *const strBuf, const int strBufSize)
	{
		const int timStrMaxSize = 50;
		if(!strBuf || strBufSize <= timStrMaxSize)
		{
			return -1;
		}
		SYSTEMTIME SystemTime;
		memset(&SystemTime, 0, sizeof(SystemTime));	
		GetLocalTime(&SystemTime);
		LOGSPRINTF(strBuf, 
			strBufSize,
			G("%04d-%02d-%02d %02d:%02d:%02d:%03d"), 
			SystemTime.wYear, 
			SystemTime.wMonth, 
			SystemTime.wDay, 
			SystemTime.wHour, 
			SystemTime.wMinute, 
			SystemTime.wSecond,
			SystemTime.wMilliseconds);    
		return SystemTime.wHour;
	}
	static int log_getCurrHour()
	{		
		SYSTEMTIME SystemTime;		
		GetLocalTime(&SystemTime);
		return SystemTime.wHour;
	}
	int log_printStr(const int level, GCHAR *const logStr, void* hStdout)
	{
		if(!logStr || (level < LOG_CONSOLEEX || level > LOG_DEBUGEX))
		{
			return -1;
		}
#ifdef WIN32
		if(INVALID_HANDLE_VALUE == hStdout)
		{
			return -2;
		}
		WORD wOldColorAttrs;
		CONSOLE_SCREEN_BUFFER_INFO csbiInfo;
		if(GetConsoleScreenBufferInfo(hStdout, &csbiInfo))
		{
			wOldColorAttrs = csbiInfo.wAttributes;
			SetConsoleTextAttribute(hStdout, COLORS[level]);
			DWORD ws;
			WriteConsole(GetStdHandle(STD_OUTPUT_HANDLE),logStr,lstrlen(logStr),&ws,NULL);
			SetConsoleTextAttribute(hStdout, wOldColorAttrs);
		}
		OutputDebugString(logStr);  
#else
		LOGSPRINTF_F(stdout, "%s%s%s", COLORS[level], logStr, SEQ_DEFAULT_COLOR);
#endif
		return 0;
	}
	int log_getStr(const int channel, 
		const GCHAR *file, 
		const GCHAR *func, 
		const int line,
		const GCHAR *userdata, 
		const int level, 
		const GCHAR *fmt, 
		va_list ap,
		GCHAR *const strBuf, 
		const int strBufSize)
	{
		if(level < LOG_CONSOLEEX || level > LOG_DEBUGEX)
		{
			return 0;
		}
		const int TIMESTR_MAXSIZE = 80;
		const int OUTSTR_MAXSIZE = 1024;
		if(!strBuf || strBufSize < LOG_STRMAXSIZE)
		{
			return 0;
		}
		int len = 0;
		const GCHAR *filep = (file ? log_cutpath(file) : G(""));
		const GCHAR *funcp = (func ? func : G(""));
		GCHAR szOutStr[OUTSTR_MAXSIZE] = {0};
		LOGSPRINTF_V(szOutStr, OUTSTR_MAXSIZE, fmt, ap);
		GCHAR currChannelStr[OUTSTR_MAXSIZE] = {0};
		if(userdata || ID_DEFAULT != channel)
		{
			if(userdata && ID_DEFAULT != channel)
			{
				LOGSPRINTF(currChannelStr, OUTSTR_MAXSIZE-1, G("%s[%d]"), userdata, channel);
			}
			else if(userdata)
			{
				LOGSPRINTF(currChannelStr, OUTSTR_MAXSIZE-1, G("%s"), userdata);
			}
			else
			{
				LOGSPRINTF(currChannelStr, OUTSTR_MAXSIZE-1, G("[%d]"), channel);
			}
			_tcscat_s(strBuf, strBufSize-1, currChannelStr);
		}
#ifdef LOG_FUNC_STR
		const GCHAR *extra_fmt = G("%s [%s] %s:%d %s() %s %s");
#else
		const GCHAR *extra_fmt = G("%s [%s] %s:%d %s %s");
#endif
		GCHAR currTimeStr[TIMESTR_MAXSIZE] = {0};
		int currCurrHour = log_getCurrTimeStr(currTimeStr, TIMESTR_MAXSIZE);
#ifdef LOG_FUNC_STR
		len = lstrlen(extra_fmt) + lstrlen(currTimeStr) + lstrlen(filep) + 32 + lstrlen(funcp) + lstrlen(currChannelStr) + lstrlen(szOutStr);
#else
		len = lstrlen(extra_fmt) + lstrlen(currTimeStr) + lstrlen(filep) + 32 + lstrlen(currChannelStr) + lstrlen(szOutStr);
#endif
		if(len >= LOG_STRMAXSIZE)
		{
			return 0;
		}
#ifdef LOG_FUNC_STR
		LOGSPRINTF(strBuf, strBufSize-1, extra_fmt, currTimeStr, log_level2str(level), filep, line, funcp, currChannelStr, szOutStr);
#else
		LOGSPRINTF(strBuf, strBufSize-1, extra_fmt, currTimeStr, log_level2str(level), filep, line, currChannelStr, szOutStr);
#endif
		_tcscat_s(strBuf, strBufSize-1, G("\n"));
		return currCurrHour;
	}
public:
	Log():
		m_modid(0),
		m_filehour(-1),
		m_fileindex(0),
		m_pLogFile(NULL)
	{
		m_logLevel = LOG_CONSOLEEX;
		m_logDevice = LOG_DEVICE_SCREEN;
		memset(m_flagStr, 0, sizeof(m_flagStr));
		memset(m_filePath, 0, sizeof(m_filePath));	
#ifdef WIN32
		m_hStdout = GetStdHandle(STD_OUTPUT_HANDLE);
#endif
	}
	~Log()
	{
		unInit();
	}

	int init(const int level, 
		const int device,
		const int modid,
		GCHAR *const filepath, 
		GCHAR *const flagStr)
	{
		if(level < LOG_CONSOLEEX || level > LOG_DEBUGEX)
		{
			return -1;
		}
		if(device < LOG_DEVICE_NULL ||  device > LOG_DEVICE_SCREEN_FILE)
		{
			return -2;
		}
		if(modid < 0)
		{
			return -3;
		}
		if(filepath && lstrlen(filepath) > sizeof(m_filePath)/sizeof(m_filePath[0]))
		{
			return -4;
		}
		m_lock.lock();	
		m_logLevel = (LOGLEVEL)level;	
		m_logDevice = (LOGDEVICE)device;	
		m_modid = modid;		
		int strLen = lstrlen(filepath);
		memset(m_filePath, 0, sizeof(m_filePath));
		if(filepath)
		{
			memcpy(m_filePath, filepath, lstrlen(filepath)*sizeof(filepath[0]));
			if (m_filePath[lstrlen(m_filePath)-1] == '\\')
			{
				m_filePath[lstrlen(m_filePath)-1] = '\0';
			}
		}		
		memset(m_flagStr, 0, sizeof(m_flagStr));
		if(flagStr)
		{
			int flagStrLen = lstrlen(flagStr);
			if(flagStrLen > 0 && flagStrLen <= sizeof(m_flagStr)/sizeof(flagStr[0]))
			{
				memcpy(m_flagStr, flagStr, lstrlen(flagStr)*sizeof(flagStr[0]));
			}
		}
		int RetOpenFile = openFile();
		m_lock.unLock();
		if(0 != RetOpenFile)
		{
			return -5;
		}
		return 0;
	}

	int unInit()
	{
		m_lock.lock();
		m_logLevel = LOG_CONSOLEEX;
		m_logDevice = LOG_DEVICE_SCREEN;
		if(m_pLogFile)
		{
			fclose(m_pLogFile);
			m_pLogFile = NULL;
		}
		memset(m_filePath, 0, sizeof(m_filePath));
		m_lock.unLock();
		return 0;
	}

	int isNeedLog(const int level)
	{
		if(LOG_DEVICE_NULL == m_logDevice || level > m_logLevel)
		{
			return 0;
		}
		return 1;
	}

	int setParams(const int level, 
		const int device)
	{
		if(level < LOG_CONSOLEEX || level > LOG_DEBUGEX
			|| device < LOG_DEVICE_NULL || device > LOG_DEVICE_SCREEN_FILE)
		{
			return 0;
		}
		m_lock.lock();
		m_logLevel = (LOGLEVEL)level;
		m_logDevice = (LOGDEVICE)device;
		m_lock.unLock();
		return 1;
	}

	int logWrite(const int level, GCHAR*const logStr, int currHour = -1)
	{
		if(!logStr)
		{
			return -1;
		}
		if(currHour < 0)
		{
			currHour = log_getCurrHour();
		}
		LOGDEVICE logDevice = LOG_DEVICE_SCREEN;
		m_lock.lock();
		logDevice = m_logDevice;
		m_lock.unLock();
		// log to file
		if(logDevice & LOG_DEVICE_FILE)
		{
			int currLogStrLen = lstrlen(logStr);
			int currIsCreateNewFile = 0;
			m_lock.lock();
			if(m_pLogFile)
			{
				fwrite(logStr, currLogStrLen*sizeof(logStr[0]), 1, m_pLogFile);
				if(m_filehour != currHour)
				{
					currIsCreateNewFile = 1;
				}
				else
				{
					fseek(m_pLogFile, SEEK_SET, SEEK_END);  
					int currFileSize = ftell(m_pLogFile);
					if(currFileSize >= LOG_FILE_MAXSIZE)
					{
						m_fileindex++;
						currIsCreateNewFile = 1;
					}
				}
				if(currIsCreateNewFile)
				{
					m_fileindex = 0;
					openFile();	
				}
			}
			m_lock.unLock();
		}
		// log to console
		if(logDevice & LOG_DEVICE_SCREEN)
		{
#ifdef WIN32
			log_printStr(level, logStr, m_hStdout);
#else
			log_printStr(level, logStr, NULL);
#endif
		}
		return 0;
	}

	int logout(
		const int channel, 
		const GCHAR *file, 
		const GCHAR *func, 
		const int line,
		const GCHAR *userdata, 
		const int level, 
		const GCHAR *format,
		va_list marker)
	{
		if(!isNeedLog(level))
		{
			return 0;
		}
		GCHAR currLogStr[LOG_STRMAXSIZE] = {0};
		int currCurHour = log_getStr(channel, file, func, line, userdata, level, 
			format, marker, currLogStr, LOG_STRMAXSIZE);
		return logWrite(level, currLogStr, currCurHour);
	}
private:
	int getFileName(GCHAR *const fileName, const int fileNameSize)
	{
		if(!fileName || fileNameSize < LOG_PATH_MAXSIZE)
		{
			return -1;
		}
		SYSTEMTIME SystemTime;
		memset(&SystemTime, 0, sizeof(SystemTime));	
		GetLocalTime(&SystemTime);
		if(lstrlen(m_filePath) > 0)
		{
#ifdef WIN32
			LOGSPRINTF(fileName, 
				fileNameSize-1,
				G("%s\\%s%d-%04d%02d%02d%02d-%d.log"), 
				m_filePath, 
				m_flagStr,
				m_modid, 
				SystemTime.wYear, 
				SystemTime.wMonth, 
				SystemTime.wDay, 
				SystemTime.wHour, 
				m_fileindex);
#else
			LOGSPRINTF(fileName, 
				fileNameSize-1,
				G("%s/%s%d-%04d%02d%02d%02d-%d.log"), 
				m_filePath, 
				m_flagStr,
				m_modid, 
				SystemTime.wYear, 
				SystemTime.wMonth, 
				SystemTime.wDay, 
				SystemTime.wHour, 
				m_fileindex);
#endif
		}
		else
		{
#ifdef WIN32
			LOGSPRINTF(fileName, 
				fileNameSize-1,
				G("%s%d-%04d%02d%02d%02d-%d.log"), 
				m_flagStr,
				m_modid, 
				SystemTime.wYear, 
				SystemTime.wMonth, 
				SystemTime.wDay, 
				SystemTime.wHour, 
				m_fileindex);
#else
			LOGSPRINTF(fileName, 
				fileNameSize-1,
				G("%s%d-%04d%02d%02d%02d-%d.log"),  
				m_flagStr,
				m_modid, 
				SystemTime.wYear, 
				SystemTime.wMonth, 
				SystemTime.wDay, 
				SystemTime.wHour, 
				m_fileindex);
#endif
		}

		return SystemTime.wHour;
	}

	int openFile()
	{
		if(m_pLogFile)
		{
			fclose(m_pLogFile);
			m_pLogFile = NULL;
		}
		GCHAR fileName[LOG_PATH_MAXSIZE] = {0};
		const int RUN_MAXTIMES = 100;
		int curHour = 0, runTimes = 0;		
		while(1)
		{
			curHour = getFileName(fileName, LOG_PATH_MAXSIZE);
			if(-1 == LOGACCESS(fileName, 0))
			{
				break;
			}
			m_fileindex++;
			runTimes++;
			if(runTimes >= RUN_MAXTIMES)
			{
				break;
			}
		}
		if(lstrlen(fileName) <= 0)
		{
			return -1;
		}		
		if(0 != LOGOPENFILE(&m_pLogFile, fileName, G("ab+")))
		{
			LOGSPRINTF_F(stderr, G("[error]log file <%s> open failed\n"), fileName);
			return -2;
		}
		fseek(m_pLogFile, 0, SEEK_END);
		if (0 == ftell(m_pLogFile))
		{
#ifdef _UNICODE
			fwrite(&UNICODE_TXT_FLG, 2, 1, m_pLogFile); 
#endif 			
			LOGSPRINTF_F(m_pLogFile, G("##### %s Log File #####\n"), m_flagStr);
		}
		m_filehour = curHour;
		return 0;		
	}
private:
	int m_modid;
	int m_filehour;
	int m_fileindex;
private:
	LogLock m_lock;
	LOGLEVEL m_logLevel;
	LOGDEVICE m_logDevice;
private:	
#ifdef WIN32
	HANDLE m_hStdout;
#endif
private:
	FILE *m_pLogFile;
	GCHAR m_flagStr[LOG_PATH_MAXSIZE];
	GCHAR m_filePath[LOG_PATH_MAXSIZE];



#ifdef _UNICODE
public:
	static int strToWStr(wchar_t* lpw, const int lpwSize, char* lpa)
	{
		if(!lpw || lpwSize <= 0 || !lpa)
		{
			return -1;
		}
		size_t aLen = strlen(lpa) + 1;
		int wLen = MultiByteToWideChar(CP_ACP, 0, lpa, aLen, NULL, 0);
		if(lpwSize <= wLen)
		{
			return -2;
		}
		MultiByteToWideChar(CP_ACP,0, lpa, aLen, lpw, wLen);
		return 0;
	}
	static int wstrToStr(char* lpa, const int lpaSize, wchar_t* lpw)
	{
		if(!lpa || lpaSize <= 0 || !lpw)
		{
			return -1;
		}
		int aLen = WideCharToMultiByte(CP_OEMCP, NULL, lpw, -1, NULL, 0, NULL, FALSE);
		if(aLen >= lpaSize)
		{
			return -1;
		}
		WideCharToMultiByte(CP_OEMCP, NULL, lpw, -1, lpa, lpaSize, NULL, FALSE);
		return 0;
	}
	static int getSessionTypeStrA(const int type, char* lpa, const int lpaSize)
	{
		if(!g_sessionTypeStrs 
			|| g_sessionTypeNum <= 0
			|| type < 0
			|| type >= g_sessionTypeNum)
		{
			strcpy_s(lpa, lpaSize-1, "SN_UNKNOWN");
			return 0;
		}		
		return wstrToStr(lpa, lpaSize, g_sessionTypeStrs[type]);
	}
private:
	static const char *LEVELSA[LOG_DEBUGEX+1];
	static const char* log_cutpathA(const char *in)
	{
		if(!in)
		{
			return NULL;
		}
		const char *i = NULL;
		const char *p = NULL; 
		const char *name = in;
		const char delims[] = "/\\";
		for(i = delims; *i; i++) 
		{
			p = in;
			while((p = strchr(p, *i)) != 0) 
			{
				name = ++p;
			}
		}
		return name;
	}
	static const char * log_level2strA(int level)
	{
		if (level < LOG_CONSOLEEX || level > LOG_DEBUGEX) 
		{
			level = LOG_CONSOLEEX;
		}
		return LEVELSA[level];
	}
	static int log_getCurrTimeStrA(char *const strBuf, const int strBufSize)
	{
		const int timStrMaxSize = 50;
		if(!strBuf || strBufSize <= timStrMaxSize)
		{
			return NULL;
		}
		SYSTEMTIME SystemTime;
		memset(&SystemTime, 0, sizeof(SystemTime));	
		GetLocalTime(&SystemTime);
		sprintf_s(strBuf, 
			strBufSize-1,
			"%04d-%02d-%02d %02d:%02d:%02d:%03d", 
			SystemTime.wYear, 
			SystemTime.wMonth, 
			SystemTime.wDay, 
			SystemTime.wHour, 
			SystemTime.wMinute, 
			SystemTime.wSecond,
			SystemTime.wMilliseconds);    
		return SystemTime.wHour;
	}	
	int log_getStrA(const int channel, 
		const char *file, 
		const char *func, 
		const int line,
		const char *userdata, 
		const int level, 
		const char *fmt, 
		va_list ap,
		char *const strBuf, 
		const int strBufSize)
	{
		if(level < LOG_CONSOLEEX || level > LOG_DEBUGEX)
		{
			return 0;
		}
		const int TIMESTR_MAXSIZE = 80;
		const int TMPOUTSTR_MAXSIZE = 1024;
		if(!strBuf || strBufSize < LOG_STRMAXSIZE)
		{
			return 0;
		}
		int len = 0;
		const char *filep = (file ? log_cutpathA(file) : "");
		const char *funcp = (func ? func : "");
		char szOutStr[TMPOUTSTR_MAXSIZE] = {0};
		vsprintf_s(szOutStr, TMPOUTSTR_MAXSIZE, fmt, ap);
		char currChannelStr[TMPOUTSTR_MAXSIZE] = {0};
		if(userdata || ID_DEFAULT != channel)
		{
			if(userdata && ID_DEFAULT != channel)
			{
				sprintf_s(currChannelStr, TMPOUTSTR_MAXSIZE-1, "%s[%d]", userdata, channel);
			}
			else if(userdata)
			{
				sprintf_s(currChannelStr, TMPOUTSTR_MAXSIZE-1, "%s", userdata);
			}
			else
			{
				sprintf_s(currChannelStr, TMPOUTSTR_MAXSIZE-1, "[%d]", channel);
			}
			strcat_s(strBuf, strBufSize-1, currChannelStr);
		}
#ifdef LOG_FUNC_STR
		const char *extra_fmt = "%s [%s] %s:%d %s() %s %s";
#else
		const char *extra_fmt = "%s [%s] %s:%d %s %s";
#endif
		char currTimeStr[TIMESTR_MAXSIZE] = {0};
		int currCurrHour = log_getCurrTimeStrA(currTimeStr, TIMESTR_MAXSIZE);
#ifdef LOG_FUNC_STR
		len = strlen(extra_fmt) + strlen(currTimeStr) + strlen(filep) + 32 + strlen(funcp) + strlen(currChannelStr) + strlen(szOutStr);
#else
		len = strlen(extra_fmt) + strlen(currTimeStr) + strlen(filep) + 32 + strlen(currChannelStr) + strlen(szOutStr);
#endif
		if(len >= LOG_STRMAXSIZE)
		{
			return 0;
		}
#ifdef LOG_FUNC_STR
		sprintf_s(strBuf, strBufSize-1, extra_fmt, currTimeStr, log_level2strA(level), filep, line, funcp, currChannelStr, szOutStr);
#else
		sprintf_s(strBuf, strBufSize-1, extra_fmt, currTimeStr, log_level2strA(level), filep, line, currChannelStr, szOutStr);
#endif
		strcat_s(strBuf, strBufSize-1, "\n");
		return currCurrHour;
	}
public:
	int logoutA(
		const int channel, 
		const char *file, 
		const char *func, 
		const int line,
		const char *userdata, 
		const int level, 
		const char *format,
		va_list marker)
	{
		if(!isNeedLog(level))
		{
			return 0;
		}
		char currLogStrA[LOG_STRMAXSIZE] = {0};
		int currCurHour = log_getStrA(channel, file, func, line, userdata, level, 
			format, marker, currLogStrA, LOG_STRMAXSIZE);
		wchar_t currLogStr[LOG_STRMAXSIZE] = {0};
		strToWStr(currLogStr, LOG_STRMAXSIZE-1, currLogStrA);
		return logWrite(level, currLogStr, currCurHour);		
	}
#endif
};

#ifdef WIN32
const WORD
#else
const GCHAR *
#endif
	Log::COLORS[LOG_DEBUGEX+1] = 
{	
	SEQ_DEFAULT_COLOR,  
	SEQ_FRED,
	SEQ_FMAGEN, 
	SEQ_FYELLOW,
};

const GCHAR *Log::LEVELS[LOG_DEBUGEX+1] = 
{	
	G("CONSOLE"), 
	G("ERR    "), 
	G("WARNING"), 
	G("DEBUG  "), 
};


int Log::g_sessionTypeNum = 0;
GCHAR Log::g_sessionTypeStrs[SNTYPE_MAX][SNSTR_MAX];

Log Log::g_log;

int Log_init(const int level, 
			const int device,
			const int modid,
			GCHAR *const filepath,
			GCHAR *const flagStr)
{
	return Log::GLog()->init(level, device, modid, filepath, flagStr);
}

int Log_unInit()
{
	return Log::GLog()->unInit();
}

int Log_setParams(const int level, const int device)
{
	return Log::GLog()->setParams(level, device);
}

int Log_setSessionType(GCHAR sessionTypeStrs[][SNSTR_MAX], const int sessionTypeNum)
{
	if(!sessionTypeStrs || sessionTypeNum < 0)
	{
		return -1;
	}
	return Log::log_setSessionType(sessionTypeStrs, sessionTypeNum);
}


void Log_str(int level, const GCHAR *data, int len)
{
	const int currLevel = Log::getLevel(level);
	if(!Log::GLog()->isNeedLog(currLevel))
	{
		return ;
	}
	Log::GLog()->logWrite(currLevel, (GCHAR*const)data);
}

int Log_list(const int channel, 
			const GCHAR *file, 
			const GCHAR *func, 
			const int line,
			const GCHAR *userdata, 
			const int level, 
			const GCHAR *format,
			va_list marker)
{
	if(!Log::GLog()->isNeedLog(level))
	{
		return 0;
	}
	return Log::GLog()->logout(channel, file, func, line, userdata, level, format, marker);
}

int Log_out(const int channel, 
			const GCHAR *file, 
			const GCHAR *func, 
			const int line,
			const GCHAR *userdata, 
			const int level, 
			const GCHAR *fmt, ...)
{
	if(!Log::GLog()->isNeedLog(level))
	{
		return 0;
	}
	int ret = 0;
	va_list marker;
	va_start(marker, fmt);
	ret = Log::GLog()->logout(channel, file, func, line, userdata, level, fmt, marker);
	va_end(marker);
	return ret;
}

int Log_session(const int channel, 
							const GCHAR *file, 
							const GCHAR *func, 
							const int line,
							const int type, 
							const int level, 
							const GCHAR *fmt, ...)
{
	if(!Log::GLog()->isNeedLog(level))
	{
		return 0;
	}
	int ret = 0;
	va_list marker;
	va_start(marker, fmt);
	ret = Log::GLog()->logout(channel, file, func, line, Log::getSessionTypeStr(type), level, fmt, marker);
	va_end(marker);
	return ret;
}


#ifdef _UNICODE
const char *Log::LEVELSA[LOG_DEBUGEX+1] = 
{	
	"CONSOLE", 
	"ERR    ", 
	"WARNING", 
	"DEBUG  ", 
};

void Log_strA(int level, const char *data, int len)
{
	const int currLevel = Log::getLevel(level);
	if(!Log::GLog()->isNeedLog(currLevel))
	{
		return ;
	}
	wchar_t currLogStr[Log::LOG_STRMAXSIZE] = {0};
	Log::strToWStr(currLogStr, Log::LOG_STRMAXSIZE-1, (char*)data);
	Log::GLog()->logWrite(currLevel, (GCHAR*const)currLogStr);
}

int Log_listA(const int channel, 
			 const char *file, 
			 const char *func, 
			 const int line,
			 const char *userdata, 
			 const int level, 
			 const char *format,
			 va_list marker)
{
	if(!Log::GLog()->isNeedLog(level))
	{
		return 0;
	}
	return Log::GLog()->logoutA(channel, file, func, line, userdata, level, format, marker);
}

int Log_outA(const int channel, 
			const char *file, 
			const char *func, 
			const int line,
			const char *userdata, 
			const int level, 
			const char *fmt, ...)
{
	if(!Log::GLog()->isNeedLog(level))
	{
		return 0;
	}
	int ret = 0;
	va_list marker;
	va_start(marker, fmt);
	ret = Log::GLog()->logoutA(channel, file, func, line, userdata, level, fmt, marker);
	va_end(marker);
	return ret;
}

int Log_sessionA(const int channel, 
				const char *file, 
				const char *func, 
				const int line,
				const int type, 
				const int level, 
				const char *fmt, ...)
{
	if(!Log::GLog()->isNeedLog(level))
	{
		return 0;
	}
	int ret = 0;
	va_list marker;
	va_start(marker, fmt);
	char typeStr[SNSTR_MAX+SNSTR_MAX] = {0};
	Log::log_getSessionTypeStrA(type, typeStr, SNSTR_MAX+SNSTR_MAX);
	ret = Log::GLog()->logoutA(channel, file, func, line, typeStr, level, fmt, marker);
	va_end(marker);
	return ret;
}

#endif