#include "Log.hpp"

HANDLE hFile;

void LogTime(string* log, DWORD lastError)
{
	time_t _time = time(NULL);

	tm ltm;
	ZeroMemory(&ltm, sizeof(ltm));

	localtime_s(&ltm, &_time);

	log->append("[");

	if (ltm.tm_mday < 10)
		log->append("0");

	log->append(to_string(ltm.tm_mday));

	log->append(".");

	if (1 + ltm.tm_mon < 10)
		log->append("0");

	log->append(to_string(1 + ltm.tm_mon));

	log->append(".");

	log->append(to_string(1900 + ltm.tm_year));

	log->append(" ");

	if (ltm.tm_hour < 10)
		log->append("0");

	log->append(to_string(ltm.tm_hour));

	log->append(":");

	if (ltm.tm_min < 10)
		log->append("0");

	log->append(to_string(ltm.tm_min));

	log->append(":");

	if (ltm.tm_sec < 10)
		log->append("0");

	log->append(to_string(ltm.tm_sec));

	log->append(" LastError: ");

	log->append(to_string(lastError));

	if (lastError)
	{
		log->append("(");

		// Retrieve the system error message for the last-error code

		LPVOID lpMsgBuf;

		FormatMessageA(
			FORMAT_MESSAGE_ALLOCATE_BUFFER |
			FORMAT_MESSAGE_FROM_SYSTEM |
			FORMAT_MESSAGE_IGNORE_INSERTS,
			NULL,
			lastError,
			MAKELANGID(LANG_ENGLISH, SUBLANG_DEFAULT),
			(LPSTR)&lpMsgBuf,
			0, NULL);

		for (size_t i = 0; i < LocalSize(lpMsgBuf); i++)
			if (((LPSTR)lpMsgBuf)[i] == '\n'
				|| ((LPSTR)lpMsgBuf)[i] == '\r')
				((LPSTR)lpMsgBuf)[i] = 0x00;

		log->append((LPSTR)lpMsgBuf);

		log->append(")");

		LocalFree(lpMsgBuf);
	}

	log->append("] ");

	return;
}

/*void Log(const char* text)
{
	size_t nocConverted;

	wchar_t* pwText = new wchar_t[strlen(text) + 1];
	ZeroMemory(pwText, sizeof(pwText));

	mbstowcs_s(&nocConverted, pwText, strlen(text) + 1, text, strlen(text));

	Log(text);

	delete[] pwText;

	return;
}*/

void Log(const char* text)
{
	DWORD lastError = GetLastError();

	wchar_t path[MAX_PATH];
	if (!GetCurDir(path, MAX_PATH))
		return;

	std::wstring fullpath(path);
	fullpath.append(L"\\error.log");

	if (!hFile
		|| hFile == INVALID_HANDLE_VALUE)
	{
		hFile = CreateFileW(fullpath.c_str(), FILE_APPEND_DATA, FILE_SHARE_READ, 0, OPEN_ALWAYS, FILE_ATTRIBUTE_NORMAL, 0);
		if (hFile == INVALID_HANDLE_VALUE)
			return;
	}

	std::string log;

	LogTime(&log, lastError);

	log.append(text);
	
	log.append("\n");

	WriteFile(hFile, log.c_str(), log.size(), 0, 0);

	return;
}