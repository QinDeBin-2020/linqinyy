/*
 * Copyright:	All rights reserved, 2020.1. -- 2030.1.
 * Author:		QinDB.
 * Date:		2020-1-27
 * Description:	一些共用的函数、类或模板等
 */

#pragma once

#include <type_traits>

#include <windows.h>
#include <Sddl.h>
#include <stdio.h>
#include <string.h>
#include <strsafe.h>

#include <eh.h> // for _set_se_translator
#include <DbgHelp.h>  // minidump
#include <tchar.h> // _T
#include <shellapi.h> // ShellExecute

#pragma comment(lib, "dbghelp.lib")  // minidump

namespace QinDBUtil
{

	/*
	 * 单例模式的模板基类；所有要实现单例模式的类可以继承此类。
	 */
	template<typename T>
	class Singleton
	{
	public:
		static T& get_instance() noexcept(std::is_nothrow_constructible<T>::value)
		{
			static T instance{ token() };
			return instance;
		}

		virtual ~Singleton() = default;
		Singleton(const Singleton&) = delete;
		Singleton& operator =(const Singleton&) = delete;

	protected:
		struct token {}; // helper class
		Singleton() noexcept = default;
	};

	/*
	 * 结构化异常SEH转换为c++标准异常的类定义
	 */
	class CSE
	{
	public:
		// call this function for each thread!
		static void MapSEtoCE()
		{
			_set_se_translator(TranslateSEtoCE);
		}

		operator DWORD()
		{
			return m_er.ExceptionCode;
		}
		DWORD GetExpCode()
		{
			return m_er.ExceptionCode;
		}

	private:
		CSE(PEXCEPTION_POINTERS pep)
		{
			m_er = *pep->ExceptionRecord;
			m_ctt = *pep->ContextRecord;
		}

		static void _cdecl TranslateSEtoCE(UINT dwEC, PEXCEPTION_POINTERS pep)
		{
			throw(CSE(pep));
		}

	private:
		EXCEPTION_RECORD	m_er;	// CPU independent exception information
		CONTEXT				m_ctt;	// CPU dependent exception information
	};

	// 是否已存在进程的实例; 参考：https://blog.csdn.net/cjf_iceking/article/details/7728008
	bool hasProcessInstance()
	{
		//创建边界描述符
		PCTSTR szBoundary = TEXT("QinDBForBoundary");
		HANDLE hBoundary = CreateBoundaryDescriptor(szBoundary, 0);

		//添加管理员组SID到边界描述符
		BYTE localAdminSID[SECURITY_MAX_SID_SIZE];
		PSID pLocalAdminSID = &localAdminSID;
		DWORD cbSID = sizeof(localAdminSID);
		if (!CreateWellKnownSid(WinBuiltinAdministratorsSid, NULL, pLocalAdminSID, &cbSID))
		{
			printf("CreateWellKnownSid Failed!\n");
			return false;
		}

		if (!AddSIDToBoundaryDescriptor(&hBoundary, pLocalAdminSID))
		{
			printf("AddSIDToBoundaryDescriptor Failed!\n");
			return false;
		}

		//产生安全信息
		SECURITY_ATTRIBUTES sa;
		sa.nLength = sizeof(sa);
		sa.bInheritHandle = FALSE;
		if (!ConvertStringSecurityDescriptorToSecurityDescriptor(TEXT("D:(A;;GA;;;BA)"),
			SDDL_REVISION_1, &sa.lpSecurityDescriptor, NULL))
		{
			printf("ConvertString Failed!\n");
			return false;
		}

		//创建专有命名空间 "TestForNamespace"
		PCTSTR szNamespace = TEXT("TestForNamespace");
		HANDLE hNamespace = CreatePrivateNamespace(&sa, hBoundary, szNamespace);
		if (hNamespace == NULL)
		{
			//这里没有进行处理，如果已经创建，可以打开专有命名空间
			//OpenPrivateNamespace API
			printf("CreatePrivateNamespace Failed!\n");
			return false;
		}
		LocalFree(sa.lpSecurityDescriptor);

		//创建锁
		TCHAR szMutexName[64];
		StringCchPrintf(szMutexName, _countof(szMutexName), TEXT("%s\\%s"), szNamespace, TEXT("TestForApp"));
		HANDLE g_hSingleton = CreateMutex(NULL, FALSE, szMutexName);
		if (GetLastError() == ERROR_ALREADY_EXISTS)
		{
			printf("应用程序实例已经启动！\n");
			return true;
		}

		return false;
	}

	/*
	 很多 C/C++ 程序会设置自己的 Unhandled Exception Filter 用于捕获 Unhandled exceptions 并输出一些信息（例如，
	 创建 mini-dump 或者输出调用栈到日志文件中）。
	 从 VC++2005 开始出于安全因素微软改变了 CRT 的行为。在以下情况下 CRT 不会通知被注册的 Unhandled Exception Filter：
	调用了 abort() 并且设置 abort 的行为为 _CALL_REPORTFAULT（Release 版本默认使用此设置）
	Security Checks 失败时，具体来说就是检查到一些会引发安全问题的堆栈溢出时不会通知被注册的 Unhandled Exception Filter，
	会引发安全问题的堆栈溢出包括：覆盖了函数的返回值，覆盖了 Exception handler 的地址，覆盖了某些类型的参数。
	关于编译器的 Security Checks 的内容，
	详细参考：http://msdn.microsoft.com/en-us/library/Aa290051（注意，此文章谈到的是 Visual Studio .NET 2003，
	其中 _set_security_error_handler 函数在 VC++2005 以及以上版本已经无法使用）
	如果没有调用 _set_invalid_parameter_handler 设置 Invalid parameter handler 时，检查到了非法的参数
	CRT 是通过何种方式使得我们注册的 Unhandled Exception Filter 不被调用的？答案在 CRT 的代码中：

	// 代码来源于 gs_report.c
	// Make sure any filter already in place is deleted.
	SetUnhandledExceptionFilter(NULL);
	UnhandledExceptionFilter(&ExceptionPointers);
	// CRT 通过调用 SetUnhandledExceptionFilter 并传递参数 NULL 来清除用户注册的 Unhandled Exception Filter。
	如果期望用户注册的 Unhandled Exception Filter 总是被调用那么应该避免 CRT 中相关的清理代码。
	做法之一就是修改 CRT 代码并且编译为静态库（微软的 VC++ Libraries 开发 Lead Martyn Lovell
	在 https ://connect.microsoft.com/feedback/ViewFeedback.aspx?FeedbackID=101337&SiteID=210 谈到过有关的问题），
	这里并不建议使用此做法。另外一种做法则是改变 SetUnhandledExceptionFilter 的行为，
	使得 CRT 对 SetUnhandledExceptionFilter 的调用不起任何作用（更加详细的论述可以参考《Windows 核心编程》相关章节）。
	 */

#ifndef _M_IX86
#error "The following code only works for x86!"
#endif

	 // 此函数一旦成功调用，之后对 SetUnhandledExceptionFilter 的调用将无效; 但此函数在X64上不能运行!
	void DisableSetUnhandledExceptionFilter()
	{
		WCHAR dll[] = L"kernel32.dll";
		void* addr = (void*)GetProcAddress(LoadLibrary(dll), "SetUnhandledExceptionFilter");

		if (addr)
		{
			unsigned char code[16];
			int size = 0;

			code[size++] = 0x33;
			code[size++] = 0xC0;
			code[size++] = 0xC2;
			code[size++] = 0x04;
			code[size++] = 0x00;

			DWORD dwOldFlag, dwTempFlag;
			VirtualProtect(addr, size, PAGE_READWRITE, &dwOldFlag);
			WriteProcessMemory(GetCurrentProcess(), addr, code, size, NULL);
			VirtualProtect(addr, size, dwOldFlag, &dwTempFlag);
		}
	}

	// 来自于：https://www.cnblogs.com/yifi/p/6610322.html
	/*
	 VEH：向量化异常处理程序(进程相关)
	 VCH：向量化异常处理程序，总是在最后调用（进程相关）
	 SEH：结构化异常处理程序，fs : [0]（线程相关）
	 UEF：TopLevalEH，基于SEH的

	 EH全称就是ExceptionHandler，中文意为异常处理器。
	 EH（异常处理程序）是做什么的呢，就是当程序发生一些错误、异常时，系统会保存好线程的CONTEXT（线程上下文）。
	 再交给EH来处理异常，有时候不仅仅是错误、异常。一些调试用的中断，异常处理程序也可以处理。比如int 1、int 3。
	 因为SEH的的头部被保存在TEB（fs : [0]），所以它是线程相关的。
	 UEF、VEH、VCH异常处理函数定义（UEF和VEH、VCH的函数类型名不一样，但是结构是一样的）：

	 UEF、VEH、VCH的异常处理函数调用约定是stdcall的，windows下的系统api、回调，基本都是stdcall的。
	 SEH的异常处理函数调用约定cdecl的。

		1. 第一次交给调试器(进程必须被调试)
		2. 执行VEH
		3. 执行SEH
		4. UEF(TopLevelEH 进程被调试时不会被执行)
		-->这里应该还有个VCH //对操作系统有要求 xp下没有
		5. 最后一次交给调试器(上面的异常处理都说处理不了，就再次交给调试器)
		6. 调用异常端口通知csrss.exe
	 */

	BOOL IsDataSectionNeeded(const WCHAR* pModuleName)
	{
		if (pModuleName == 0)
		{
			return FALSE;
		}
		WCHAR szFileName[_MAX_FNAME] = L"";
		_wsplitpath(pModuleName, NULL, NULL, szFileName, NULL);
		if (wcsicmp(szFileName, L"ntdll") == 0)
			return TRUE;
		return FALSE;
	}

	BOOL CALLBACK MiniDumpCallback(PVOID pParam,
		const PMINIDUMP_CALLBACK_INPUT   pInput,
		PMINIDUMP_CALLBACK_OUTPUT        pOutput)
	{
		if (pInput == 0 || pOutput == 0)
			return FALSE;
		switch (pInput->CallbackType)
		{
		case ModuleCallback:
			if (pOutput->ModuleWriteFlags & ModuleWriteDataSeg)
				if (!IsDataSectionNeeded(pInput->Module.FullPath))
					pOutput->ModuleWriteFlags &= (~ModuleWriteDataSeg);
		case IncludeModuleCallback:
		case IncludeThreadCallback:
		case ThreadCallback:
		case ThreadExCallback:
			return TRUE;
		default:;
		}
		return FALSE;
	}

	// 根据异常的信息，创建一个minidump的文件
	void CreateMiniDump(EXCEPTION_POINTERS* pep)
	{
		// Open the file 
		HANDLE hFile = CreateFile(_T("QinDBMiniDump.dmp"), GENERIC_READ | GENERIC_WRITE,
			0, NULL, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);

		if ((hFile != NULL) && (hFile != INVALID_HANDLE_VALUE))
		{
			// Create the minidump 
			MINIDUMP_EXCEPTION_INFORMATION mdei;

			mdei.ThreadId = GetCurrentThreadId();
			mdei.ExceptionPointers = pep;
			mdei.ClientPointers = FALSE;

			MINIDUMP_CALLBACK_INFORMATION mci;

			mci.CallbackRoutine = (MINIDUMP_CALLBACK_ROUTINE)MiniDumpCallback;
			mci.CallbackParam = 0;     // this example does not use the context

			MINIDUMP_TYPE mdt = MiniDumpNormal;

			BOOL rv = MiniDumpWriteDump(GetCurrentProcess(), GetCurrentProcessId(),
				hFile, mdt, (pep != 0) ? &mdei : 0, 0, &mci);

			if (!rv)
				_tprintf(_T("MiniDumpWriteDump failed. Error: %u \n"), GetLastError());
			else
				_tprintf(_T("Minidump created.\n"));

			// Close the file 
			CloseHandle(hFile);
		}
		else
		{
			_tprintf(_T("CreateFile failed. Error: %u \n"), GetLastError());
		}
	}

	//创建Dump文件
	void CreateMiniDump(EXCEPTION_POINTERS* pep, LPCTSTR strFileName)
	{
		HANDLE hFile = CreateFile(strFileName, GENERIC_WRITE, 0, NULL, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
		if ((hFile != NULL) && (hFile != INVALID_HANDLE_VALUE))
		{
			MINIDUMP_EXCEPTION_INFORMATION mdei;
			mdei.ThreadId = GetCurrentThreadId();
			mdei.ExceptionPointers = pep;
			mdei.ClientPointers = FALSE;

			MINIDUMP_CALLBACK_INFORMATION mci;
			mci.CallbackRoutine = (MINIDUMP_CALLBACK_ROUTINE)MiniDumpCallback;
			mci.CallbackParam = 0;
			MINIDUMP_TYPE mdt = (MINIDUMP_TYPE)0x0000ffff;

			MiniDumpWriteDump(GetCurrentProcess(), GetCurrentProcessId(), hFile, MiniDumpNormal, &mdei, NULL, &mci);
			CloseHandle(hFile);
		}
	}

	LPTOP_LEVEL_EXCEPTION_FILTER WINAPI MyDummySetUnhandledExceptionFilter(LPTOP_LEVEL_EXCEPTION_FILTER lpTopLevelExceptionFilter)
	{
		return NULL;
	}

	BOOL PreventSetUnhandledExceptionFilter()
	{
		HMODULE hKernel32 = LoadLibrary(_T("kernel32.dll"));
		if (hKernel32 == NULL)
			return FALSE;
		void* pOrgEntry = GetProcAddress(hKernel32, "SetUnhandledExceptionFilter");

		if (pOrgEntry == NULL)
			return FALSE;
		unsigned char newJump[100];
		DWORD dwOrgEntryAddr = (DWORD)pOrgEntry;
		dwOrgEntryAddr += 5; // add 5 for 5 op-codes for jmp far
		void* pNewFunc = &MyDummySetUnhandledExceptionFilter;
		DWORD dwNewEntryAddr = (DWORD)pNewFunc;
		DWORD dwRelativeAddr = dwNewEntryAddr - dwOrgEntryAddr;
		newJump[0] = 0xE9;  // JMP absolute
		memcpy(&newJump[1], &dwRelativeAddr, sizeof(pNewFunc));
		SIZE_T bytesWritten;
		BOOL bRet = WriteProcessMemory(GetCurrentProcess(), pOrgEntry, newJump, sizeof(pNewFunc) + 1, &bytesWritten);
		return bRet;
	}

	void AutomaticRunProcess(WCHAR* bat_name)
	{
		WCHAR operation[] = L"open";
		ShellExecute(NULL, operation, bat_name, NULL, NULL, SW_HIDE);
	}

	// 异常处理代码
	// EXCEPTION_EXECUTE_HANDLER equ 1 表示我已经处理了异常,可以优雅地结束了 
	// EXCEPTION_CONTINUE_SEARCH equ 0 表示我不处理,其他人来吧,于是windows调用默认的处理程序显示一个错误框,并结束 
	// EXCEPTION_CONTINUE_EXECUTION equ -1 表示错误已经被修复,请从异常发生处继续执行
	LONG WINAPI UnhandledExceptionFilterEx(struct _EXCEPTION_POINTERS* pException)
	{
		TCHAR szMbsFile[MAX_PATH] = { 0 };
		::GetModuleFileName(NULL, szMbsFile, MAX_PATH);
		TCHAR* pFind = _tcsrchr(szMbsFile, '\\');
		if (pFind)
		{
			*(pFind + 1) = 0;
			_tcscat(szMbsFile, _T("CreateMiniDump.dmp"));
			CreateMiniDump(pException, szMbsFile);
		}

		// 运行一个bat
		AutomaticRunProcess(L"daemon.bat");
		return EXCEPTION_CONTINUE_SEARCH;
	}

	// 运行异常处理
	void RunCrashHandler()
	{
		SetUnhandledExceptionFilter(UnhandledExceptionFilterEx);
		//	PreventSetUnhandledExceptionFilter();
	}
	/*
	 * 正则表达式规则：
	   ?匹配零次或一次前面的分组。
	 *匹配零次或多次前面的分组。
	 +匹配一次或多次前面的分组。
	 {n}匹配n 次前面的分组。
	 {n,}匹配n 次或更多前面的分组。
	 {,m}匹配零次到m 次前面的分组。
	 {n,m}匹配至少n 次、至多m 次前面的分组。
	 {n,m}?或*?或+?对前面的分组进行非贪心匹配。
	 ^spam 意味着字符串必须以spam 开始。
	 spam$意味着字符串必须以spam 结束。
	 .匹配所有字符，换行符除外。
	 \d、\w 和\s 分别匹配数字、单词和空格。
	 \D、\W 和\S 分别匹配出数字、单词和空格外的所有字符。
	 [abc]匹配方括号内的任意字符（诸如a、b 或c）。
	 [^abc]匹配不在方括号内的任意字符。
	 */

	// OutputDebugString函数的封装，便于程序的调试；支持UNICODE宽字符
	int  DebugPrintf(LPCTSTR ptzFormat, ...)
	{
#ifdef DBG_OUTPUT
		va_list vlArgs;
		const size_t buf_size = 4096;
		TCHAR tzText[buf_size];
		va_start(vlArgs, ptzFormat);

		//返回-1说明缓存不够 使用下面方式获取实际所需长度
		//int iRealSize= _vsntprintf(NULL,0, ptzFormat, vlArgs);
		int iRet = _vsntprintf(tzText, buf_size, ptzFormat, vlArgs);
		if (iRet < 0)
		{
			tzText[buf_size-1] = '\0';
		}
		OutputDebugString(tzText);
		va_end(vlArgs);
		return iRet;
#else
		return -1;
#endif
	}

} // QinDBUtil