/*
 * Copyright:	All rights reserved, 2020.1. -- 2030.1.
 * Author:		QinDB.
 * Date:		2020-2-18
 * Description:	��־��(POCO����־�ķ�װ)���塢������־ʹ�õĺ�ȵĶ���ȡ�
 */

#pragma once

#include "Poco/Logger.h"
#include "CommonTools.h"
#include <string>

using Poco::Logger;


namespace QinDBUtil
{
    namespace LogHelper
    {
        //! ʹ��Poco::Loggerʵ�ֵı�����־�ࣻ��Pocoֻ֧��utf-8���룬���ⲿʹ�ÿ��ַ�ʱ����־��Ϣ����ת�������ʹ������Ľӿڡ�
        class EasyLogger : public Singleton<EasyLogger>
        {
            //! ��־�ӿں���
        public:
            void trace(const char* file, int line, const char* pDesctription, ...);
            void trace(const std::string& szModNameconst, const char* file, int line, const char* pDesctription, ...);

            void debug(const char* file, int line, const char* pDesctription, ...);
            void debug(const std::string& szModNameconst, const char* file, int line, const char* pDesctription, ...);

            void information(const char* file, int line, const char* pDesctription, ...);
            void information(const std::string& szModNameconst, const char* file, int line, const char* pDesctription, ...);

            void warning(const char* file, int line, const char* pDesctription, ...);
            void warning(const std::string& szModNameconst, const char* file, int line, const char* pDesctription, ...);

            void error(const char* file, int line, const char* pDesctription, ...);
            void error(const std::string& szModNameconst, const char* file, int line, const char* pDesctription, ...);

            void critical(const char* file, int line, const char* pDesctription, ...);
            void critical(const std::string& szModNameconst, const char* file, int line, const char* pDesctription, ...);

            void fatal(const char* file, int line, const char* pDesctription, ...);
            void fatal(const std::string& szModNameconst, const char* file, int line, const char* pDesctription, ...);

        protected:
            EasyLogger();
            virtual ~EasyLogger(void) {}

            void initLogger();
            std::string stringProcessFMT(const char* pDesctription, ...);

        private:
            bool        use_console_ch_;
            std::string logger_name_;
            std::string log_file_name_;
            std::string mod_name_;
            Poco::Logger* my_logger_;

        }; // EasyLogger

    } // LogHelper

} // QinDBUtil

namespace QLH = QinDBUtil::LogHelper;


//! ��־�ӿں궨�壻UTF-8�ַ���ʽ
//! ����1����ʽ���ַ���
#define ELOG_TRACE(fmt, ...)    QLH::EasyLogger::get_instance().trace(__FUNCTION__, __LINE__, fmt, __VA_ARGS__)

//! ����1: ģ������
//! ����2: ��ʽ���ַ���
#define ELOG_TRACE_M(modname, fmt, ...)    QLH::EasyLogger::get_instance().trace(modname, __FUNCTION__, __LINE__, fmt, __VA_ARGS__)

#define ELOG_DBG(fmt, ...)  QLH::EasyLogger::get_instance().debug(__FUNCTION__, __LINE__, fmt, __VA_ARGS__)
#define ELOG_DBG_M(modname, fmt, ...)  QLH::EasyLogger::get_instance().debug(modname, __FUNCTION__, __LINE__, fmt, __VA_ARGS__)

#define ELOG_INFO(fmt, ...)  QLH::EasyLogger::get_instance().information(__FUNCTION__, __LINE__, fmt, __VA_ARGS__)
#define ELOG_INFO_M(modname, fmt, ...)  QLH::EasyLogger::get_instance().information(modname, __FUNCTION__, __LINE__, fmt, __VA_ARGS__)

#define ELOG_WARNING(fmt, ...)  QLH::EasyLogger::get_instance().warning(__FUNCTION__, __LINE__, fmt, __VA_ARGS__)
#define ELOG_WARNING_M(modname, fmt, ...)  QLH::EasyLogger::get_instance().warning(modname, __FUNCTION__, __LINE__, fmt, __VA_ARGS__)

#define ELOG_ERROR(fmt, ...)  QLH::EasyLogger::get_instance().error(__FUNCTION__, __LINE__, fmt, __VA_ARGS__)
#define ELOG_ERROR_M(modname, fmt, ...)  QLH::EasyLogger::get_instance().error(modname, __FUNCTION__, __LINE__, fmt, __VA_ARGS__)

#define ELOG_CRITICAL(fmt, ...)  QLH::EasyLogger::get_instance().critical(__FUNCTION__, __LINE__, fmt, __VA_ARGS__)
#define ELOG_CRITICAL_M(modname, fmt, ...)  QLH::EasyLogger::get_instance().critical(modname, __FUNCTION__, __LINE__, fmt, __VA_ARGS__)

#define ELOG_FATAL(fmt, ...)  QLH::EasyLogger::get_instance().fatal(__FUNCTION__, __LINE__, fmt, __VA_ARGS__)
#define ELOG_FATAL_M(modname, fmt, ...)  QLH::EasyLogger::get_instance().fatal(modname, __FUNCTION__, __LINE__, fmt, __VA_ARGS__)
