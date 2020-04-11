/*
 * Copyright:	All rights reserved, 2020.1. -- 2030.1.
 * Author:		QinDB.
 * Date:		2020-2-21
 * Description:	日志类(POCO中日志的封装)实现。
 */

#include "QDBLogger.h"
#include "Poco/ConsoleChannel.h"
#include "Poco/FormattingChannel.h"
#include "Poco/SplitterChannel.h"
#include "Poco/PatternFormatter.h"
#include "Poco/AutoPtr.h"
#include "Poco/FileChannel.h"
#include "Poco/LocalDateTime.h"
#include "Poco/Message.h"

using Poco::FormattingChannel;
using Poco::PatternFormatter;
using Poco::SplitterChannel;
using Poco::AutoPtr;
using Poco::FileChannel;
using Poco::LocalDateTime;
using Poco::Message;

static const size_t s_buf_size = 4096;

#define PROCESS_FMT_STRING(pDesc, szTmp) \
{ \
    char cTmp[s_buf_size + 1] = { 0 };\
    va_list ap;\
    va_start(ap, pDesctription);\
    int ret = _vsnprintf(cTmp, s_buf_size, pDesctription, ap);\
    if (ret < 0)\
    {\
        cTmp[s_buf_size] = '\0';\
    }\
    va_end(ap);\
    szTmp = cTmp;\
}

namespace QinDBUtil 
{
    namespace LogHelper
    {
        ////////////////////////////////////////////////////////////
        // class EasyLogger
        EasyLogger::EasyLogger()
            : use_console_ch_(false)
            , logger_name_("EBS_MODULE")
            , log_file_name_("EBS_M_RUN.log")
            , mod_name_("模块名:")
            , my_logger_(nullptr)
        {
            try
            {
                initLogger();
            }
            catch (...)
            {
                DebugPrintf(_T("初始化Poco的日志模块失败，系统将无法记录日志!\n"));
            }
        }

        void EasyLogger::trace(const char* file, int line, const char* pDesctription, ...)
        {
            if (my_logger_ == nullptr)
                return;

            std::string sztmp;
            PROCESS_FMT_STRING(pDesctription, sztmp);
            my_logger_->trace(sztmp, file, line);
        }

        void EasyLogger::trace(const std::string& szModName, const char* file, int line, const char* pDesctription, ...)
        {
            if (my_logger_ == nullptr)
                return;

            std::string sztmp;
            PROCESS_FMT_STRING(pDesctription, sztmp);

            Poco::Message msg(my_logger_->name(), sztmp, Message::PRIO_TRACE, file, line);
            msg.set(mod_name_, szModName);

            my_logger_->log(msg);
        }

        void EasyLogger::debug(const char* file, int line, const char* pDesctription, ...)
        {
            if (my_logger_ == nullptr)
                return;

            std::string sztmp;
            PROCESS_FMT_STRING(pDesctription, sztmp);
            my_logger_->debug(sztmp, file, line);
        }

        void EasyLogger::debug(const std::string& szModName, const char* file, int line, const char* pDesctription, ...)
        {
            if (my_logger_ == nullptr)
                return;

            std::string sztmp;
            PROCESS_FMT_STRING(pDesctription, sztmp);

            Poco::Message msg(my_logger_->name(), sztmp, Message::PRIO_DEBUG, file, line);
            msg.set(mod_name_, szModName);

            my_logger_->log(msg);
        }

        void EasyLogger::information(const char* file, int line, const char* pDesctription, ...)
        {
            if (my_logger_ == nullptr)
                return;

            std::string sztmp;
            PROCESS_FMT_STRING(pDesctription, sztmp);
            my_logger_->information(sztmp, file, line);
        }

        void EasyLogger::information(const std::string& szModName, const char* file, int line, const char* pDesctription, ...)
        {
            if (my_logger_ == nullptr)
                return;

            std::string sztmp;
            PROCESS_FMT_STRING(pDesctription, sztmp);

            Poco::Message msg(my_logger_->name(), sztmp, Message::PRIO_INFORMATION, file, line);
            msg.set(mod_name_, szModName);

            my_logger_->log(msg);
        }

        void EasyLogger::warning(const char* file, int line, const char* pDesctription, ...)
        {
            if (my_logger_ == nullptr)
                return;

            std::string sztmp;
            PROCESS_FMT_STRING(pDesctription, sztmp);
            my_logger_->warning(sztmp, file, line);
        }

        void EasyLogger::warning(const std::string& szModName, const char* file, int line, const char* pDesctription, ...)
        {
            if (my_logger_ == nullptr)
                return;

            std::string sztmp;
            PROCESS_FMT_STRING(pDesctription, sztmp);

            Poco::Message msg(my_logger_->name(), sztmp, Message::PRIO_WARNING, file, line);
            msg.set(mod_name_, szModName);

            my_logger_->log(msg);
        }

        void EasyLogger::error(const char* file, int line, const char* pDesctription, ...)
        {
            if (my_logger_ == nullptr)
                return;

            std::string sztmp;
            PROCESS_FMT_STRING(pDesctription, sztmp);
            my_logger_->error(sztmp, file, line);
        }

        void EasyLogger::error(const std::string& szModName, const char* file, int line, const char* pDesctription, ...)
        {
            if (my_logger_ == nullptr)
                return;

            std::string sztmp;
            PROCESS_FMT_STRING(pDesctription, sztmp);

            Poco::Message msg(my_logger_->name(), sztmp, Message::PRIO_ERROR, file, line);
            msg.set(mod_name_, szModName);

            my_logger_->log(msg);
        }

        void EasyLogger::critical(const char* file, int line, const char* pDesctription, ...)
        {
            if (my_logger_ == nullptr)
                return;

            std::string sztmp;
            PROCESS_FMT_STRING(pDesctription, sztmp);
            my_logger_->critical(sztmp, file, line);
        }

        void EasyLogger::critical(const std::string& szModName, const char* file, int line, const char* pDesctription, ...)
        {
            if (my_logger_ == nullptr)
                return;

            std::string sztmp;
            PROCESS_FMT_STRING(pDesctription, sztmp);

            Poco::Message msg(my_logger_->name(), sztmp, Message::PRIO_CRITICAL, file, line);
            msg.set(mod_name_, szModName);

            my_logger_->log(msg);
        }

        void EasyLogger::fatal(const char* file, int line, const char* pDesctription, ...)
        {
            if (my_logger_ == nullptr)
                return;

            std::string sztmp;
            PROCESS_FMT_STRING(pDesctription, sztmp);
            my_logger_->fatal(sztmp, file, line);
        }

        void EasyLogger::fatal(const std::string& szModName, const char* file, int line, const char* pDesctription, ...)
        {
            if (my_logger_ == nullptr)
                return;

            std::string sztmp;
            PROCESS_FMT_STRING(pDesctription, sztmp);

            Poco::Message msg(my_logger_->name(), sztmp, Message::PRIO_FATAL, file, line);
            msg.set(mod_name_, szModName);

            my_logger_->log(msg);
        }

        void EasyLogger::initLogger()
        {
            // 1.获取 root logge
            auto& r_logger = Poco::Logger::root();

            // 2.设置管道 
            if (use_console_ch_)
            {
                // 2.1 创建控制台管道 
                Poco::AutoPtr<Poco::ConsoleChannel> console_channel(new Poco::ConsoleChannel);

                // 2.2 创建文件管道
                AutoPtr<FileChannel> file_channel(new FileChannel);
                file_channel->setProperty("rotation", "10M");   //日志文件的旋转模式
                file_channel->setProperty("archive", "timestamp");  //日志文件的归档模式
                file_channel->setProperty("path", log_file_name_);

                // 2.3 创建 Formatter;// 关于格式化控制符的说明可以参见 PatternFormatter.h 中的描述
                Poco::AutoPtr<Poco::PatternFormatter> patternFormatter(
                    new Poco::PatternFormatter("[%Y-%m-%d  %H:%M:%S] [%s] [%U(%u)] %p: %t"));

                patternFormatter->setProperty("times", "local");  // 格式化中的时间显示为本地时间

                // 2.4 创建 SplitterChannel
                AutoPtr<SplitterChannel> splitter_Channel(new SplitterChannel);
                splitter_Channel->addChannel(file_channel);
                splitter_Channel->addChannel(console_channel);

                // 2.5 创建 Formatting Channel
                Poco::AutoPtr<Poco::FormattingChannel> formattingChannel(
                    new Poco::FormattingChannel(patternFormatter, splitter_Channel));

                // 2.6 将 Formatting Channel 设置给 root logger
                r_logger.setChannel(formattingChannel);
            }
            else
            {
                // 2.1 创建文件管道
                AutoPtr<FileChannel> file_channel(new FileChannel);
                file_channel->setProperty("rotation", "10M");   //日志文件的旋转模式
                file_channel->setProperty("archive", "timestamp");  //日志文件的归档模式
                file_channel->setProperty("path", log_file_name_);

                // 2.2 创建 Formatter;// 关于格式化控制符的说明可以参见 PatternFormatter.h 中的描述
                Poco::AutoPtr<Poco::PatternFormatter> patternFormatter(
                    new Poco::PatternFormatter("[%Y-%m-%d  %H:%M:%S] [%s] [%U(%u)] %p: %t"));

                patternFormatter->setProperty("times", "local");  // 格式化中的时间显示为本地时间

                // 2.3 创建 Formatting Channel
                Poco::AutoPtr<Poco::FormattingChannel> formattingChannel(
                    new Poco::FormattingChannel(patternFormatter, file_channel));

                // 2.4 将 Formatting Channel 设置给 root logger
                r_logger.setChannel(formattingChannel);
            }

            // 3. 获取本地使用的日志对象
            my_logger_ = &Poco::Logger::get(logger_name_);

            // 4.打印日志
            my_logger_->information("Poco 日志对象创建完成!", __FILE__, __LINE__);
        }

    } // namespace LogHelper
} // namespace QinDBUtil
