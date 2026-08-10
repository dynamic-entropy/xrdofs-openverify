#include <cstdlib>
#include <fstream>
#include <iostream>
#include <sstream>
#include <string>
#include <unistd.h>

#include "OpenVerifyFailureLog.hh"
#include "XrdSys/XrdSysError.hh"
#include "XrdSys/XrdSysLogger.hh"

namespace {

int g_failures = 0;

void Expect(bool cond, const std::string& msg) {
    if (!cond) {
        ++g_failures;
        std::cerr << "FAIL: " << msg << "\n";
    }
}

OpenVerifyFailureRecord SampleRecord() {
    OpenVerifyFailureRecord rec;
    rec.source = "rucio";
    rec.attempt = 2;
    rec.host = "cms-xrd.example.edu";
    rec.port = 1094;
    rec.path = "/store/data/file.root";
    rec.pfn = "root://cms-xrd.example.edu:1094//store/data/file.root";
    rec.protocol = "root";
    rec.stage = "open";
    rec.reason = "socket_timeout";
    rec.status_code = 103;
    rec.err_no = 0;
    rec.detail = "[ERROR] Socket timeout";
    return rec;
}

void Test_EscapeValuePlain() {
    Expect(OpenVerifyFailureLog::EscapeValue("abc") == "abc", "EscapeValuePlain: plain value unchanged");
    Expect(OpenVerifyFailureLog::EscapeValue("a/b.c") == "a/b.c", "EscapeValuePlain: path-like unchanged");
}

void Test_EscapeValueQuoted() {
    Expect(OpenVerifyFailureLog::EscapeValue("a b") == "\"a b\"", "EscapeValueQuoted: space");
    Expect(OpenVerifyFailureLog::EscapeValue("a=b") == "\"a=b\"", "EscapeValueQuoted: equals");
    Expect(OpenVerifyFailureLog::EscapeValue("say \"hi\"") == "\"say \\\"hi\\\"\"", "EscapeValueQuoted: quotes");
    Expect(OpenVerifyFailureLog::EscapeValue("a\nb") == "\"a\\nb\"", "EscapeValueQuoted: newline");
    Expect(OpenVerifyFailureLog::EscapeValue("") == "\"\"", "EscapeValueQuoted: empty");
}

void Test_FormatRecordFields() {
    const auto line = OpenVerifyFailureLog::FormatRecord(SampleRecord());
    Expect(line.find("openverify_failure") == 0, "FormatRecordFields: prefix");
    Expect(line.find(" source=rucio") != std::string::npos, "FormatRecordFields: source=rucio");
    Expect(line.find(" attempt=2") != std::string::npos, "FormatRecordFields: attempt");
    Expect(line.find(" host=cms-xrd.example.edu") != std::string::npos, "FormatRecordFields: host");
    Expect(line.find(" port=1094") != std::string::npos, "FormatRecordFields: port");
    Expect(line.find(" path=/store/data/file.root") != std::string::npos, "FormatRecordFields: path");
    Expect(line.find(" pfn=root://cms-xrd.example.edu:1094//store/data/file.root") != std::string::npos,
           "FormatRecordFields: pfn");
    Expect(line.find(" protocol=root") != std::string::npos, "FormatRecordFields: protocol");
    Expect(line.find(" stage=open") != std::string::npos, "FormatRecordFields: stage");
    Expect(line.find(" reason=socket_timeout") != std::string::npos, "FormatRecordFields: reason");
    Expect(line.find(" status_code=103") != std::string::npos, "FormatRecordFields: status_code");
    Expect(line.find(" err_no=0") != std::string::npos, "FormatRecordFields: err_no");
    Expect(line.find(" detail=\"[ERROR] Socket timeout\"") != std::string::npos, "FormatRecordFields: detail");
}

void Test_FormatRecordCmsdVsRucio() {
    auto cmsd = SampleRecord();
    cmsd.source = "cmsd";
    cmsd.attempt = 1;
    cmsd.stage = "vector_read";
    cmsd.reason = "not_found";
    const auto line = OpenVerifyFailureLog::FormatRecord(cmsd);
    Expect(line.find(" source=cmsd") != std::string::npos, "FormatRecordCmsdVsRucio: source=cmsd");
    Expect(line.find(" source=rucio") == std::string::npos, "FormatRecordCmsdVsRucio: not rucio");
    Expect(line.find(" stage=vector_read") != std::string::npos, "FormatRecordCmsdVsRucio: stage");
    Expect(line.find(" reason=not_found") != std::string::npos, "FormatRecordCmsdVsRucio: reason");
}

void Test_FormatRecordDefaults() {
    OpenVerifyFailureRecord rec;
    const auto line = OpenVerifyFailureLog::FormatRecord(rec);
    Expect(line.find(" source=unknown") != std::string::npos, "FormatRecordDefaults: source");
    Expect(line.find(" pfn=\"\"") != std::string::npos, "FormatRecordDefaults: empty pfn quoted");
    Expect(line.find(" protocol=unknown") != std::string::npos, "FormatRecordDefaults: protocol");
    Expect(line.find(" stage=unknown") != std::string::npos, "FormatRecordDefaults: stage");
    Expect(line.find(" reason=openverify_failure") != std::string::npos, "FormatRecordDefaults: reason");
}

void Test_SynthesizePfn() {
    Expect(OpenVerifyFailureLog::SynthesizePfn("root", "h.example.edu", 1094, "/store/a.root") ==
               "root://h.example.edu:1094//store/a.root",
           "SynthesizePfn: root double-slash path");
    Expect(OpenVerifyFailureLog::SynthesizePfn("http", "h.example.edu", 1094, "/store/a.root") ==
               "https://h.example.edu:1094/store/a.root",
           "SynthesizePfn: https");
    Expect(OpenVerifyFailureLog::SynthesizePfn("root", "h.example.edu", -1, "store/a.root") ==
               "root://h.example.edu//store/a.root",
           "SynthesizePfn: no port + normalize path");
}

void Test_DisabledWithoutEnv() {
    unsetenv("XRD_OPENVERIFY_FAILURE_LOG");
    XrdSysLogger logger(STDERR_FILENO, 0);
    XrdSysError daemon_log(&logger, "test");
    OpenVerifyFailureLog fail_log;
    fail_log.Configure(daemon_log);
    Expect(!fail_log.Enabled(), "DisabledWithoutEnv: should be disabled");
    // No-op when disabled.
    fail_log.Log(SampleRecord());
}

void Test_FileOutputScoped() {
    char tmpl[] = "/tmp/openverify_fail_log_XXXXXX";
    const int fd = mkstemp(tmpl);
    Expect(fd >= 0, "FileOutputScoped: mkstemp");
    if (fd < 0) return;
    close(fd);
    unlink(tmpl);  // Bind will create/open the path.

    setenv("XRD_OPENVERIFY_FAILURE_LOG", tmpl, 1);

    std::string contents;
    {
        XrdSysLogger logger(STDERR_FILENO, 0);
        XrdSysError daemon_log(&logger, "test");
        OpenVerifyFailureLog fail_log;
        fail_log.Configure(daemon_log);
        Expect(fail_log.Enabled(), "FileOutputScoped: enabled");
        fail_log.Log(SampleRecord());

        auto cmsd = SampleRecord();
        cmsd.source = "cmsd";
        cmsd.attempt = 1;
        cmsd.stage = "empty_file";
        cmsd.reason = "openverify_empty_file";
        cmsd.detail = "[ERROR] Data error";
        fail_log.Log(cmsd);
        // Destructor flushes/closes the bound log FD.
    }

    std::ifstream in(tmpl);
    Expect(static_cast<bool>(in), "FileOutputScoped: open for read");
    std::ostringstream buf;
    buf << in.rdbuf();
    contents = buf.str();
    unlink(tmpl);
    unsetenv("XRD_OPENVERIFY_FAILURE_LOG");

    Expect(contents.find("source=rucio") != std::string::npos, "FileOutputScoped: rucio line present");
    Expect(contents.find("source=cmsd") != std::string::npos, "FileOutputScoped: cmsd line present");
    Expect(contents.find("stage=open") != std::string::npos, "FileOutputScoped: open stage");
    Expect(contents.find("stage=empty_file") != std::string::npos, "FileOutputScoped: empty_file stage");
    Expect(contents.find("reason=socket_timeout") != std::string::npos, "FileOutputScoped: rucio reason");
    Expect(contents.find("reason=openverify_empty_file") != std::string::npos, "FileOutputScoped: empty reason");
    // Must not leak URL-like credential material from our FormatRecord API.
    Expect(contents.find("authz=") == std::string::npos, "FileOutputScoped: no authz");
    Expect(contents.find("xrd.ztn") == std::string::npos, "FileOutputScoped: no ztn");
    Expect(contents.find("Bearer ") == std::string::npos, "FileOutputScoped: no bearer");
}

}  // namespace

int main() {
    Test_EscapeValuePlain();
    Test_EscapeValueQuoted();
    Test_FormatRecordFields();
    Test_FormatRecordCmsdVsRucio();
    Test_FormatRecordDefaults();
    Test_SynthesizePfn();
    Test_DisabledWithoutEnv();
    Test_FileOutputScoped();

    if (g_failures != 0) {
        std::cerr << g_failures << " failure(s)\n";
        return 1;
    }
    std::cout << "OK\n";
    return 0;
}
