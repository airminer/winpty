// Copyright (c) 2016 Ryan Prichard
//
// Permission is hereby granted, free of charge, to any person obtaining a copy
// of this software and associated documentation files (the "Software"), to
// deal in the Software without restriction, including without limitation the
// rights to use, copy, modify, merge, publish, distribute, sublicense, and/or
// sell copies of the Software, and to permit persons to whom the Software is
// furnished to do so, subject to the following conditions:
//
// The above copyright notice and this permission notice shall be included in
// all copies or substantial portions of the Software.
//
// THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
// IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
// FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
// AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
// LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING
// FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS
// IN THE SOFTWARE.

#include "AgentCreateDesktop.h"

#include "../shared/BackgroundDesktop.h"
#include "../shared/Buffer.h"
#include "../shared/DebugClient.h"
#include "../shared/StringBuilder.h"
#include "../shared/StringUtil.h"

#include "EventLoop.h"
#include "NamedPipe.h"

namespace {

static inline WriteBuffer newPacket() {
    WriteBuffer packet;
    packet.putRawValue<uint64_t>(0); // Reserve space for size.
    return packet;
}

class CreateDesktopLoop : public EventLoop {
public:
    CreateDesktopLoop(LPCWSTR controlPipeName);

protected:
    CreateDesktopLoop() : m_pipe(createNamedPipe()) {}
    virtual void onPipeIo(NamedPipe &namedPipe) override;
    void writePacket(WriteBuffer &packet);

    BackgroundDesktop m_desktop;
    NamedPipe &m_pipe;
};

CreateDesktopLoop::CreateDesktopLoop(LPCWSTR controlPipeName) :
        m_pipe(createNamedPipe()) {
    m_pipe.connectToServer(controlPipeName, NamedPipe::OpenMode::Duplex);
    auto packet = newPacket();
    packet.putWString(m_desktop.desktopName());
    writePacket(packet);
}

void CreateDesktopLoop::writePacket(WriteBuffer &packet) {
    const auto &bytes = packet.buf();
    packet.replaceRawValue<uint64_t>(0, bytes.size());
    m_pipe.write(bytes.data(), bytes.size());
}

void CreateDesktopLoop::onPipeIo(NamedPipe &namedPipe) {
    if (m_pipe.isClosed()) {
        shutdown();
    }
}

// Given a process and a handle in the current process,
// duplicate the handle into the process.
static inline HANDLE shareHandle(HANDLE process, HANDLE h) {
    HANDLE ret = nullptr;
    if (!DuplicateHandle(
        GetCurrentProcess(), h,
        process, &ret,
        0, FALSE, DUPLICATE_SAME_ACCESS)) {
        ASSERT(false && "DuplicateHandle failed!");
    }
    return ret;
}

// It's safe to truncate a handle from 64-bits to 32-bits, or to sign-extend it
// back to 64-bits.  See the MSDN article, "Interprocess Communication Between
// 32-bit and 64-bit Applications".
// https://msdn.microsoft.com/en-us/library/windows/desktop/aa384203.aspx
static int64_t int64FromHandle(HANDLE h) {
    return static_cast<int64_t>(reinterpret_cast<intptr_t>(h));
}

class RespawnLoop : public CreateDesktopLoop {
public:
    RespawnLoop(LPWSTR* argv);
};

RespawnLoop::RespawnLoop(LPWSTR* argv) {
    TRACE("Entering RespawnLoop");
    m_pipe.connectToServer(argv[1], NamedPipe::OpenMode::Duplex);
    PROCESS_INFORMATION pi = {};
    STARTUPINFOW sui = {};
    sui.cb = sizeof(sui);
    auto desktopNameV = vectorWithNulFromString(m_desktop.desktopName());
    sui.lpDesktop = desktopNameV.data();

    WStringBuilder cmdBuilder = WStringBuilder(256) << argv[0];
    for (int i = 3; i < 9; i++) {
        cmdBuilder << L" " << argv[i];
    }
    std::wstring cmdline = cmdBuilder.str_moved();
    auto cmdlineV = vectorWithNulFromString(cmdline);

    const BOOL success = CreateProcessW(argv[0],
        cmdlineV.data(),
        nullptr, nullptr,
        /*bInheritHandles=*/FALSE,
        /*dwCreationFlags=*/CREATE_NEW_CONSOLE,
        nullptr, nullptr,
        &sui, &pi);
    int64_t replyprocess = 0;
    if (success) {
        CloseHandle(pi.hThread);
        TRACE("Created agent successfully, pid=%u, cmdline=%s",
            static_cast<unsigned int>(pi.dwProcessId),
            utf8FromWide(cmdline).c_str());
        DWORD ppid = atoi(utf8FromWide(argv[4]).c_str());
        HANDLE parent = OpenProcess(PROCESS_DUP_HANDLE, FALSE, ppid);
        replyprocess = int64FromHandle(shareHandle(parent, pi.hProcess));
        CloseHandle(parent);
        CloseHandle(pi.hProcess);
    }
    auto packet = newPacket();
    packet.putInt64(replyprocess);
    writePacket(packet);
}
} // anonymous namespace

void handleCreateDesktop(LPCWSTR controlPipeName) {
    try {
        CreateDesktopLoop loop(controlPipeName);
        loop.run();
        trace("Agent exiting...");
    } catch (const WinptyException &e) {
        trace("handleCreateDesktop: internal error: %s",
            utf8FromWide(e.what()).c_str());
    }
}

void handleRespawnAdmin(LPWSTR* argv) {
    TRACE("Entering handleRespawnAdmin");
    try {
        RespawnLoop loop(argv);
        loop.run();
        trace("Agent exiting...");
    }
    catch (const WinptyException& e) {
        trace("handleRespawnAdmin: internal error: %s",
            utf8FromWide(e.what()).c_str());
    }
}
