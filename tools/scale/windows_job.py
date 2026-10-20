"""Harness only: assign a suspended child to a committed-memory-limited Job."""
import ctypes as c
from ctypes import wintypes as w


class IO(c.Structure):
    _fields_ = [(name, c.c_ulonglong) for name in ("ReadOperationCount", "WriteOperationCount", "OtherOperationCount", "ReadTransferCount", "WriteTransferCount", "OtherTransferCount")]


class Basic(c.Structure):
    _fields_ = [("PerProcessUserTimeLimit", c.c_longlong), ("PerJobUserTimeLimit", c.c_longlong),
                ("LimitFlags", w.DWORD), ("MinimumWorkingSetSize", c.c_size_t),
                ("MaximumWorkingSetSize", c.c_size_t), ("ActiveProcessLimit", w.DWORD),
                ("Affinity", c.c_size_t), ("PriorityClass", w.DWORD), ("SchedulingClass", w.DWORD)]


class Extended(c.Structure):
    _fields_ = [("BasicLimitInformation", Basic), ("IoInfo", IO), ("ProcessMemoryLimit", c.c_size_t),
                ("JobMemoryLimit", c.c_size_t), ("PeakProcessMemoryUsed", c.c_size_t), ("PeakJobMemoryUsed", c.c_size_t)]


class Job:
    def __init__(self, cap):
        self.api = c.WinDLL("kernel32", use_last_error=True)
        self.api.CreateJobObjectW.argtypes = [c.c_void_p, w.LPCWSTR]
        self.api.CreateJobObjectW.restype = w.HANDLE
        self.api.SetInformationJobObject.argtypes = [w.HANDLE, c.c_int, c.c_void_p, w.DWORD]
        self.api.AssignProcessToJobObject.argtypes = [w.HANDLE, w.HANDLE]
        self.api.QueryInformationJobObject.argtypes = [w.HANDLE, c.c_int, c.c_void_p, w.DWORD, c.c_void_p]
        self.api.CloseHandle.argtypes = [w.HANDLE]
        self.handle = self.api.CreateJobObjectW(None, None)
        if not self.handle:
            raise c.WinError(c.get_last_error())
        limits = Extended()
        limits.BasicLimitInformation.LimitFlags = 0x2000 | (0x200 if cap else 0)
        limits.JobMemoryLimit = cap
        if not self.api.SetInformationJobObject(self.handle, 9, c.byref(limits), c.sizeof(limits)):
            self.close()
            raise c.WinError(c.get_last_error())

    def assign_and_resume(self, process):
        if not self.api.AssignProcessToJobObject(self.handle, w.HANDLE(int(process._handle))):
            process.kill()
            raise c.WinError(c.get_last_error())
        native = c.WinDLL("ntdll")
        native.NtResumeProcess.argtypes = [w.HANDLE]
        native.NtResumeProcess.restype = c.c_long
        status = native.NtResumeProcess(w.HANDLE(int(process._handle)))
        if status != 0:
            process.kill()
            raise OSError("NtResumeProcess", status)

    def peak(self):
        info = Extended()
        if not self.api.QueryInformationJobObject(self.handle, 9, c.byref(info), c.sizeof(info), None):
            raise c.WinError(c.get_last_error())
        return info.PeakJobMemoryUsed

    def close(self):
        if self.handle:
            self.api.CloseHandle(self.handle)
            self.handle = None
