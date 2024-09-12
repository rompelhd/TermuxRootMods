#include <iostream>
#include <fstream>
#include <sstream>
#include <vector>
#include <string>
#include <cstdlib>
#include <cstdio>
#include <sys/types.h>
#include <unistd.h>
#include <algorithm>
#include <iomanip>

void check_root() {
    if (geteuid() != 0) {
        std::cerr << "You need root privileges to run this program. Exiting..." << std::endl;
        exit(EXIT_FAILURE);
    }
}

//  execution `dumpsys -l`
std::vector<std::string> get_services() {
    std::vector<std::string> services;
    FILE* pipe = popen("dumpsys -l", "r");
    if (!pipe) {
        std::cerr << "Failed to run dumpsys command." << std::endl;
        exit(EXIT_FAILURE);
    }

    char buffer[256];
    while (fgets(buffer, sizeof(buffer), pipe) != nullptr) {
        std::string line(buffer);
        if (!line.empty() && line.find_first_not_of(" \t\n\r") != std::string::npos) {
            line.erase(line.find_last_not_of("\n\r") + 1);
            services.push_back(line);
        }
    }
    pclose(pipe);

    return services;
}

void list_services(bool show_all) {
    std::vector<std::string> services = get_services();

    std::sort(services.begin(), services.end(), [](const std::string& a, const std::string& b) {
        return a.size() < b.size();
    });

    const size_t terminal_width = 80; // size

    const size_t max_length = terminal_width / 4;
    size_t current_column = 0;

    for (const auto& service : services) {
        std::string truncated_service = service;
        if (truncated_service.size() > max_length) {
            if (show_all) {
                std::cout << std::left << std::setw(max_length + 2) << service;
            } else {
                truncated_service = truncated_service.substr(0, max_length - 3) + "...";
                std::cout << std::left << std::setw(max_length + 2) << truncated_service;
            }
        } else {
            std::cout << std::left << std::setw(max_length + 2) << service;
        }

        current_column++;
        if (current_column >= 4) {
            std::cout << std::endl;
            current_column = 0;
        }
    }

    if (current_column > 0) {
        std::cout << std::endl;
    }
}

void show_service_info(const std::string& service_name) {
    if (service_name.empty()) {
        std::cerr << "Please provide a service name to show details." << std::endl;
        return;
    }

    std::string command = "dumpsys " + service_name;
    FILE* pipe = popen(command.c_str(), "r");
    if (!pipe) {
        std::cerr << "Failed to run dumpsys command for service: " << service_name << std::endl;
        return;
    }

    char buffer[256];
    while (fgets(buffer, sizeof(buffer), pipe) != nullptr) {
        std::cout << buffer;
    }
    pclose(pipe);
}

int main(int argc, char* argv[]) {
    check_root();

    bool show_all = false;
    std::string service_name;

    for (int i = 1; i < argc; ++i) {
        std::string arg(argv[i]);
        if (arg == "-all") {
            show_all = true;
        } else {
            service_name = arg;
        }
    }

    if (service_name.empty()) {
        list_services(show_all);
        std::cout << "Usage: " << argv[0] << " [-all] [service_name]" << std::endl;
    } else if (service_name == "--help") {
        std::cout << "Usage: " << argv[0] << " [-all] [service_name]" << std::endl;
        std::cout << "Options:" << std::endl;
        std::cout << "  -all          Show all services, including those with long names." << std::endl;
        std::cout << "  service_name  Display details of the specified service" << std::endl;
        std::cout << "  --help        Show this help message" << std::endl;
    } else {
        show_service_info(service_name);
    }

    return EXIT_SUCCESS;
}
