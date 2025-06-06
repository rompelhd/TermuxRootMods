#include <iostream>
#include <fstream>
#include <sstream>
#include <iomanip>
#include <dirent.h>

const std::string THERMAL_DIR = "/sys/class/thermal/";

float read_temperature(const std::string& temp_file) {
    std::ifstream file(temp_file);
    float temp;
    if (file >> temp) {
        return temp / 1000;
    }
    return -1; // Error
}

void print_table() {
    std::cout << "+--------------------+-------------------+" << std::endl;
    std::cout << "| Type               | Temp (°C)         |" << std::endl;
    std::cout << "+--------------------+-------------------+" << std::endl;

    DIR* dir = opendir(THERMAL_DIR.c_str());
    if (dir == nullptr) {
        std::cerr << "Error: Unable to open thermal directory." << std::endl;
        return;
    }

    struct dirent* entry;
    while ((entry = readdir(dir)) != nullptr) {
        std::string name(entry->d_name);
        if (name.find("thermal_zone") != std::string::npos) {
            std::string type_file = THERMAL_DIR + name + "/type";
            std::string temp_file = THERMAL_DIR + name + "/temp";

            std::ifstream type_stream(type_file);
            std::string type;
            std::getline(type_stream, type);

            float temp = read_temperature(temp_file);
            if (temp >= 0) {
                std::cout << "| " << std::left << std::setw(18) << type << " | "
                          << std::left << std::setw(17) << std::fixed << std::setprecision(1) << temp
                          << " |" << std::endl;
            }
        }
    }
    closedir(dir);

    std::cout << "+--------------------+-------------------+" << std::endl;
}

int main() {
    print_table();
    return 0;
}
