#include <iostream>
#include <string>
#include <curl/curl.h>
#include <cstdlib>
#include <fstream>
#include <vector>

const std::string configPath = "/data/data/com.termux/files/root-home/.config/TermuxRootMods/.trm";

const std::string banner = R"(
▗▄▄▄▖▗▄▄▄▖▗▄▄▖ ▗▖  ▗▖▗▖ ▗▖▗▖  ▗▖▗▄▄▖  ▗▄▖  ▗▄▖▗▄▄▄▖▗▖  ▗▖ ▗▄▖ ▗▄▄▄  ▗▄▄▖
  █  ▐▌   ▐▌ ▐▌▐▛▚▞▜▌▐▌ ▐▌ ▝▚▞▘ ▐▌ ▐▌▐▌ ▐▌▐▌ ▐▌ █  ▐▛▚▞▜▌▐▌ ▐▌▐▌  █▐▌
  █  ▐▛▀▀▘▐▛▀▚▖▐▌  ▐▌▐▌ ▐▌  ▐▌  ▐▛▀▚▖▐▌ ▐▌▐▌ ▐▌ █  ▐▌  ▐▌▐▌ ▐▌▐▌  █ ▝▀▚▖
  █  ▐▙▄▄▖▐▌ ▐▌▐▌  ▐▌▝▚▄▞▘▗▞▘▝▚▖▐▌ ▐▌▝▚▄▞▘▝▚▄▞▘ █  ▐▌  ▐▌▝▚▄▞▘▐▙▄▄▀▗▄▄▞▘
)";
const std::string URL = "https://raw.githubusercontent.com/rompelhd/TermuxRootMods/refs/heads/main/update.json";
const std::string Iversion = "v1.0.8";

size_t WriteCallback(void* contents, size_t size, size_t nmemb, void* userp) {
    ((std::string*)userp)->append((char*)contents, size * nmemb);
    return size * nmemb;
}

void ckroot() {
    if (geteuid() != 0) {
        std::cerr << "You must run this program as root." << std::endl;
        exit(EXIT_FAILURE);
    }
}

std::string fetchRemoteVersion() {
    CURL* curl;
    CURLcode res;
    std::string readBuffer;

    curl = curl_easy_init();
    if (curl) {
        curl_easy_setopt(curl, CURLOPT_URL, URL.c_str());
        curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, WriteCallback);
        curl_easy_setopt(curl, CURLOPT_WRITEDATA, &readBuffer);
        res = curl_easy_perform(curl);
        curl_easy_cleanup(curl);

        if (res == CURLE_OK) {

            size_t pos = readBuffer.find("\"version\":");
            if (pos != std::string::npos) {
                size_t start = readBuffer.find("\"", pos + 10) + 1;
                size_t end = readBuffer.find("\"", start);
                return readBuffer.substr(start, end - start);
            } else {
                std::cout << "Error: 'version' key not found in the JSON.\n";
            }
        } else {
            std::cout << "Error: Could not make the HTTP request. Error code: " << res << "\n";
        }
    }
    return "";
}

void checkVersion() {
    std::string remoteVersion = fetchRemoteVersion();
    if (remoteVersion.empty()) {
        std::cout << "Error: Could not fetch the remote version.\n";
        return;
    }
    if (Iversion == remoteVersion) {
        std::cout << "\nThe version is up to date. Current version: " << Iversion << "\n";
    } else {
        std::cout << "\nUpdate available: remote version " << remoteVersion
          << " (current version: " << Iversion << ")\n"
          << "To update, go to the Magisk app, in the modules section, "
          << "and perform the update from there.\n";
    }
}

std::string shell;
std::string theme_name;
std::string language;

void UpdateConfigVariable(const std::string& variable, const std::string& newValue) {
    std::ifstream fileIn(configPath);
    if (!fileIn) {
        std::cerr << "❌ Error: No se pudo abrir el archivo de configuración.\n";
        return;
    }

    std::vector<std::string> lines;
    std::string line;
    bool variableUpdated = false;

    while (std::getline(fileIn, line)) {
        if (line.find(variable + " =") == 0) {
            line = variable + " = " + newValue;
            variableUpdated = true;
        }
        lines.push_back(line);
    }
    fileIn.close();

    if (!variableUpdated) {
        lines.push_back(variable + " = " + newValue);
    }

    std::ofstream fileOut(configPath);
    if (!fileOut) {
        std::cerr << "❌ Error: No se pudo escribir en el archivo de configuración.\n";
        return;
    }

    for (const std::string& updatedLine : lines) {
        fileOut << updatedLine << "\n";
    }

    fileOut.close();
    std::cout << "✅ " << variable << " cambiado a: " << newValue << "\n";
}

void loadConfiguration(const std::string& configPath) {
    std::ifstream configFile(configPath);
    if (!configFile.is_open()) {
        std::cout << "Error: Unable to open configuration file.\n";
        return;
    }

    std::string line;
    std::string currentSection;

    while (std::getline(configFile, line)) {
        line.erase(0, line.find_first_not_of(" \t"));
        line.erase(line.find_last_not_of(" \t") + 1);

        if (line.empty() || line[0] == ';') {
            continue;
        }

        if (line[0] == '[' && line[line.size() - 1] == ']') {
            currentSection = line.substr(1, line.size() - 2);
        } else {
            size_t pos = line.find('=');
            if (pos != std::string::npos) {
                std::string key = line.substr(0, pos);
                std::string value = line.substr(pos + 1);

                key.erase(0, key.find_first_not_of(" \t"));
                key.erase(key.find_last_not_of(" \t") + 1);
                value.erase(0, value.find_first_not_of(" \t"));
                value.erase(value.find_last_not_of(" \t") + 1);

                if (currentSection == "SHELL") {
                    if (key == "shell") {
                        shell = value;
                    }
                } else if (currentSection == "THEME") {
                    if (key == "theme_name") {
                        theme_name = value;
                    }
                } else if (currentSection == "GENERAL") {
                    if (key == "language") {
                        language = value;
                    }
                }
            }
        }
    }

    configFile.close();
}

void ChangeTheme() {
    std::string currentShell = "/bin/bash";
    std::cout << "Select a theme for " << (currentShell == "/bin/bash" ? "Bash" : "Zsh") << ":\n\n";

    if (currentShell == "/bin/bash") {
        std::cout << "1) Without Oh My Bash\n";
        std::cout << "2) With Oh My Bash\n";
        std::cout << "\nSelect an option: ";
        int bashOption;
        std::cin >> bashOption;

        switch (bashOption) {
            case 1: {
                std::cout << "Choose a theme:\n";
                std::cout << "1) Termux Default theme -> \033[1;32m/root/ \033[1;37m# \033[0m\n";
                std::cout << "2) Colorful theme -> \033[1;32mroot@android\033[0m:\033[1;34m/root/\033[0m#\n";
                std::cout << "3) Minimalist theme -> \033[1;31m⚡\033[1;31mroot \033[1;33m@ \033[1;32mandroid \033[1;36min \033[1;34m/root/ \033[1;35m→ \033[0m\n";
                std::cout << "\nSelect an option: ";
                int themeOption;
                std::cin >> themeOption;

                switch (themeOption) {
                    case 1:
                        UpdateConfigVariable("theme_name", "default");
                        break;
                    case 2:
                        UpdateConfigVariable("theme_name", "colorful");
                        break;
                    case 3:
                        UpdateConfigVariable("theme_name", "minimalist");
                        break;
                    default:
                        std::cout << "Invalid option.\n";
                }
                break;
            }
            case 2:
                std::cout << "Theme changed to with Oh My Bash.\n";
                break;
            default:
                std::cout << "Invalid option.\n";
        }
    } else if (currentShell == "/bin/zsh") {
        std::cout << "1) Without Oh My Zsh\n";
        std::cout << "2) With Oh My Zsh\n";
        std::cout << "\nSelect an option: ";
        int zshOption;
        std::cin >> zshOption;

        switch (zshOption) {
            case 1: {
                std::cout << "Select a theme:\n";
                std::cout << "1) Termux Default theme -> \033[1;32m/root/ \033[1;37m# \033[0m\n";
                std::cout << "2) Colorful theme -> \033[1;32mroot@android\033[0m:\033[1;34m/root/\033[0m#\n";
                std::cout << "3) Minimalist theme -> \033[1;31m⚡ \033[1;31mroot \033[1;33m@ \033[1;32mandroid \033[1;36min \033[1;34m/root/ \033[1;35m→ \033[0m\n";
                std::cout << "\nSelect an option: ";
                int themeOption;
                std::cin >> themeOption;

                switch (themeOption) {
                    case 1:
                        std::cout << "Zsh theme changed to Termux Default.\n";
                        break;
                    case 2:
                        std::cout << "Zsh theme changed to Colorful.\n";
                        break;
                    case 3:
                        std::cout << "Zsh theme changed to Minimalist.\n";
                        break;
                    default:
                        std::cout << "Invalid option.\n";
                }
                break;
            }
            case 2:
                std::cout << "Zsh theme changed to with Oh My Zsh.\n";
                break;
            default:
                std::cout << "Invalid option.\n";
        }
    } else {
        std::cout << "Shell not compatible for theme change.\n";
    }
}

void editConfiguration() {
    std::cout << "Editing configuration using nano...\n";

    std::string configPath = "/data/data/com.termux/files/root-home/.config/TermuxRootMods/.trm";

    std::string command = "nano " + configPath;
    int result = system(command.c_str());

    if (result == 0) {
        std::cout << "Configuration edited successfully!\n";
    } else {
        std::cout << "Error: Unable to open nano or file path might be incorrect.\n";
    }
}

void showSettings() {
    std::cout << "\nCurrent settings:\n";
    std::cout << "\nScript version: " << Iversion << "\n";

    std::cout << "\n[SHELL]\n";
    std::cout << "\nshell = " << shell << "\n";

    std::cout << "\n[THEME]\n";
    std::cout << "\ntheme_name = " << theme_name << "\n";

    std::cout << "\n[GENERAL]\n";
    std::cout << "\nlanguage = " << language << "\n";
}

void pauseProgram() {
    std::cout << "\nPRESS ENTER to return to the menu.";
    std::cin.ignore(std::numeric_limits<std::streamsize>::max(), '\n'); // Clean buffer
    std::cin.get();
}

int main() {
    ckroot();
    while (true) {
        std::string configPath = "/data/data/com.termux/files/root-home/.config/TermuxRootMods/.trm";
        loadConfiguration(configPath);
        system("clear");
        std::cout << banner << "\n";
        std::cout << "\n";
        std::cout << "1) Check version\n";
        std::cout << "2) Change shell theme\n";
        std::cout << "3) Show config\n";
        std::cout << "4) Edit config\n";
        std::cout << "5) Exit\n";
        std::cout << "\nSelect an option: ";

        int option;
        std::cin >> option;

        switch (option) {
            case 1:
                checkVersion();
                pauseProgram();
                break;
            case 2:
                ChangeTheme();
                pauseProgram();
                break;
            case 3:
                showSettings();
                pauseProgram();
                break;
            case 4:
                editConfiguration();
                pauseProgram();
                break;
            case 5:
                std::cout << "Exiting !!!\n";
                return 0;
            default:
                std::cout << "Invalid option, please try again.\n";
                pauseProgram();
        }
        std::cout << "\n";
    }
}
