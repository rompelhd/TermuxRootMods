#include <iostream>
#include <fstream>
#include <cstdlib>
#include <string>
#include <unistd.h>

int main() {
    std::string Home = "/data/data/com.termux/files/root-home";
    std::string Term = "xterm-256color";
    std::string AliasFile = "/sdcard/.aliases";
    std::string TempDir = "/data/data/com.termux/files/usr/tmp";
    std::string LD_LIBRARY_PATH = "/data/data/com.termux/files/usr/lib";
    std::string trm_config = "/data/data/com.termux/files/root-home/.config/TermuxRootMods/.trm";

    std::ifstream configFile(trm_config);
    std::string theme_name = "none";

    if (configFile) {
        std::string line, current_section;
        while (std::getline(configFile, line)) {
            line.erase(0, line.find_first_not_of(" \t\r\n"));
            line.erase(line.find_last_not_of(" \t\r\n") + 1);

            if (line.empty() || line[0] == ';' || line[0] == '#') continue;

            if (line.front() == '[' && line.back() == ']') {
                current_section = line.substr(1, line.size() - 2);
                continue;
            }

            size_t pos = line.find('=');
            if (pos != std::string::npos) {
                std::string key = line.substr(0, pos);
                std::string value = line.substr(pos + 1);

                key.erase(0, key.find_first_not_of(" \t"));
                key.erase(key.find_last_not_of(" \t") + 1);
                value.erase(0, value.find_first_not_of(" \t"));
                value.erase(value.find_last_not_of(" \t") + 1);

                std::string env_var;
                if (current_section == "SHELL" && key == "shell") {
                    env_var = "SHELL";
                } else if (current_section == "GENERAL" && key == "language") {
                    env_var = "GENERAL_LANGUAGE";
                } else if (current_section == "THEME" && key == "theme_name") {
                    env_var = "THEME_NAME";
                    theme_name = value;
                }

                if (!env_var.empty()) {
                    //std::cout << "Setting: " << env_var << "=" << value << std::endl;
                    setenv(env_var.c_str(), value.c_str(), 1);
                }
            }
        }
    }

    std::string Shell = std::getenv("SHELL") ? std::getenv("SHELL") : "/bin/sh";

    if (Shell == "zsh" || Shell == "bash" || Shell == "sh") {
        Shell = "/data/data/com.termux/files/usr/bin/" + Shell;
    }

    if (access(Shell.c_str(), X_OK) != 0) {
        std::cerr << "Error: El shell '" << Shell << "' no se encontró. Usando /bin/sh." << std::endl;
        Shell = "/bin/sh";
    }

    if (std::getenv("TMPDIR") != TempDir) {
        setenv("TMPDIR", TempDir.c_str(), 1);
    }

    setenv("LD_LIBRARY_PATH", LD_LIBRARY_PATH.c_str(), 1);
    setenv("TERM", Term.c_str(), 1);
    setenv("HOME", Home.c_str(), 1);
    setenv("SHELL", Shell.c_str(), 1);
    setenv("PATH", (std::string(std::getenv("PATH")) + ":/data/data/com.termux/files/usr/bin").c_str(), 1);

    std::string PS1;
    if (theme_name == "minimalist") {
        PS1 = "\\[\\e[1;31m\\]⚡\\u \\[\\e[1;33m\\]@ \\[\\e[1;32m\\]\\h \\[\\e[1;36m\\]in \\[\\e[1;34m\\]\\w \\[\\e[1;35m\\]→ \\[\\e[0m\\]";
    } else if (theme_name == "colorful") {
        PS1 = "\033[1;32m\\u@\\h\033[0m:\033[1;34m\\w\033[0m$ ";
    } else if (theme_name == "default") {
        PS1 = "\\[\\e[0;32m\\]\\w\\[\\e[0m\\] \\[\\e[0;97m\\]#\\[\\e[0m\\] ";
    }

    std::string temp_bashrc = TempDir + "/bashrc." + std::to_string(getpid());
    std::ofstream bashrcFile(temp_bashrc);
    if (bashrcFile) {
        bashrcFile << "export TERM='" << Term << "'\n";
        bashrcFile << "export HOME='" << Home << "'\n";
        bashrcFile << "export SHELL='" << Shell << "'\n";
        bashrcFile << "export PATH='" << std::getenv("PATH") << "'\n";
        if (!PS1.empty()) {
            bashrcFile << "export PS1=\"" << PS1 << "\"\n";
        }
        if (std::ifstream(AliasFile)) {
            bashrcFile << "if [ -f '" << AliasFile << "' ]; then . '" << AliasFile << "'; fi\n";
        }
        bashrcFile.close();
    }

    if (!temp_bashrc.empty() && std::ifstream(temp_bashrc)) {
        std::string shell_name = Shell.substr(Shell.find_last_of("/") + 1);
        if (shell_name == "bash") {
            execl(Shell.c_str(), Shell.c_str(), "--rcfile", temp_bashrc.c_str(), (char*)NULL);
        } else if (shell_name == "zsh") {
            setenv("ZDOTDIR", TempDir.c_str(), 1);
            execl(Shell.c_str(), Shell.c_str(), (char*)NULL);
        } else {
            execl(Shell.c_str(), Shell.c_str(), (char*)NULL);
        }
    } else {
        execl(Shell.c_str(), Shell.c_str(), (char*)NULL);
    }

    remove(temp_bashrc.c_str());

    return 0;
}
