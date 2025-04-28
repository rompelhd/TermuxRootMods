#include <iostream>
#include <filesystem>
#include <unistd.h>
#include <vector>
#include <string.h>
#include <sys/wait.h>

int main(int argc, char* argv[]) {
    if (access("/data/data/com.termux/files/usr/bin/proot", X_OK) != 0 && access("/usr/bin/proot", X_OK) != 0) {
        std::cout << "proot is not installed. Exiting script. [❌]" << std::endl;
        return 1;
    }

    std::string root_home_dir = "/data/data/com.termux/files/root-home";
    std::string default_home_dir = "/";
    std::string home_dir;

    namespace fs = std::filesystem;
    if (fs::exists(root_home_dir) && fs::is_directory(root_home_dir) &&
        (access(root_home_dir.c_str(), R_OK | W_OK) == 0)) {
        home_dir = root_home_dir;
    } else {
        home_dir = default_home_dir;
        std::cout << "The " << root_home_dir << " directory is not accessible [⚠️]" << std::endl;
    }

    std::vector<const char*> args;

    args.push_back("proot");
    args.push_back("-0");
    args.push_back("--verbose=0");
    args.push_back("-w");
    args.push_back(home_dir.c_str());

    if (argc > 1) {
        for (int i = 1; i < argc; ++i) {
            args.push_back(argv[i]);
        }
    } else {
        std::cout << "\nFalse shell root executed [✔️]\n" << std::endl;
        args.push_back("/system/bin/sh");
    }
    args.push_back(nullptr);

    pid_t pid = fork();
    if (pid < 0) {
        perror("fork failed");
        return 1;
    } else if (pid == 0) {
        execvp("proot", const_cast<char* const*>(args.data()));
        perror("execvp failed");
        exit(1);
    } else {
        int status;
        waitpid(pid, &status, 0);

        if (WIFEXITED(status) && WEXITSTATUS(status) != 0 && argc > 1) {
            std::cout << "Command not recognized or failed: " << argv[1] << " [❌]" << std::endl;
        }
    }

    return 0;
}
