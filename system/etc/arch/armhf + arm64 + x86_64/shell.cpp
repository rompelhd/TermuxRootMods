#include <iostream>
#include <fstream>
#include <string>
#include <sstream>
#include <unistd.h>
#include <sys/stat.h>
#include <sys/time.h>
#include <openssl/sha.h>
#include <openssl/evp.h>
#include <openssl/rand.h>

#define AES_IV_LENGTH 16

const unsigned char AES_ENCRYPTION_KEY[] = {
    0x1a, 0x2b, 0x3c, 0x4d, 0x5e, 0x6f, 0x7a, 0x8b,
    0x9c, 0xad, 0xbe, 0xcf, 0xd0, 0xe1, 0xf2, 0x03,
    0x14, 0x25, 0x36, 0x47, 0x58, 0x69, 0x7a, 0x8b,
    0x9c, 0xad, 0xbe, 0xcf, 0xd0, 0xe1, 0xf2, 0x03
};

std::string sha256_with_salt(const std::string& input, const std::string& salt) {
    std::string salted_input = input + salt;
    unsigned char hash[SHA256_DIGEST_LENGTH];
    SHA256((unsigned char*)salted_input.c_str(), salted_input.size(), hash);

    char output[2 * SHA256_DIGEST_LENGTH + 1];
    for (int i = 0; i < SHA256_DIGEST_LENGTH; ++i) {
        sprintf(output + (i * 2), "%02x", hash[i]);
    }
    output[64] = 0;
    return std::string(output);
}

bool encrypt_timestamp(long timestamp, const std::string& filename) {
    unsigned char iv[AES_IV_LENGTH];
    if (RAND_bytes(iv, AES_IV_LENGTH) != 1) {
        std::cerr << "Error: Failed to generate IV." << std::endl;
        return false;
    }

    std::string timestamp_str = std::to_string(timestamp);
    unsigned char ciphertext[256];
    int ciphertext_len = 0;
    int len;

    EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
    if (!ctx) {
        std::cerr << "Error: Failed to create EVP context." << std::endl;
        return false;
    }

    if (EVP_EncryptInit_ex(ctx, EVP_aes_256_cbc(), nullptr, AES_ENCRYPTION_KEY, iv) != 1) {
        std::cerr << "Error: Failed to initialize encryption." << std::endl;
        EVP_CIPHER_CTX_free(ctx);
        return false;
    }

    if (EVP_EncryptUpdate(ctx, ciphertext, &len, (unsigned char*)timestamp_str.c_str(), timestamp_str.size()) != 1) {
        std::cerr << "Error: Failed to encrypt data." << std::endl;
        EVP_CIPHER_CTX_free(ctx);
        return false;
    }
    ciphertext_len += len;

    if (EVP_EncryptFinal_ex(ctx, ciphertext + len, &len) != 1) {
        std::cerr << "Error: Failed to finalize encryption." << std::endl;
        EVP_CIPHER_CTX_free(ctx);
        return false;
    }
    ciphertext_len += len;

    EVP_CIPHER_CTX_free(ctx);

    std::ofstream out(filename, std::ios::binary);
    if (!out) {
        std::cerr << "Warning: Unable to create timestamp file." << std::endl;
        return false;
    }
    out.write((char*)iv, AES_IV_LENGTH);
    out.write((char*)ciphertext, ciphertext_len);
    out.close();

    chmod(filename.c_str(), 0600);
    return true;
}

bool decrypt_timestamp(const std::string& filename, long& timestamp) {
    std::ifstream in(filename, std::ios::binary);
    if (!in) {
        return false;
    }

    unsigned char iv[AES_IV_LENGTH];
    unsigned char ciphertext[256];
    unsigned char plaintext[256];
    int ciphertext_len = 0;
    int plaintext_len = 0;
    int len;

    in.read((char*)iv, AES_IV_LENGTH);
    ciphertext_len = in.read((char*)ciphertext, sizeof(ciphertext)).gcount();
    in.close();

    if (ciphertext_len <= 0) {
        return false;
    }

    EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
    if (!ctx) {
        std::cerr << "Error: Failed to create EVP context." << std::endl;
        return false;
    }

    if (EVP_DecryptInit_ex(ctx, EVP_aes_256_cbc(), nullptr, AES_ENCRYPTION_KEY, iv) != 1) {
        std::cerr << "Error: Failed to initialize decryption." << std::endl;
        EVP_CIPHER_CTX_free(ctx);
        return false;
    }

    if (EVP_DecryptUpdate(ctx, plaintext, &len, ciphertext, ciphertext_len) != 1) {
        std::cerr << "Error: Failed to decrypt data." << std::endl;
        EVP_CIPHER_CTX_free(ctx);
        return false;
    }
    plaintext_len += len;

    if (EVP_DecryptFinal_ex(ctx, plaintext + len, &len) != 1) {
        std::cerr << "Error: Failed to finalize decryption." << std::endl;
        EVP_CIPHER_CTX_free(ctx);
        return false;
    }
    plaintext_len += len;

    EVP_CIPHER_CTX_free(ctx);

    std::string plaintext_str((char*)plaintext, plaintext_len);
    try {
        timestamp = std::stol(plaintext_str);
        return true;
    } catch (...) {
        return false;
    }
}

bool ver_con() {
    std::string shadow_file = "/data/data/com.termux/files/usr/etc/.trm_shadow";
    std::string timestamp_file = "/data/data/com.termux/files/usr/tmp/.trm_sudo_timestamp";
    std::string username = "termux";
    std::string salt = "trm_salt_2025";
    const long TIMEOUT_SECONDS = 300; // 5m

    struct stat file_stat;
    long timestamp;
    if (stat(timestamp_file.c_str(), &file_stat) == 0 && decrypt_timestamp(timestamp_file, timestamp)) {
        struct timeval current_time;
        gettimeofday(&current_time, nullptr);
        long current_seconds = current_time.tv_sec;

        if ((file_stat.st_mode & 0777) != 0600) {
            chmod(timestamp_file.c_str(), 0600);
        }

        if (current_seconds - timestamp < TIMEOUT_SECONDS) {
            return true;
        }
    }

    if (stat(shadow_file.c_str(), &file_stat) == 0) {
        if ((file_stat.st_mode & 0777) != 0600) {
            chmod(shadow_file.c_str(), 0600);
        }
    }

    std::ifstream file(shadow_file);
    if (!file) {
        std::cerr << "Error: Unable to open shadow file." << std::endl;
        return false;
    }

    std::string line;
    std::string hash_guardado;
    bool found = false;
    while (std::getline(file, line)) {
        std::istringstream iss(line);
        std::string user, hash_field;
        std::getline(iss, user, ':');
        std::getline(iss, hash_field, ':');
        if (user == username) {
            size_t pos1 = hash_field.find('$');
            size_t pos2 = hash_field.find('$', pos1 + 1);
            size_t pos3 = hash_field.find('$', pos2 + 1);
            if (pos1 != std::string::npos && pos2 != std::string::npos && pos3 != std::string::npos) {
                std::string id = hash_field.substr(pos1 + 1, pos2 - pos1 - 1);
                std::string file_salt = hash_field.substr(pos2 + 1, pos3 - pos2 - 1);
                hash_guardado = hash_field.substr(pos3 + 1);
                if (id == "5" && file_salt == salt) {
                    found = true;
                    break;
                }
            }
        }
    }
    file.close();

    if (!found) {
        std::cerr << "Error: User or hash not found in shadow file." << std::endl;
        return false;
    }

    char* input = getpass("Enter password: ");
    if (!input) {
        std::cerr << "Error: Unable to read password." << std::endl;
        return false;
    }

    std::string hash_input = sha256_with_salt(input, salt);
    memset(input, 0, strlen(input));

    if (hash_input != hash_guardado) {
        std::cerr << "Access denied." << std::endl;
        return false;
    }

    struct timeval current_time;
    gettimeofday(&current_time, nullptr);
    if (!encrypt_timestamp(current_time.tv_sec, timestamp_file)) {
        std::cerr << "Warning: Unable to create encrypted timestamp file." << std::endl;
    }

    return true;
}

int main() {
    if (!ver_con()) {
        return 1;
    }

    std::string Home = "/data/data/com.termux/files/root-home";
    std::string Term = "xterm-256color";
    std::string AliasFile = "/sdcard/.aliases";
    std::string TempDir = "/data/data/com.termux/files/usr/tmp";
    std::string LD_LIBRARY_PATH = "/data/data/com.termux/files/usr/lib";
    std::string trm_config = Home + "/.config/TermuxRootMods/.trm";
    std::string theme_name = "none";

    std::ifstream configFile(trm_config);
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
                    setenv(env_var.c_str(), value.c_str(), 1);
                }
            }
        }
        configFile.close();
    }

    const char* shell_env = std::getenv("SHELL");
    std::string Shell = shell_env ? shell_env : "/bin/sh";
    if (Shell == "zsh" || Shell == "bash" || Shell == "sh") {
        Shell = "/data/data/com.termux/files/usr/bin/" + Shell;
    }
    if (access(Shell.c_str(), X_OK) != 0) {
        std::cerr << "Error: Shell not found. Falling back to /bin/sh." << std::endl;
        Shell = "/bin/sh";
    }

    setenv("TMPDIR", TempDir.c_str(), 1);
    setenv("LD_LIBRARY_PATH", LD_LIBRARY_PATH.c_str(), 1);
    setenv("TERM", Term.c_str(), 1);
    setenv("HOME", Home.c_str(), 1);
    setenv("SHELL", Shell.c_str(), 1);

    const char* path_env = std::getenv("PATH");
    std::string DefaultPath = "/data/data/com.termux/files/usr/bin:/system/bin:/bin:/usr/bin";
    std::string FullPath = path_env ? std::string(path_env) : DefaultPath;
    if (FullPath.find("/data/data/com.termux/files/usr/bin") == std::string::npos) {
        FullPath += ":/data/data/com.termux/files/usr/bin";
    }
    setenv("PATH", FullPath.c_str(), 1);

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
        bashrcFile << "export PATH='" << FullPath << "'\n";
        bashrcFile << "export TMPDIR='" << TempDir << "'\n";
        bashrcFile << "export LD_LIBRARY_PATH='" << LD_LIBRARY_PATH << "'\n";
        if (!PS1.empty()) {
            bashrcFile << "export PS1=\"" << PS1 << "\"\n";
        }
        if (std::ifstream(AliasFile)) {
            bashrcFile << "if [ -f '" << AliasFile << "' ]; then . '" << AliasFile << "'; fi\n";
        }
        bashrcFile.close();
        chmod(temp_bashrc.c_str(), 0600);
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
