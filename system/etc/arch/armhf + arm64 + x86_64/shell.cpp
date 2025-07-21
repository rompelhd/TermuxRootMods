#include <iostream>
#include <fstream>
#include <sstream>
#include <string>
#include <cstring>
#include <iomanip>
#include <vector>
#include <unistd.h>
#include <sys/stat.h>
#include <sys/time.h>
#include <openssl/evp.h>
#include <openssl/rand.h>
#include <openssl/sha.h>
#include <openssl/hmac.h>
#include <openssl/crypto.h>

#define AES_KEYLEN 32
#define AES_IVLEN 12
#define GCM_TAGLEN 16
#define HMAC_KEYLEN 32
#define HMAC_OUTLEN 32
#define PBKDF2_ITERATIONS 100000
#define MIN_TIMESTAMP_SIZE (AES_IVLEN + 1 + GCM_TAGLEN + HMAC_OUTLEN)
#define TIMEOUT_SECONDS 300 // 5 m

std::string derive_hash(const std::string& password, const std::string& salt) {
    unsigned char hash[SHA256_DIGEST_LENGTH];
    PKCS5_PBKDF2_HMAC(password.c_str(), password.size(),
                      reinterpret_cast<const unsigned char*>(salt.c_str()), salt.size(),
                      PBKDF2_ITERATIONS, EVP_sha256(), SHA256_DIGEST_LENGTH, hash);
    std::ostringstream oss;
    for (size_t i = 0; i < SHA256_DIGEST_LENGTH; ++i)
        oss << std::hex << std::setw(2) << std::setfill('0') << (int)hash[i];
    return oss.str();
}

bool derive_keys(const std::string& password, const std::string& salt,
                 unsigned char* aes_key, unsigned char* hmac_key) {
    unsigned char key_material[AES_KEYLEN + HMAC_KEYLEN];
    if (!PKCS5_PBKDF2_HMAC(password.c_str(), password.size(),
                           reinterpret_cast<const unsigned char*>(salt.c_str()), salt.size(),
                           PBKDF2_ITERATIONS, EVP_sha256(), AES_KEYLEN + HMAC_KEYLEN, key_material)) {
        return false;
    }
    memcpy(aes_key, key_material, AES_KEYLEN);
    memcpy(hmac_key, key_material + AES_KEYLEN, HMAC_KEYLEN);
    OPENSSL_cleanse(key_material, sizeof(key_material));
    return true;
}

std::vector<unsigned char> compute_hmac(const unsigned char* hmac_key,
                                       const std::vector<unsigned char>& data) {
    unsigned char hmac[HMAC_OUTLEN];
    unsigned int hmac_len;
    HMAC(EVP_sha256(), hmac_key, HMAC_KEYLEN, data.data(), data.size(), hmac, &hmac_len);
    return std::vector<unsigned char>(hmac, hmac + hmac_len);
}

bool encrypt_data(const std::string& plaintext, const std::string& password,
                  const std::string& salt, const std::string& out_file) {
    unsigned char aes_key[AES_KEYLEN];
    unsigned char hmac_key[HMAC_KEYLEN];
    unsigned char iv[AES_IVLEN];

    if (!derive_keys(password, salt, aes_key, hmac_key)) {
        return false;
    }
    if (RAND_bytes(iv, AES_IVLEN) != 1) {
        OPENSSL_cleanse(aes_key, AES_KEYLEN);
        OPENSSL_cleanse(hmac_key, HMAC_KEYLEN);
        return false;
    }

    EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
    if (!ctx) {
        OPENSSL_cleanse(aes_key, AES_KEYLEN);
        OPENSSL_cleanse(hmac_key, HMAC_KEYLEN);
        return false;
    }

    std::vector<unsigned char> ciphertext(plaintext.size() + GCM_TAGLEN);
    int len, ciphertext_len = 0;

    if (EVP_EncryptInit_ex(ctx, EVP_aes_256_gcm(), nullptr, nullptr, nullptr) != 1 ||
        EVP_EncryptInit_ex(ctx, nullptr, nullptr, aes_key, iv) != 1) {
        EVP_CIPHER_CTX_free(ctx);
        OPENSSL_cleanse(aes_key, AES_KEYLEN);
        OPENSSL_cleanse(hmac_key, HMAC_KEYLEN);
        return false;
    }

    if (EVP_EncryptUpdate(ctx, ciphertext.data(), &len,
                          reinterpret_cast<const unsigned char*>(plaintext.c_str()), plaintext.size()) != 1) {
        EVP_CIPHER_CTX_free(ctx);
        OPENSSL_cleanse(aes_key, AES_KEYLEN);
        OPENSSL_cleanse(hmac_key, HMAC_KEYLEN);
        return false;
    }
    ciphertext_len += len;

    if (EVP_EncryptFinal_ex(ctx, ciphertext.data() + len, &len) != 1) {
        EVP_CIPHER_CTX_free(ctx);
        OPENSSL_cleanse(aes_key, AES_KEYLEN);
        OPENSSL_cleanse(hmac_key, HMAC_KEYLEN);
        return false;
    }
    ciphertext_len += len;

    unsigned char tag[GCM_TAGLEN];
    if (EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_GET_TAG, GCM_TAGLEN, tag) != 1) {
        EVP_CIPHER_CTX_free(ctx);
        OPENSSL_cleanse(aes_key, AES_KEYLEN);
        OPENSSL_cleanse(hmac_key, HMAC_KEYLEN);
        return false;
    }
    EVP_CIPHER_CTX_free(ctx);

    std::vector<unsigned char> data_to_hmac;
    data_to_hmac.insert(data_to_hmac.end(), iv, iv + AES_IVLEN);
    data_to_hmac.insert(data_to_hmac.end(), ciphertext.begin(), ciphertext.begin() + ciphertext_len);
    data_to_hmac.insert(data_to_hmac.end(), tag, tag + GCM_TAGLEN);
    auto hmac = compute_hmac(hmac_key, data_to_hmac);

    std::ofstream out(out_file, std::ios::binary);
    if (!out) {
        OPENSSL_cleanse(aes_key, AES_KEYLEN);
        OPENSSL_cleanse(hmac_key, HMAC_KEYLEN);
        return false;
    }
    out.write(reinterpret_cast<char*>(iv), AES_IVLEN);
    out.write(reinterpret_cast<char*>(ciphertext.data()), ciphertext_len);
    out.write(reinterpret_cast<char*>(tag), GCM_TAGLEN);
    out.write(reinterpret_cast<char*>(hmac.data()), hmac.size());
    out.close();

    if (chmod(out_file.c_str(), 0600) != 0) {
    }
    uid_t ruid = getuid();
    gid_t rgid = getgid();
    if (chown(out_file.c_str(), ruid, rgid) != 0) {
        std::cerr << "Debug: Failed to set ownership of timestamp file (uid=" << ruid << ", gid=" << rgid << ")." << std::endl;
    }

    OPENSSL_cleanse(aes_key, AES_KEYLEN);
    OPENSSL_cleanse(hmac_key, HMAC_KEYLEN);
    return true;
}

bool decrypt_data(const std::string& password, const std::string& salt,
                  const std::string& in_file, std::string& plaintext_out) {
    std::ifstream in(in_file, std::ios::binary);
    if (!in) {
        std::cerr << "Debug: Unable to open timestamp file: " << in_file << std::endl;
        return false;
    }

    std::vector<unsigned char> file_data((std::istreambuf_iterator<char>(in)), std::istreambuf_iterator<char>());
    in.close();

    if (file_data.size() < MIN_TIMESTAMP_SIZE) {
        std::cerr << "Debug: Timestamp file too small (" << file_data.size() << " bytes, expected at least " << MIN_TIMESTAMP_SIZE << ")." << std::endl;
        return false;
    }

    unsigned char* iv = file_data.data();
    unsigned char* tag = file_data.data() + file_data.size() - HMAC_OUTLEN - GCM_TAGLEN;
    unsigned char* hmac = file_data.data() + file_data.size() - HMAC_OUTLEN;
    std::vector<unsigned char> ciphertext(file_data.begin() + AES_IVLEN,
                                         file_data.begin() + file_data.size() - GCM_TAGLEN - HMAC_OUTLEN);
    int ciphertext_len = ciphertext.size();

    if (ciphertext_len < 1) {
        std::cerr << "Debug: No ciphertext data in timestamp file." << std::endl;
        return false;
    }

    unsigned char aes_key[AES_KEYLEN];
    unsigned char hmac_key[HMAC_KEYLEN];
    if (!derive_keys(password, salt, aes_key, hmac_key)) {
        std::cerr << "Debug: Failed to derive keys for decryption." << std::endl;
        return false;
    }

    std::vector<unsigned char> data_to_hmac(file_data.begin(), file_data.begin() + file_data.size() - HMAC_OUTLEN);
    auto computed_hmac = compute_hmac(hmac_key, data_to_hmac);
    if (computed_hmac.size() != HMAC_OUTLEN ||
        CRYPTO_memcmp(computed_hmac.data(), hmac, HMAC_OUTLEN) != 0) {
        std::cerr << "Debug: HMAC verification failed." << std::endl;
        OPENSSL_cleanse(aes_key, AES_KEYLEN);
        OPENSSL_cleanse(hmac_key, HMAC_KEYLEN);
        return false;
    }

    EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
    if (!ctx) {
        std::cerr << "Debug: Failed to create EVP context for decryption." << std::endl;
        OPENSSL_cleanse(aes_key, AES_KEYLEN);
        OPENSSL_cleanse(hmac_key, HMAC_KEYLEN);
        return false;
    }

    std::vector<unsigned char> plaintext(ciphertext_len);
    int len, plaintext_len = 0;

    if (EVP_DecryptInit_ex(ctx, EVP_aes_256_gcm(), nullptr, nullptr, nullptr) != 1 ||
        EVP_DecryptInit_ex(ctx, nullptr, nullptr, aes_key, iv) != 1) {
        std::cerr << "Debug: Failed to initialize decryption." << std::endl;
        EVP_CIPHER_CTX_free(ctx);
        OPENSSL_cleanse(aes_key, AES_KEYLEN);
        OPENSSL_cleanse(hmac_key, HMAC_KEYLEN);
        return false;
    }

    if (EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_TAG, GCM_TAGLEN, tag) != 1) {
        std::cerr << "Debug: Failed to set GCM tag." << std::endl;
        EVP_CIPHER_CTX_free(ctx);
        OPENSSL_cleanse(aes_key, AES_KEYLEN);
        OPENSSL_cleanse(hmac_key, HMAC_KEYLEN);
        return false;
    }

    if (EVP_DecryptUpdate(ctx, plaintext.data(), &len, ciphertext.data(), ciphertext_len) != 1) {
        std::cerr << "Debug: Failed to decrypt data." << std::endl;
        EVP_CIPHER_CTX_free(ctx);
        OPENSSL_cleanse(aes_key, AES_KEYLEN);
        OPENSSL_cleanse(hmac_key, HMAC_KEYLEN);
        return false;
    }
    plaintext_len += len;

    if (EVP_DecryptFinal_ex(ctx, plaintext.data() + len, &len) != 1) {
        std::cerr << "Debug: Failed to finalize decryption." << std::endl;
        EVP_CIPHER_CTX_free(ctx);
        OPENSSL_cleanse(aes_key, AES_KEYLEN);
        OPENSSL_cleanse(hmac_key, HMAC_KEYLEN);
        return false;
    }
    plaintext_len += len;

    EVP_CIPHER_CTX_free(ctx);

    plaintext_out.assign(reinterpret_cast<char*>(plaintext.data()), plaintext_len);
    OPENSSL_cleanse(aes_key, AES_KEYLEN);
    OPENSSL_cleanse(hmac_key, HMAC_KEYLEN);
    return true;
}

bool validate_shadow_file(const std::string& shadow_file, const std::string& username) {
    std::ifstream file(shadow_file);
    if (!file) {
        std::cerr << "Debug: Unable to open shadow file: " << shadow_file << std::endl;
        return false;
    }

    std::string line;
    bool found = false;
    while (std::getline(file, line)) {
        std::istringstream iss(line);
        std::string user, hash_field;
        if (!std::getline(iss, user, ':') || !std::getline(iss, hash_field, ':')) {
            std::cerr << "Debug: Invalid shadow file format." << std::endl;
            return false;
        }

        if (user.length() > 32 || user.empty()) {
            std::cerr << "Debug: Invalid username length in shadow file." << std::endl;
            return false;
        }
        for (char c : user) {
            if (!std::isalnum(c)) {
                std::cerr << "Debug: Invalid characters in username." << std::endl;
                return false;
            }
        }

        if (hash_field.length() != 64) {
            std::cerr << "Debug: Invalid hash length in shadow file." << std::endl;
            return false;
        }
        for (char c : hash_field) {
            if (!std::isxdigit(c)) {
                std::cerr << "Debug: Invalid hash format in shadow file." << std::endl;
                return false;
            }
        }

        if (user == username) {
            found = true;
        }
    }
    file.close();

    if (!found) {
        std::cerr << "Debug: No valid password found for user " << username << " in shadow file." << std::endl;
        return false;
    }
    return true;
}

bool store_password(const std::string& password, const std::string& key_file) {
    std::string system_salt = "trm_key_salt_2025";
    return encrypt_data(password, system_salt, system_salt, key_file);
}

bool retrieve_password(std::string& password_out, const std::string& key_file) {
    std::string system_salt = "trm_key_salt_2025";
    if (decrypt_data(system_salt, system_salt, key_file, password_out)) {
        return true;
    }
    return false;
}

bool ver_con(std::string& input_password, bool& password_prompted) {
    std::string shadow_file = "/data/data/com.termux/files/usr/etc/.trm_shadow";
    std::string timestamp_file = "/data/data/com.termux/files/usr/tmp/.trm_sudo_timestamp";
    std::string key_file = "/data/data/com.termux/files/usr/tmp/.trm_sudo_key";
    std::string username = "termux";
    std::string salt = "trm_salt_2025";

    struct stat file_stat;
    if (stat(shadow_file.c_str(), &file_stat) != 0) {
        std::cerr << "Debug: No password set. Please create a password in " << shadow_file << "." << std::endl;
        return false;
    }

    if (!validate_shadow_file(shadow_file, username)) {
        return false;
    }

    if ((file_stat.st_mode & 0777) != 0600) {
        chmod(shadow_file.c_str(), 0600);
    }

    if (stat(key_file.c_str(), &file_stat) == 0) {
        if ((file_stat.st_mode & 0777) != 0600) {
            std::cerr << "Debug: Key file has incorrect permissions, fixing." << std::endl;
            chmod(key_file.c_str(), 0600);
        }

        std::string stored_password;
        if (retrieve_password(stored_password, key_file)) {
            if (stat(timestamp_file.c_str(), &file_stat) == 0) {
                if ((file_stat.st_mode & 0777) != 0600) {
                    std::cerr << "Debug: Timestamp file has incorrect permissions, fixing." << std::endl;
                    chmod(timestamp_file.c_str(), 0600);
                    uid_t ruid = getuid();
                    gid_t rgid = getgid();
                    if (chown(timestamp_file.c_str(), ruid, rgid) != 0) {
                        std::cerr << "Debug: Failed to set ownership, continuing." << std::endl;
                    }
                }

                std::string decrypted_ts;
                if (decrypt_data(stored_password, salt, timestamp_file, decrypted_ts)) {
                    try {
                        long timestamp = std::stol(decrypted_ts);
                        struct timeval current_time;
                        gettimeofday(&current_time, nullptr);
                        long current_seconds = current_time.tv_sec;

                        if (current_seconds < timestamp || (timestamp - current_seconds) > 60) {
                            unlink(timestamp_file.c_str());
                            unlink(key_file.c_str());
                        } else if (current_seconds - timestamp < TIMEOUT_SECONDS) {
                            input_password = stored_password;
                            return true;
                        } else {
                            unlink(timestamp_file.c_str());
                            unlink(key_file.c_str());
                        }
                    } catch (...) {
                        unlink(timestamp_file.c_str());
                        unlink(key_file.c_str());
                    }
                } else {
                    unlink(key_file.c_str());
                }
            } else {
                unlink(key_file.c_str());
            }
        } else {
            unlink(key_file.c_str());
        }
    }

    if (!password_prompted) {
        char* input = getpass("Enter password: ");
        if (!input || strlen(input) == 0) {
            std::cerr << "Debug: Unable to read password." << std::endl;
            return false;
        }
        input_password = input;
        password_prompted = true;
        OPENSSL_cleanse(input, strlen(input));
    }

    std::ifstream file(shadow_file);
    std::string hash_guardado;
    bool found = false;
    std::string line;
    while (std::getline(file, line)) {
        std::istringstream iss(line);
        std::string user, hash_field;
        std::getline(iss, user, ':');
        std::getline(iss, hash_field, ':');
        if (user == username) {
            hash_guardado = hash_field;
            found = true;
            break;
        }
    }
    file.close();

    if (!found) {
        std::cerr << "Debug: No valid password found for user " << username << " in shadow file." << std::endl;
        return false;
    }

    std::string hash_input = derive_hash(input_password, salt);
    if (hash_input.size() != hash_guardado.size() ||
        CRYPTO_memcmp(hash_input.c_str(), hash_guardado.c_str(), hash_input.size()) != 0) {
        std::cerr << "Access denied." << std::endl;
        return false;
    }

    struct timeval current_time;
    gettimeofday(&current_time, nullptr);
    std::string ts_str = std::to_string(current_time.tv_sec);
    if (!encrypt_data(ts_str, input_password, salt, timestamp_file)) {
        std::cerr << "Debug: Failed to create encrypted timestamp file." << std::endl;
    }
    if (!store_password(input_password, key_file)) {
        std::cerr << "Debug: Failed to store password in key file." << std::endl;
    }

    return true;
}

int main() {
    std::string shadow_file = "/data/data/com.termux/files/usr/etc/.trm_shadow";

    struct stat file_stat;
    if (stat(shadow_file.c_str(), &file_stat) != 0) {
        std::cerr << "Debug: No password set. Please create a password in " << shadow_file << "." << std::endl;
        return 1;
    }

    std::string password;
    bool password_prompted = false;
    if (!ver_con(password, password_prompted)) {
        OPENSSL_cleanse(&password[0], password.size());
        return 1;
    }

    OPENSSL_cleanse(&password[0], password.size());

    std::string Home = "/data/data/com.termux/files/root-home";
    std::string Term = "xterm-256color";
    std::string AliasFile = Home + "/.aliases";
    std::string TempDir = "/data/data/com.termux/files/usr/tmp";
    std::string LD_LIBRARY_PATH = "/data/data/com.termux/files/usr/lib";
    std::string trm_config = Home + "/.config/TermuxHome";
    std::string theme_name = "none";

    std::ifstream config(trm_config);
    if (config) {
        std::string line;
        std::string current;
        while (std::getline(config, line)) {
            line.erase(0, line.find_first_not_of(" \t\r\n"));
            line.erase(line.find_last_not_of(" \t\r\n") + 1);
            if (line.empty() || line[0] == ';' || line[0] == '#') continue;
            if (line.front() == '[' && line.back() == ']') {
                current = line.substr(1, line.size() - 2);
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
                if (current == "SHELL" && key == "home") {
                    env_var = "SHELL";
                } else if (current == "GENERAL" && key == "language") {
                    env_var = "GENERAL_LANGUAGE";
                } else if (current == "THEME" && key == "theme_name") {
                    env_var = "THEME_NAME";
                    theme_name = value;
                }

                if (!env_var.empty()) {
                    setenv(env_var.c_str(), value.c_str(), 1);
                }
            }
        }
        config.close();
    }

    const char* shell_env = std::getenv("SHELL");
    std::string Shell = shell_env ? shell_env : "/bin/sh";
    if (Shell == "zsh" || Shell == "bash" || Shell == "sh") {
        Shell = "/data/data/com.termux/files/usr/bin/" + Shell;
    }
    if (access(Shell.c_str(), X_OK) != 0) {
        std::cerr << "Debug: Shell not found. Falling back to /bin/sh." << std::endl;
        Shell = "/bin/sh";
    }

    setenv("TMPDIR", TempDir.c_str(), 1);
    setenv("LD_LIBRARY_PATH", LD_LIBRARY_PATH.c_str(), 1);
    setenv("TERM", Term.c_str(), 1);
    setenv("HOME", Home.c_str(), 1);
    setenv("SHELL", Shell.c_str(), 1);

    const char* path_env = std::getenv("PATH");
    std::string DefaultPath = "/data/data/com.termux/files/usr/bin:/system/bin:/bin:/sbin";
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
        bashrcFile << "export TERM='" << Term << "'" << std::endl;
        bashrcFile << "export HOME='" << Home << "'" << std::endl;
        bashrcFile << "export SHELL='" << Shell << "'" << std::endl;
        bashrcFile << "export PATH='" << FullPath << "'" << std::endl;
        bashrcFile << "export TMPDIR='" << TempDir << "'" << std::endl;
        bashrcFile << "export LD_LIBRARY_PATH='" << LD_LIBRARY_PATH << "'" << std::endl;
        if (!PS1.empty()) {
            bashrcFile << "export PS1=\"" << PS1 << "\"" << std::endl;
        }
        if (std::ifstream(AliasFile)) {
            bashrcFile << "if [ -f '" << AliasFile << "' ]; then . '" << AliasFile << "'; fi" << std::endl;
        }
        bashrcFile.close();
        chmod(temp_bashrc.c_str(), 0600);
    }

    if (!temp_bashrc.empty() && std::ifstream(temp_bashrc)) {
        std::string shell_name = Shell.substr(Shell.find_last_of("/") + 1);
        if (shell_name == "bash") {
            execl(Shell.c_str(), Shell.c_str(), "--rcfile", temp_bashrc.c_str(), (char*)nullptr);
        } else if (shell_name == "zsh") {
            setenv("ZDOTDIR", TempDir.c_str(), 1);
            execl(Shell.c_str(), Shell.c_str(), (char*)nullptr);
        } else if (shell_name == "fish") {
            setenv("XDG_CONFIG_HOME", TempDir.c_str(), 1);
            execl(Shell.c_str(), Shell.c_str(), (char*)nullptr);
        } else {
            execl(Shell.c_str(), Shell.c_str(), (char*)nullptr);
        }
    } else {
        execl(Shell.c_str(), Shell.c_str(), (char*)nullptr);
    }

    std::cerr << "Debug: Failed to execute shell: " << Shell << std::endl;
    remove(temp_bashrc.c_str());
    return 1;
}
