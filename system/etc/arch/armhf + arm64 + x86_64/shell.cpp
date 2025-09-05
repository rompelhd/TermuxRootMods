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
#include <cerrno>

#define AES_KEYLEN 32
#define AES_IVLEN 12
#define GCM_TAGLEN 16
#define HMAC_KEYLEN 32
#define HMAC_OUTLEN 32
#define PBKDF2_ITERATIONS 100000
#define MIN_TIMESTAMP_SIZE (AES_IVLEN + 1 + GCM_TAGLEN + HMAC_OUTLEN)
#define TIMEOUT_SECONDS 300 // 5 minutes

bool debug_mode = false;

void debug_log(const std::string& message) {
    if (debug_mode) {
        std::cerr << "Debug: " << message << std::endl;
    }
}

std::string derive_hash(const std::string& password, const std::string& salt) {
    debug_log("Deriving hash for password with salt: " + salt);
    unsigned char hash[SHA256_DIGEST_LENGTH];
    PKCS5_PBKDF2_HMAC(password.c_str(), password.size(),
                      reinterpret_cast<const unsigned char*>(salt.c_str()), salt.size(),
                      PBKDF2_ITERATIONS, EVP_sha256(), SHA256_DIGEST_LENGTH, hash);
    std::ostringstream oss;
    for (size_t i = 0; i < SHA256_DIGEST_LENGTH; ++i)
        oss << std::hex << std::setw(2) << std::setfill('0') << (int)hash[i];
    debug_log("Hash derived successfully: " + oss.str());
    return oss.str();
}

bool derive_keys(const std::string& password, const std::string& salt,
                 unsigned char* aes_key, unsigned char* hmac_key) {
    debug_log("Deriving AES and HMAC keys...");
    unsigned char key_material[AES_KEYLEN + HMAC_KEYLEN];
    if (!PKCS5_PBKDF2_HMAC(password.c_str(), password.size(),
                           reinterpret_cast<const unsigned char*>(salt.c_str()), salt.size(),
                           PBKDF2_ITERATIONS, EVP_sha256(), AES_KEYLEN + HMAC_KEYLEN, key_material)) {
        debug_log("Failed to derive keys.");
        return false;
    }
    memcpy(aes_key, key_material, AES_KEYLEN);
    memcpy(hmac_key, key_material + AES_KEYLEN, HMAC_KEYLEN);
    OPENSSL_cleanse(key_material, sizeof(key_material));
    debug_log("Keys derived successfully.");
    return true;
}

std::vector<unsigned char> compute_hmac(const unsigned char* hmac_key,
                                       const std::vector<unsigned char>& data) {
    debug_log("Computing HMAC...");
    unsigned char hmac[HMAC_OUTLEN];
    unsigned int hmac_len;
    HMAC(EVP_sha256(), hmac_key, HMAC_KEYLEN, data.data(), data.size(), hmac, &hmac_len);
    debug_log("HMAC computed successfully.");
    return std::vector<unsigned char>(hmac, hmac + hmac_len);
}

bool encrypt_data(const std::string& plaintext, const std::string& password,
                  const std::string& salt, const std::string& out_file) {
    debug_log("Encrypting data to file: " + out_file);
    unsigned char aes_key[AES_KEYLEN];
    unsigned char hmac_key[HMAC_KEYLEN];
    unsigned char iv[AES_IVLEN];

    if (!derive_keys(password, salt, aes_key, hmac_key)) {
        debug_log("Failed to derive keys for encryption.");
        return false;
    }
    if (RAND_bytes(iv, AES_IVLEN) != 1) {
        debug_log("Failed to generate IV.");
        OPENSSL_cleanse(aes_key, AES_KEYLEN);
        OPENSSL_cleanse(hmac_key, HMAC_KEYLEN);
        return false;
    }

    EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
    if (!ctx) {
        debug_log("Failed to create EVP context.");
        OPENSSL_cleanse(aes_key, AES_KEYLEN);
        OPENSSL_cleanse(hmac_key, HMAC_KEYLEN);
        return false;
    }

    std::vector<unsigned char> ciphertext(plaintext.size() + GCM_TAGLEN);
    int len, ciphertext_len = 0;

    if (EVP_EncryptInit_ex(ctx, EVP_aes_256_gcm(), nullptr, nullptr, nullptr) != 1 ||
        EVP_EncryptInit_ex(ctx, nullptr, nullptr, aes_key, iv) != 1) {
        debug_log("Failed to initialize encryption.");
        EVP_CIPHER_CTX_free(ctx);
        OPENSSL_cleanse(aes_key, AES_KEYLEN);
        OPENSSL_cleanse(hmac_key, HMAC_KEYLEN);
        return false;
    }

    if (EVP_EncryptUpdate(ctx, ciphertext.data(), &len,
                          reinterpret_cast<const unsigned char*>(plaintext.c_str()), plaintext.size()) != 1) {
        debug_log("Failed to encrypt data.");
        EVP_CIPHER_CTX_free(ctx);
        OPENSSL_cleanse(aes_key, AES_KEYLEN);
        OPENSSL_cleanse(hmac_key, HMAC_KEYLEN);
        return false;
    }
    ciphertext_len += len;

    if (EVP_EncryptFinal_ex(ctx, ciphertext.data() + len, &len) != 1) {
        debug_log("Failed to finalize encryption.");
        EVP_CIPHER_CTX_free(ctx);
        OPENSSL_cleanse(aes_key, AES_KEYLEN);
        OPENSSL_cleanse(hmac_key, HMAC_KEYLEN);
        return false;
    }
    ciphertext_len += len;

    unsigned char tag[GCM_TAGLEN];
    if (EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_GET_TAG, GCM_TAGLEN, tag) != 1) {
        debug_log("Failed to get GCM tag.");
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
        debug_log("Failed to open output file: " + out_file);
        OPENSSL_cleanse(aes_key, AES_KEYLEN);
        OPENSSL_cleanse(hmac_key, HMAC_KEYLEN);
        return false;
    }
    out.write(reinterpret_cast<char*>(iv), AES_IVLEN);
    out.write(reinterpret_cast<char*>(ciphertext.data()), ciphertext_len);
    out.write(reinterpret_cast<char*>(tag), GCM_TAGLEN);
    out.write(reinterpret_cast<char*>(hmac.data()), hmac.size());
    out.close();

    debug_log("Data written to file: " + out_file);
    if (chmod(out_file.c_str(), 0600) != 0) {
        debug_log("Failed to set permissions on file: " + out_file + " (errno: " + std::to_string(errno) + ")");
    }
    uid_t ruid = getuid();
    gid_t rgid = getgid();
    if (chown(out_file.c_str(), ruid, rgid) != 0) {
        debug_log("Failed to set ownership of file: " + out_file + " (uid=" + std::to_string(ruid) + ", gid=" + std::to_string(rgid) + ", errno: " + std::to_string(errno) + ")");
    }

    OPENSSL_cleanse(aes_key, AES_KEYLEN);
    OPENSSL_cleanse(hmac_key, HMAC_KEYLEN);
    debug_log("Encryption completed successfully.");
    return true;
}

bool decrypt_data(const std::string& password, const std::string& salt,
                  const std::string& in_file, std::string& plaintext_out) {
    debug_log("Decrypting data from file: " + in_file);
    std::ifstream in(in_file, std::ios::binary);
    if (!in) {
        debug_log("Unable to open input file: " + in_file + " (errno: " + std::to_string(errno) + ")");
        return false;
    }

    std::vector<unsigned char> file_data((std::istreambuf_iterator<char>(in)), std::istreambuf_iterator<char>());
    in.close();
    debug_log("Read " + std::to_string(file_data.size()) + " bytes from file.");

    if (file_data.size() < MIN_TIMESTAMP_SIZE) {
        debug_log("File too small (" + std::to_string(file_data.size()) + " bytes, expected at least " + std::to_string(MIN_TIMESTAMP_SIZE) + ").");
        return false;
    }

    unsigned char* iv = file_data.data();
    unsigned char* tag = file_data.data() + file_data.size() - HMAC_OUTLEN - GCM_TAGLEN;
    unsigned char* hmac = file_data.data() + file_data.size() - HMAC_OUTLEN;
    std::vector<unsigned char> ciphertext(file_data.begin() + AES_IVLEN,
                                         file_data.begin() + file_data.size() - GCM_TAGLEN - HMAC_OUTLEN);
    int ciphertext_len = ciphertext.size();

    if (ciphertext_len < 1) {
        debug_log("No ciphertext data in file.");
        return false;
    }
    debug_log("Ciphertext length: " + std::to_string(ciphertext_len) + " bytes.");

    unsigned char aes_key[AES_KEYLEN];
    unsigned char hmac_key[HMAC_KEYLEN];
    if (!derive_keys(password, salt, aes_key, hmac_key)) {
        debug_log("Failed to derive keys for decryption.");
        return false;
    }

    std::vector<unsigned char> data_to_hmac(file_data.begin(), file_data.begin() + file_data.size() - HMAC_OUTLEN);
    auto computed_hmac = compute_hmac(hmac_key, data_to_hmac);
    if (computed_hmac.size() != HMAC_OUTLEN ||
        CRYPTO_memcmp(computed_hmac.data(), hmac, HMAC_OUTLEN) != 0) {
        debug_log("HMAC verification failed.");
        OPENSSL_cleanse(aes_key, AES_KEYLEN);
        OPENSSL_cleanse(hmac_key, HMAC_KEYLEN);
        return false;
    }
    debug_log("HMAC verification passed.");

    EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
    if (!ctx) {
        debug_log("Failed to create EVP context for decryption.");
        OPENSSL_cleanse(aes_key, AES_KEYLEN);
        OPENSSL_cleanse(hmac_key, HMAC_KEYLEN);
        return false;
    }

    std::vector<unsigned char> plaintext(ciphertext_len);
    int len, plaintext_len = 0;

    if (EVP_DecryptInit_ex(ctx, EVP_aes_256_gcm(), nullptr, nullptr, nullptr) != 1 ||
        EVP_DecryptInit_ex(ctx, nullptr, nullptr, aes_key, iv) != 1) {
        debug_log("Failed to initialize decryption.");
        EVP_CIPHER_CTX_free(ctx);
        OPENSSL_cleanse(aes_key, AES_KEYLEN);
        OPENSSL_cleanse(hmac_key, HMAC_KEYLEN);
        return false;
    }

    if (EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_TAG, GCM_TAGLEN, tag) != 1) {
        debug_log("Failed to set GCM tag.");
        EVP_CIPHER_CTX_free(ctx);
        OPENSSL_cleanse(aes_key, AES_KEYLEN);
        OPENSSL_cleanse(hmac_key, HMAC_KEYLEN);
        return false;
    }

    if (EVP_DecryptUpdate(ctx, plaintext.data(), &len, ciphertext.data(), ciphertext_len) != 1) {
        debug_log("Failed to decrypt data.");
        EVP_CIPHER_CTX_free(ctx);
        OPENSSL_cleanse(aes_key, AES_KEYLEN);
        OPENSSL_cleanse(hmac_key, HMAC_KEYLEN);
        return false;
    }
    plaintext_len += len;

    if (EVP_DecryptFinal_ex(ctx, plaintext.data() + len, &len) != 1) {
        debug_log("Failed to finalize decryption.");
        EVP_CIPHER_CTX_free(ctx);
        OPENSSL_cleanse(aes_key, AES_KEYLEN);
        OPENSSL_cleanse(hmac_key, HMAC_KEYLEN);
        return false;
    }
    plaintext_len += len;

    EVP_CIPHER_CTX_free(ctx);

    plaintext_out.assign(reinterpret_cast<char*>(plaintext.data()), plaintext_len);
    debug_log("Decryption completed successfully");
    OPENSSL_cleanse(aes_key, AES_KEYLEN);
    OPENSSL_cleanse(hmac_key, HMAC_KEYLEN);
    return true;
}

bool validate_shadow_file(const std::string& shadow_file, const std::string& username) {
    debug_log("Validating shadow file: " + shadow_file);
    std::ifstream file(shadow_file);
    if (!file) {
        debug_log("Unable to open shadow file: " + shadow_file + " (errno: " + std::to_string(errno) + ")");
        return false;
    }

    std::string line;
    bool found = false;
    while (std::getline(file, line)) {
        debug_log("Processing shadow file line: " + line);
        std::istringstream iss(line);
        std::string user, hash_field;
        if (!std::getline(iss, user, ':') || !std::getline(iss, hash_field, ':')) {
            debug_log("Invalid shadow file format in line: " + line);
            return false;
        }

        if (user.length() > 32 || user.empty()) {
            debug_log("Invalid username length: " + user);
            return false;
        }
        for (char c : user) {
            if (!std::isalnum(c)) {
                debug_log("Invalid characters in username: " + user);
                return false;
            }
        }

        if (hash_field.length() != 64) {
            debug_log("Invalid hash length: " + hash_field);
            return false;
        }
        for (char c : hash_field) {
            if (!std::isxdigit(c)) {
                debug_log("Invalid hash format: " + hash_field);
                return false;
            }
        }

        if (user == username) {
            debug_log("Found user " + username + " in shadow file.");
            found = true;
        }
    }
    file.close();

    if (!found) {
        debug_log("No valid password found for user " + username + " in shadow file.");
        return false;
    }
    debug_log("Shadow file validated successfully.");
    return true;
}

bool store_password(const std::string& password, const std::string& key_file) {
    debug_log("Storing password to key file: " + key_file);
    std::string system_salt = "trm_key_salt_2025";
    if (encrypt_data(password, system_salt, system_salt, key_file)) {
        debug_log("Password stored successfully.");
        return true;
    }
    debug_log("Failed to store password.");
    return false;
}

bool retrieve_password(std::string& password_out, const std::string& key_file) {
    debug_log("Retrieving password from key file: " + key_file);
    std::string system_salt = "trm_key_salt_2025";
    if (decrypt_data(system_salt, system_salt, key_file, password_out)) {
        debug_log("Password retrieved successfully: ");
        return true;
    }
    debug_log("Failed to retrieve password.");
    return false;
}

bool verify_connection(std::string& input_password, bool& password_prompted) {
    std::string shadow_file = "/data/data/com.termux/files/usr/etc/.trm_shadow";
    std::string timestamp_file = "/data/data/com.termux/files/usr/tmp/.trm_sudo_timestamp";
    std::string key_file = "/data/data/com.termux/files/usr/tmp/.trm_sudo_key";
    std::string username = "termux";
    std::string salt = "trm_salt_2025";

    debug_log("Starting verify_connection for user: " + username);
    struct stat file_stat;
    if (stat(shadow_file.c_str(), &file_stat) != 0) {
        debug_log("Shadow file does not exist: " + shadow_file + " (errno: " + std::to_string(errno) + ")");
        return false;
    }

    if (!validate_shadow_file(shadow_file, username)) {
        debug_log("Shadow file validation failed.");
        return false;
    }

    if ((file_stat.st_mode & 0777) != 0600) {
        debug_log("Fixing shadow file permissions.");
        if (chmod(shadow_file.c_str(), 0600) != 0) {
            debug_log("Failed to set shadow file permissions (errno: " + std::to_string(errno) + ")");
        }
    }

    if (stat(key_file.c_str(), &file_stat) == 0) {
        debug_log("Key file exists: " + key_file);
        if ((file_stat.st_mode & 0777) != 0600) {
            debug_log("Fixing key file permissions.");
            if (chmod(key_file.c_str(), 0600) != 0) {
                debug_log("Failed to set key file permissions (errno: " + std::to_string(errno) + ")");
            }
        }

        std::string stored_password;
        if (retrieve_password(stored_password, key_file)) {
            debug_log("Retrieved stored password.");
            if (stat(timestamp_file.c_str(), &file_stat) == 0) {
                debug_log("Timestamp file exists: " + timestamp_file);
                if ((file_stat.st_mode & 0777) != 0600) {
                    debug_log("Fixing timestamp file permissions.");
                    if (chmod(timestamp_file.c_str(), 0600) != 0) {
                        debug_log("Failed to set timestamp file permissions (errno: " + std::to_string(errno) + ")");
                    }
                    uid_t ruid = getuid();
                    gid_t rgid = getgid();
                    if (chown(timestamp_file.c_str(), ruid, rgid) != 0) {
                        debug_log("Failed to set timestamp file ownership (errno: " + std::to_string(errno) + ")");
                    }
                }

                std::string decrypted_ts;
                if (decrypt_data(stored_password, salt, timestamp_file, decrypted_ts)) {
                    debug_log("Decrypted timestamp: " + decrypted_ts);
                    try {
                        long timestamp = std::stol(decrypted_ts);
                        struct timeval current_time;
                        gettimeofday(&current_time, nullptr);
                        long current_seconds = current_time.tv_sec;

                        debug_log("Current time: " + std::to_string(current_seconds) + ", Timestamp: " + std::to_string(timestamp));
                        if (current_seconds < timestamp || (timestamp - current_seconds) > 60) {
                            debug_log("Timestamp invalid, removing files.");
                            unlink(timestamp_file.c_str());
                            unlink(key_file.c_str());
                        } else if (current_seconds - timestamp < TIMEOUT_SECONDS) {
                            debug_log("Timestamp valid, reusing stored password.");
                            input_password = stored_password;
                            return true;
                        } else {
                            debug_log("Timestamp expired, removing files.");
                            unlink(timestamp_file.c_str());
                            unlink(key_file.c_str());
                        }
                    } catch (...) {
                        debug_log("Failed to parse timestamp, removing files.");
                        unlink(timestamp_file.c_str());
                        unlink(key_file.c_str());
                    }
                } else {
                    debug_log("Failed to decrypt timestamp, removing key file.");
                    unlink(key_file.c_str());
                }
            } else {
                debug_log("Timestamp file does not exist, removing key file.");
                unlink(key_file.c_str());
            }
        } else {
            debug_log("Failed to retrieve password, removing key file.");
            unlink(key_file.c_str());
        }
    } else {
        debug_log("Key file does not exist.");
    }

    if (!password_prompted) {
        debug_log("Prompting for password.");
        char* input = getpass("Enter password: ");
        if (!input || strlen(input) == 0) {
            debug_log("Unable to read password.");
            return false;
        }
        input_password = input;
        password_prompted = true;
        debug_log("Password read successfully.");
        OPENSSL_cleanse(input, strlen(input));
    }

    debug_log("Reading shadow file for hash comparison.");
    std::ifstream file(shadow_file);
    std::string stored_hash;
    bool found = false;
    std::string line;
    while (std::getline(file, line)) {
        std::istringstream iss(line);
        std::string user, hash_field;
        std::getline(iss, user, ':');
        std::getline(iss, hash_field, ':');
        if (user == username) {
            stored_hash = hash_field;
            found = true;
            debug_log("Found hash for user " + username + ": " + hash_field);
            break;
        }
    }
    file.close();

    if (!found) {
        debug_log("No valid password found for user " + username + " in shadow file.");
        return false;
    }

    std::string input_hash = derive_hash(input_password, salt);
    debug_log("Computed hash: " + input_hash);
    if (input_hash.size() != stored_hash.size() ||
        CRYPTO_memcmp(input_hash.c_str(), stored_hash.c_str(), input_hash.size()) != 0) {
        debug_log("Password hash mismatch. Access denied.");
        return false;
    }
    debug_log("Password verified successfully.");

    struct timeval current_time;
    gettimeofday(&current_time, nullptr);
    std::string ts_str = std::to_string(current_time.tv_sec);
    debug_log("Creating timestamp: " + ts_str);
    if (!encrypt_data(ts_str, input_password, salt, timestamp_file)) {
        debug_log("Failed to create encrypted timestamp file.");
    } else {
        debug_log("Timestamp file created successfully.");
    }
    if (!store_password(input_password, key_file)) {
        debug_log("Failed to store password in key file.");
    } else {
        debug_log("Password stored in key file successfully.");
    }

    debug_log("verify_connection completed successfully.");
    return true;
}

int main(int argc, char* argv[]) {
    for (int i = 1; i < argc; ++i) {
        if (std::strcmp(argv[i], "--debug") == 0) {
            debug_mode = true;
            break;
        }
    }

    debug_log("Starting main function.");
    std::string shadow_file = "/data/data/com.termux/files/usr/etc/.trm_shadow";

    struct stat file_stat;
    if (stat(shadow_file.c_str(), &file_stat) != 0) {
        debug_log("Shadow file does not exist: " + shadow_file + " (errno: " + std::to_string(errno) + ")");
        return 1;
    }

    std::string password;
    bool password_prompted = false;
    debug_log("Calling verify_connection.");
    if (!verify_connection(password, password_prompted)) {
        debug_log("verify_connection failed, cleaning up password.");
        OPENSSL_cleanse(&password[0], password.size());
        return 1;
    }
    debug_log("verify_connection succeeded, proceeding to shell setup.");
    OPENSSL_cleanse(&password[0], password.size());

    std::string Home = "/data/data/com.termux/files/root-home";
    std::string Term = "xterm-256color";
    std::string AliasFile = Home + "/.aliases";
    std::string TempDir = "/data/data/com.termux/files/usr/tmp";
    std::string LD_LIBRARY_PATH = "/data/data/com.termux/files/usr/lib";
    std::string trm_config = Home + "/.config/TermuxRootMods/.trm";
    std::string theme_name = "none";
    std::string shell_from_config;

    debug_log("Reading config file: " + trm_config);
    std::ifstream config(trm_config);
    if (config) {
        std::string line;
        std::string current;
        while (std::getline(config, line)) {
            debug_log("Processing config line: " + line);
            line.erase(0, line.find_first_not_of(" \t\r\n"));
            line.erase(line.find_last_not_of(" \t\r\n") + 1);
            if (line.empty() || line[0] == ';' || line[0] == '#') continue;
            if (line.front() == '[' && line.back() == ']') {
                current = line.substr(1, line.size() - 2);
                debug_log("Config section: " + current);
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
                if (current == "SHELL" && key == "shell") {
                    env_var = "SHELL";
                    shell_from_config = value;
                } else if (current == "GENERAL" && key == "language") {
                    env_var = "GENERAL_LANGUAGE";
                } else if (current == "THEME" && key == "theme_name") {
                    env_var = "THEME_NAME";
                    theme_name = value;
                }

                if (!env_var.empty()) {
                    debug_log("Setting env var " + env_var + "=" + value);
                    setenv(env_var.c_str(), value.c_str(), 1);
                }
            }
        }
        config.close();
    } else {
        debug_log("Config file not found or unreadable: " + trm_config);
    }

    const char* shell_env = std::getenv("SHELL");
    std::string Shell = shell_env ? shell_env : "/bin/sh";
    debug_log("Initial shell from env: " + Shell);

    if (!shell_from_config.empty()) {
        Shell = shell_from_config;
        debug_log("Shell overridden from config: " + Shell);
    }

    if (access(Shell.c_str(), X_OK) != 0) {
        debug_log("Shell not executable: " + Shell + " (errno: " + std::to_string(errno) + "). Falling back to /bin/sh.");
        Shell = "/bin/sh";
    }
    debug_log("Final shell path: " + Shell);

    setenv("TMPDIR", TempDir.c_str(), 1);
    setenv("LD_LIBRARY_PATH", LD_LIBRARY_PATH.c_str(), 1);
    setenv("TERM", Term.c_str(), 1);
    setenv("HOME", Home.c_str(), 1);
    setenv("SHELL", Shell.c_str(), 1);
    debug_log("Environment variables set: TMPDIR=" + TempDir + ", SHELL=" + Shell);

    const char* path_env = std::getenv("PATH");
    std::string DefaultPath = "/data/data/com.termux/files/usr/bin:/system/bin:/bin:/sbin";
    std::string FullPath = path_env ? std::string(path_env) : DefaultPath;
    if (FullPath.find("/data/data/com.termux/files/usr/bin") == std::string::npos) {
        FullPath += ":/data/data/com.termux/files/usr/bin";
    }
    setenv("PATH", FullPath.c_str(), 1);
    debug_log("PATH set to: " + FullPath);

    std::string PS1;
    if (theme_name == "minimalist") {
        PS1 = "\\[\\e[1;31m\\]⚡\\u \\[\\e[1;33m\\]@ \\[\\e[1;32m\\]\\h \\[\\e[1;36m\\]in \\[\\e[1;34m\\]\\w \\[\\e[1;35m\\]→ \\[\\e[0m\\]";
    } else if (theme_name == "colorful") {
        PS1 = "\033[1;32m\\u@\\h\033[0m:\033[1;34m\\w\033[0m$ ";
    } else if (theme_name == "default") {
        PS1 = "\\[\\e[0;32m\\]\\w\\[\\e[0m\\] \\[\\e[0;97m\\]#\\[\\e[0m\\] ";
    }
    debug_log("PS1 set to: " + PS1);

    std::string temp_bashrc = TempDir + "/bashrc." + std::to_string(getpid());
    debug_log("Creating temporary bashrc: " + temp_bashrc);
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
        debug_log("Temporary bashrc created successfully.");
        if (chmod(temp_bashrc.c_str(), 0600) != 0) {
            debug_log("Failed to set bashrc permissions (errno: " + std::to_string(errno) + ")");
        }
    } else {
        debug_log("Failed to create temporary bashrc: " + temp_bashrc + " (errno: " + std::to_string(errno) + ")");
    }

    debug_log("Preparing to execute shell: " + Shell);
    std::string shell_name = Shell.substr(Shell.find_last_of("/") + 1);
    debug_log("Shell name: " + shell_name);

    if (!temp_bashrc.empty() && std::ifstream(temp_bashrc)) {
        if (shell_name == "bash") {
            debug_log("Executing bash with rcfile: " + temp_bashrc);
            if (execl(Shell.c_str(), Shell.c_str(), "--rcfile", temp_bashrc.c_str(), (char*)nullptr) == -1) {
                debug_log("Failed to execute bash: " + Shell + " (errno: " + std::to_string(errno) + ")");
            }
        } else if (shell_name == "zsh") {
            debug_log("Executing zsh, setting ZDOTDIR: " + TempDir);
            setenv("ZDOTDIR", TempDir.c_str(), 1);
            if (execl(Shell.c_str(), Shell.c_str(), (char*)nullptr) == -1) {
                debug_log("Failed to execute zsh: " + Shell + " (errno: " + std::to_string(errno) + ")");
            }
        } else if (shell_name == "fish") {
            debug_log("Executing fish, setting XDG_CONFIG_HOME: " + TempDir);
            setenv("XDG_CONFIG_HOME", TempDir.c_str(), 1);
            if (execl(Shell.c_str(), Shell.c_str(), (char*)nullptr) == -1) {
                debug_log("Failed to execute fish: " + Shell + " (errno: " + std::to_string(errno) + ")");
            }
        } else {
            debug_log("Executing default shell: " + Shell);
            if (execl(Shell.c_str(), Shell.c_str(), (char*)nullptr) == -1) {
                debug_log("Failed to execute default shell: " + Shell + " (errno: " + std::to_string(errno) + ")");
            }
        }
    } else {
        debug_log("Temporary bashrc not found, executing shell without rcfile.");
        if (execl(Shell.c_str(), Shell.c_str(), (char*)nullptr) == -1) {
            debug_log("Failed to execute shell: " + Shell + " (errno: " + std::to_string(errno) + ")");
        }
    }

    debug_log("Failed to execute shell: " + Shell + " (errno: " + std::to_string(errno) + ")");
    if (!temp_bashrc.empty()) {
        debug_log("Removing temporary bashrc: " + temp_bashrc);
        remove(temp_bashrc.c_str());
    }
    return 1;
}
