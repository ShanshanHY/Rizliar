#include <cstdlib>
#include <unistd.h>
#include <fcntl.h>
#include <android/log.h>
#include <sys/inotify.h>
#include <thread>
#include <sys/stat.h>
#include <vector>
#include <sys/un.h>
#include <shared_mutex>
#include <sstream>
#include <fstream>
#include <map>
#include <sys/system_properties.h>
#include <ctime>

#include "zygisk.hpp"
#include "util.h"
#include "bytehook.h"

using zygisk::Api;
using zygisk::AppSpecializeArgs;
using zygisk::ServerSpecializeArgs;

#define LOG_DEBUG_MPF(...) __android_log_print(ANDROID_LOG_DEBUG, "Rizliar", __VA_ARGS__)
#define LOG_INFO_MPF(...) __android_log_print(ANDROID_LOG_INFO, "Rizliar", __VA_ARGS__)
#define LOG_WARN_MPF(...) __android_log_print(ANDROID_LOG_WARN, "Rizliar", __VA_ARGS__)
#define LOG_ERROR_MPF(...) __android_log_print(ANDROID_LOG_ERROR, "Rizliar", __VA_ARGS__)
#define LOG_BYTE_HOOK(fmt, ...) __android_log_print(ANDROID_LOG_DEBUG, "ByteHook", fmt, ##__VA_ARGS__)

static std::vector<std::string> packages_2_work;
static long time_next_read_packages_2_work = 0;
const static std::string conf_file_path = "/data/adb/modules/rizliar/packages.txt";
// properties to hack.
const static char *sim_hack = "hk";
const static std::map<std::string, std::string> props_4_hack{
        {"gsm.sim.operator.iso-country",   sim_hack}
};

// callback func for __system_property_read_callback
typedef void (*spr_param_cb_t)(void *cookie,
                               const char *name,
                               const char *value,
                               uint32_t serial);

// __system_property_read_callback
typedef void (*__system_property_read_callback_t)(const prop_info *pi,
                                                  spr_param_cb_t *callback,
                                                  void *cookie);

// __system_property_get
typedef int (*__system_property_get_t)(const char *name, char *value);

#define MPF_BHOOK_DEF(fn)                                                                                     \
  static fn##_t fn##_prev = nullptr;                                                                         \
  static bytehook_stub_t fn##_stub = nullptr;                                                                \
  static void fn##_hooked_callback(bytehook_stub_t task_stub, int status_code, const char *caller_path_name, \
                                   const char *sym_name, void *new_func, void *prev_func, void *arg) {       \
    if (BYTEHOOK_STATUS_CODE_ORIG_ADDR == status_code) {                                                     \
      fn##_prev = (fn##_t)prev_func;                                                                         \
      LOG_BYTE_HOOK(">>>>> save original address: %lu", (unsigned long)prev_func);                           \
    } else {                                                                                                 \
      LOG_BYTE_HOOK(">>>>> hooked. stub: %lu, status: %d, caller_path_name: %s, sym_name: %s, new_func: %lu, prev_func: %lu, arg: %lu", \
          (unsigned long)task_stub, status_code, caller_path_name, sym_name, (unsigned long)new_func,        \
          (unsigned long)prev_func, (unsigned long)arg);                                                     \
    }                                                                                                        \
  }

MPF_BHOOK_DEF(__system_property_read_callback)

MPF_BHOOK_DEF(__system_property_get)

thread_local spr_param_cb_t spr_param_cb_prev = nullptr;

static void spr_param_cb_new(void *cookie, const char *name, const char *value, uint32_t serial) {
    if (spr_param_cb_prev == nullptr) {
        LOG_ERROR_MPF("spr_param_cb_new previous function is null");
    }
    auto search_ = props_4_hack.find(name);
    if (search_ != props_4_hack.end()) {
        LOG_DEBUG_MPF("spr_param_cb_new: [%s] -> [%s]", name,
                     search_->second.c_str());
        return spr_param_cb_prev(cookie, name, search_->second.c_str(), serial);
    }
    LOG_DEBUG_MPF("spr_param_cb_new call prev: [%s] -> [%s]", name,
                 search_->second.c_str());
    spr_param_cb_prev(cookie, name, value, serial);
}

static void system_property_read_callback_new(const prop_info *pi,
                                              spr_param_cb_t callback,
                                              void *cookie) {
    BYTEHOOK_STACK_SCOPE();
    if (pi == nullptr) {
        LOG_DEBUG_MPF("system_property_read_callback_new prop_info is null");
        return;
    }
    spr_param_cb_prev = callback;
    LOG_DEBUG_MPF("system_property_read_callback_new call prev: prop_info[%lu] cookie[%lu]",
                 (unsigned long) pi, (unsigned long) cookie);
    BYTEHOOK_CALL_PREV(system_property_read_callback_new, pi, spr_param_cb_new, cookie);
}

static int system_property_get_new(const char *name, char *value) {
    BYTEHOOK_STACK_SCOPE();
    auto search_ = props_4_hack.find(name);
    if (search_ != props_4_hack.end()) {
        strcpy(value, search_->second.c_str());
        LOG_DEBUG_MPF("system_property_get_new: [%s] -> [%s]", name, value);
        return 1;
    }
    LOG_DEBUG_MPF("system_property_get_new call prev: [%s] -> [%s]", name, value);
    return BYTEHOOK_CALL_PREV(system_property_get_new, name, value);
}

static void read_packages_2_work(const std::string &file) {
    packages_2_work.clear();
    std::ifstream i_file_(file);
    std::string line_;
    while (std::getline(i_file_, line_)) {
        trim(line_);
        if (line_.empty()) {
            continue;
        }
        packages_2_work.push_back(line_);
    }
    for (const auto &p: packages_2_work) {
        LOG_INFO_MPF("Rizliar works on: [%s]", p.c_str());
    }
}

class RizliarModule : public zygisk::ModuleBase {
public:
    void onLoad(Api *pApi, JNIEnv *pEnv) override {
        this->api = pApi;
        this->env = pEnv;
        LOG_INFO_MPF("module loaded");
    }

    void preAppSpecialize(AppSpecializeArgs *args) override {
        // Use JNI to fetch our process name
        const char *process = env->GetStringUTFChars(args->nice_name, nullptr);
        pre_specialize(process);
        env->ReleaseStringUTFChars(args->nice_name, process);
    }

    void preServerSpecialize(ServerSpecializeArgs *args) override {
        pre_specialize("system_server");
    }


private:
    Api *api{};
    JNIEnv *env{};
    bool IfManipulate = false;

    bool is_process_2_work(const char *process) {
        int match_ = 0;
        LOG_DEBUG_MPF("process=[%s]", process);
        int fd = api->connectCompanion();
        if (write(fd, process, strlen(process) + 1) <= 0) {
            LOG_WARN_MPF("write socket failed");
        }
        if (read(fd, &match_, sizeof(match_)) <= 0) {
            LOG_WARN_MPF("read socket failed");
        }
        close(fd);
        LOG_DEBUG_MPF("process=[%s] to manipulate: %d", process, match_);
        return match_ > 0;
    }

    void pre_specialize(const char *process) {
        LOG_INFO_MPF("Zygisk preSpecialize within [%s]", process);
        bytehook_init(BYTEHOOK_MODE_AUTOMATIC, false);
        if (is_process_2_work(process)) {
            this->IfManipulate = true;
            LOG_INFO_MPF("Will hook property functions");
            auto hook_stub_ = bytehook_hook_all(nullptr, "__system_property_get",
                                                (void *) system_property_get_new,
                                                __system_property_get_hooked_callback, nullptr);
            LOG_DEBUG_MPF("hook result __system_property_get stub: %ld",
                          (unsigned long) hook_stub_);
            hook_stub_ = bytehook_hook_all(nullptr, "__system_property_read_callback",
                                           (void *) system_property_read_callback_new,
                                           __system_property_read_callback_hooked_callback,
                                           nullptr);
            LOG_DEBUG_MPF("hook result __system_property_read_callback stub: %ld",
                          (unsigned long) hook_stub_);

        }
    }
};

static std::mutex conf_mutex;

static void companion_handler(int fd) {
    if (access(conf_file_path.c_str(), F_OK) != 0) {
        LOG_ERROR_MPF("can't access config file");
        return;
    }
    std::lock_guard<std::mutex> lock(conf_mutex);
    auto now_ts_ = std::time(nullptr);
    if (now_ts_ > time_next_read_packages_2_work) {
        read_packages_2_work(conf_file_path);
        time_next_read_packages_2_work = now_ts_ + 60; // reread after seconds.
    }
    char buff_[BUFSIZ];
    memset(buff_, 0, BUFSIZ);
    if (read(fd, buff_, BUFSIZ) <= 0) {
        return;
    }
    auto package_ = std::string(buff_);
    LOG_DEBUG_MPF("package [%s] for matching", package_.c_str());
    int match_ = 0;
    for (auto &p: packages_2_work) {
        trim(p);
        trim(package_);
        std::transform(p.begin(), p.end(), p.begin(),
                       [](unsigned char c){ return std::tolower(c); });
        std::transform(package_.begin(), package_.end(), package_.begin(),
                       [](unsigned char c){ return std::tolower(c); });
        if (strncmp(p.c_str(), package_.c_str(), strlen(p.c_str())) == 0) {
            match_ = 1;
            LOG_DEBUG_MPF("package [%s] match %s", package_.c_str(), p.c_str());
        }
    }
    LOG_DEBUG_MPF("package [%s] match result: %d", package_.c_str(), match_);
    if (write(fd, &match_, sizeof(match_)) < sizeof(match_)) {
        LOG_ERROR_MPF("partial/failed write");
    }
}

REGISTER_ZYGISK_MODULE(RizliarModule)

REGISTER_ZYGISK_COMPANION(companion_handler)
