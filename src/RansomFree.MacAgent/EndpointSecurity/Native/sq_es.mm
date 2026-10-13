#include "sq_es.h"
#import <Foundation/Foundation.h>
#include <EndpointSecurity/EndpointSecurity.h>
#include <bsm/libbsm.h>
#include <mach/mach.h>
#include <array>
#include <atomic>
#include <cstring>
#include <memory>
#include <mutex>
#include <stdexcept>
#include <future>
#include <thread>
#include <chrono>
#include <iterator>

namespace {
constexpr size_t max_bytes = 65536, slots = 64;
struct Record { uint32_t size = 0; std::array<uint8_t, max_bytes> data; };
struct State {
    std::mutex mutex;
    std::array<Record, slots> queue;
    size_t head = 0, count = 0;
    std::atomic<bool> accepting{true};
    std::atomic<uint64_t> loss{0};
    // Apple delivers callbacks serially for each client. Only callback accesses sequences.
    uint64_t previous = 0;
    bool have_previous = false;
};
struct Handle { es_client_t *client = nullptr; std::shared_ptr<State> state; };
std::atomic<bool> poisoned{false};
std::atomic<bool> active{false}; // At most one live or abandoned client in this process.

NSString *token(es_string_token_t value, size_t limit) {
    if (value.length > limit || (value.length && !value.data)) throw std::runtime_error("token bound");
    if (!value.length) return @"";
    NSString *result = [[NSString alloc] initWithBytes:value.data length:value.length encoding:NSUTF8StringEncoding];
    if (!result) throw std::runtime_error("non UTF8 token");
    return result;
}
NSString *path(const es_file_t *file, bool &truncated) {
    if (!file) throw std::runtime_error("missing file");
    truncated |= file->path_truncated;
    return token(file->path, 4096);
}

// This serializes a selected-field SDK snapshot, NOT a byte dump of pointer-bearing es_message_t.
// No AUTH messages, successful reads, copy intent, encryption inference or response authority.
NSData *snapshot(const es_message_t *message) {
    if (!message || message->action_type != ES_ACTION_TYPE_NOTIFY) throw std::runtime_error("not notify");
    bool truncated = false;
    NSString *source = nil, *target = nil, *operation = @"Unknown", *event = nil;
    NSMutableDictionary *details = [NSMutableDictionary dictionary];
    switch (message->event_type) {
    case ES_EVENT_TYPE_NOTIFY_OPEN:
        event = @"NOTIFY_OPEN"; operation = @"OpenIntent";
        source = path(message->event.open.file, truncated);
        details[@"fflag"] = @(message->event.open.fflag); break;
    case ES_EVENT_TYPE_NOTIFY_WRITE:
        event = @"NOTIFY_WRITE"; operation = @"Write";
        source = path(message->event.write.target, truncated); break;
    case ES_EVENT_TYPE_NOTIFY_CLOSE:
        event = @"NOTIFY_CLOSE";
        if (message->event.close.modified) operation = @"ModifiedClose";
        details[@"modified"] = @(message->event.close.modified);
        source = path(message->event.close.target, truncated); break;
    case ES_EVENT_TYPE_NOTIFY_UNLINK:
        event = @"NOTIFY_UNLINK"; operation = @"Delete";
        source = path(message->event.unlink.target, truncated); break;
    case ES_EVENT_TYPE_NOTIFY_RENAME: {
        event = @"NOTIFY_RENAME"; operation = @"Rename";
        const auto &rename = message->event.rename;
        source = path(rename.source, truncated);
        if (rename.destination_type == ES_DESTINATION_TYPE_EXISTING_FILE)
            target = path(rename.destination.existing_file, truncated);
        else if (rename.destination_type == ES_DESTINATION_TYPE_NEW_PATH) {
            NSString *dir = path(rename.destination.new_path.dir, truncated);
            NSString *name = token(rename.destination.new_path.filename, 4096);
            if (!name.length || [name containsString:@"/"] || [name isEqual:@"."] || [name isEqual:@".."]) throw std::runtime_error("filename");
            target = [dir stringByAppendingFormat: [dir hasSuffix:@"/"] ? @"%@" : @"/%@", name];
            if ([target lengthOfBytesUsingEncoding:NSUTF8StringEncoding] > 4096) throw std::runtime_error("target bound");
        } else throw std::runtime_error("unknown rename union");
        break;
    }
    case ES_EVENT_TYPE_NOTIFY_SETMODE:
        event = @"NOTIFY_SETMODE"; operation = @"Permissions";
        source = path(message->event.setmode.target, truncated);
        details[@"mode"] = @(message->event.setmode.mode); break;
    default: throw std::runtime_error("unsubscribed event");
    }
    NSMutableDictionary *result = [@{ @"schema": @1, @"version": @(message->version),
        @"seconds": @(message->time.tv_sec), @"nanoseconds": @(message->time.tv_nsec),
        @"event": event, @"operation": operation, @"source": source,
        @"details": details } mutableCopy];
    if (target) result[@"target"] = target;
    if (message->version >= 4) result[@"globalSequence"] = @(message->global_seq_num);
    if (message->version >= 2) result[@"sequence"] = @(message->seq_num);
    if (message->process) {
        const auto *p = message->process;
        const auto a = p->audit_token;
        NSMutableString *hex = [NSMutableString stringWithCapacity:sizeof(a) * 2];
        const auto *bytes = reinterpret_cast<const unsigned char *>(&a);
        for (size_t i = 0; i < sizeof(a); ++i) [hex appendFormat:@"%02x", bytes[i]];
        NSMutableDictionary *actor = [@{ @"AuditTokenHex": hex, @"ParentPid": @(p->ppid),
            @"RealUserId": @(audit_token_to_ruid(a)), @"EffectiveUserId": @(audit_token_to_euid(a)),
            @"SessionId": @(audit_token_to_asid(a)) } mutableCopy];
        if (audit_token_to_auid(a) != static_cast<au_id_t>(AU_DEFAUDITID)) actor[@"AuditUserId"] = @(audit_token_to_auid(a));
        pid_t pid = audit_token_to_pid(a);
        if (pid > 0) actor[@"Pid"] = @(pid);
        // A truncated executable is not presented as an exact executable identity.
        if (p->executable && !p->executable->path_truncated) actor[@"Executable"] = path(p->executable, truncated);
        NSString *signing = token(p->signing_id, 512), *team = token(p->team_id, 512);
        if (signing.length) actor[@"SigningId"] = signing;
        if (team.length) actor[@"TeamId"] = team;
        result[@"actor"] = actor;
    }
    result[@"truncated"] = @(truncated);
    return [NSJSONSerialization dataWithJSONObject:result options:NSJSONWritingSortedKeys error:nil];
}

void receive(const std::shared_ptr<State> &state, const es_message_t *message) noexcept {
    if (!state->accepting.load()) return;
    // Own an explicit retain for exactly the serialization scope; never queue native pointers.
    es_retain_message(message);
    struct Release { const es_message_t *m; ~Release() { es_release_message(m); } } release{message};
    @autoreleasepool {
        @try {
            try {
                // Global sequence avoids double-counting overlapping per-type and global gaps.
                if (message->version >= 4) {
                    uint64_t current = message->global_seq_num;
                    if (state->have_previous && current > state->previous && current - state->previous > 1)
                        state->loss.fetch_add(current - state->previous - 1);
                    else if (state->have_previous && current <= state->previous) state->loss.fetch_add(1);
                    state->previous = current; state->have_previous = true;
                } else {
                    // macOS 11+ transport requires v4 global loss accounting; fail closed per record.
                    state->loss.fetch_add(1); return;
                }
                NSData *data = snapshot(message);
                if (!data || !data.length || data.length > max_bytes) { state->loss.fetch_add(1); return; }
                std::unique_lock<std::mutex> lock(state->mutex, std::try_to_lock);
                if (!lock.owns_lock()) { state->loss.fetch_add(1); return; }
                if (!state->accepting.load()) return;
                if (state->count == slots) { state->loss.fetch_add(1); return; }
                auto &record = state->queue[(state->head + state->count) % slots];
                record.size = static_cast<uint32_t>(data.length);
                std::memcpy(record.data.data(), data.bytes, record.size); ++state->count;
            } catch (...) { state->loss.fetch_add(1); }
        } @catch (NSException *) { state->loss.fetch_add(1); }
    }
}
}

uint32_t sq_es_abi(void) { return 1; }
int32_t sq_es_open(void **output) {
    if (!output) return 5;
    *output = nullptr;
    if (poisoned.load()) return 6;
    try {
        auto handle = std::make_unique<Handle>();
        auto state = std::make_shared<State>(); handle->state = state;
        bool expected = false;
        if (!active.compare_exchange_strong(expected, true)) return 6;
        auto result = es_new_client(&handle->client, ^(es_client_t *, const es_message_t *message) { receive(state, message); });
        if (result != ES_NEW_CLIENT_RESULT_SUCCESS) {
            active.store(false);
            switch (result) {
            case ES_NEW_CLIENT_RESULT_ERR_NOT_ENTITLED: return 1;
            case ES_NEW_CLIENT_RESULT_ERR_NOT_PERMITTED: return 2;
            case ES_NEW_CLIENT_RESULT_ERR_NOT_PRIVILEGED: return 3;
            default: return 5;
            }
        }
        // Mute this exact process identity before subscribing to avoid evidence-write feedback.
        // Obtain the kernel audit token; never synthesize a token from a PID.
        audit_token_t self{};
        mach_msg_type_number_t count = TASK_AUDIT_TOKEN_COUNT;
        if (task_info(mach_task_self(), TASK_AUDIT_TOKEN, reinterpret_cast<task_info_t>(&self), &count) != KERN_SUCCESS
            || count != TASK_AUDIT_TOKEN_COUNT || es_mute_process(handle->client, &self) != ES_RETURN_SUCCESS)
            return sq_es_close(handle.release()) == 0 ? 4 : 6;
        const es_event_type_t events[] = { ES_EVENT_TYPE_NOTIFY_OPEN, ES_EVENT_TYPE_NOTIFY_WRITE,
            ES_EVENT_TYPE_NOTIFY_CLOSE, ES_EVENT_TYPE_NOTIFY_UNLINK, ES_EVENT_TYPE_NOTIFY_RENAME, ES_EVENT_TYPE_NOTIFY_SETMODE };
        if (es_subscribe(handle->client, events, static_cast<uint32_t>(std::size(events))) != ES_RETURN_SUCCESS) {
            return sq_es_close(handle.release()) == 0 ? 4 : 6;
        }
        *output = handle.release(); return 0;
    } catch (...) { if (active.load()) poisoned.store(true); return 5; }
}
int32_t sq_es_read(void *value, uint8_t *bytes, uint32_t capacity, uint64_t *loss) {
    if (!value || !bytes || capacity < max_bytes || !loss) return -1;
    auto &state = *static_cast<Handle *>(value)->state;
    std::lock_guard<std::mutex> lock(state.mutex);
    *loss = state.loss.exchange(0);
    if (!state.count) return 0;
    auto &record = state.queue[state.head];
    std::memcpy(bytes, record.data.data(), record.size);
    state.head = (state.head + 1) % slots; --state.count;
    return static_cast<int32_t>(record.size);
}
int32_t sq_es_close(void *value) {
    if (!value) return 0;
    std::unique_ptr<Handle> handle(static_cast<Handle *>(value));
    handle->state->accepting.store(false);
    // No managed callback is captured, even if the OS never returns from deletion.
    // The fixed queue/state stays owned by the block. Never unload this library after use.
    try {
        auto complete = std::make_shared<std::promise<int32_t>>();
        auto done = complete->get_future();
        std::thread([owned = std::move(handle), complete]() {
            auto unsubscribed = es_unsubscribe_all(owned->client);
            auto deleted = es_delete_client(owned->client);
            int32_t result = unsubscribed == ES_RETURN_SUCCESS && deleted == ES_RETURN_SUCCESS ? 0 : 6;
            if (result != 0) poisoned.store(true);
            if (deleted == ES_RETURN_SUCCESS) active.store(false);
            complete->set_value(result);
        }).detach();
        if (done.wait_for(std::chrono::seconds(2)) == std::future_status::ready) return done.get();
    } catch (...) { }
    poisoned.store(true);
    return 6;
}
