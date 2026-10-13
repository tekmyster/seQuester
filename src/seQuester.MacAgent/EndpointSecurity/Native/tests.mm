// SDK-only synthetic snapshots: no client, entitlement, TCC, signing or host activity.
#include "sq_es.mm"
#include <cassert>
int main() {
    @autoreleasepool {
        es_file_t file{}; file.path = { 7, "/canary" };
        es_message_t message{};
        message.version = 4; message.action_type = ES_ACTION_TYPE_NOTIFY;
        message.event_type = ES_EVENT_TYPE_NOTIFY_CLOSE;
        message.event.close.target = &file;
        NSDictionary *closed = [NSJSONSerialization JSONObjectWithData:snapshot(&message) options:0 error:nil];
        assert([closed[@"operation"] isEqual:@"Unknown"]);
        assert(!closed[@"actor"]);
        message.event.close.modified = true;
        closed = [NSJSONSerialization JSONObjectWithData:snapshot(&message) options:0 error:nil];
        assert([closed[@"operation"] isEqual:@"ModifiedClose"]);
        file.path_truncated = true;
        closed = [NSJSONSerialization JSONObjectWithData:snapshot(&message) options:0 error:nil];
        assert([closed[@"truncated"] boolValue]);
        file.path_truncated = false;
        message.event_type = ES_EVENT_TYPE_NOTIFY_RENAME;
        message.event.rename.source = &file;
        message.event.rename.destination_type = ES_DESTINATION_TYPE_NEW_PATH;
        message.event.rename.destination.new_path.dir = &file;
        message.event.rename.destination.new_path.filename = { 3, "new" };
        NSDictionary *renamed = [NSJSONSerialization JSONObjectWithData:snapshot(&message) options:0 error:nil];
        assert([renamed[@"target"] isEqual:@"/canary/new"]);
        file.path.length = 4097;
        bool rejected = false;
        try { snapshot(&message); } catch (...) { rejected = true; }
        assert(rejected);
        assert(sq_es_abi() == 1);
        assert(sq_es_open(nullptr) == 5);
        assert(sq_es_read(nullptr, nullptr, 0, nullptr) == -1);
        assert(sq_es_close(nullptr) == 0);
    }
}
