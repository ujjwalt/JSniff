// Create bindings for all functions of libpcap and just pass it on. Very simple and light weight

#include <iostream>
#include <node.h>
#include <node_buffer.h>
#include <v8.h>
#include <pcap/pcap.h>
#include <sys/ioctl.h>

using namespace v8;
using namespace node;
using namespace std;

#define RETURN_NULL return (scope.Close(Null()));

#pragma mark Session Definition
class Session : public node::ObjectWrap {
    pcap_t *handle; // the handle to the pcap session 

    static Persistent<Function> constructor;

    Session();
    ~Session();
    static Handle<Value> New(const Arguments &args);
    static Handle<Value> Start(const Arguments &args);
    static Handle<Value> Stop(const Arguments &args);
    static Handle<Value> Stats(const Arguments &args);
    static void PacketReady(u_char *user, const struct pcap_pkthdr *h, const u_char *bytes);

public:
    static void Init();
    static Handle<Value> NewInstance(const Arguments &args);
};


#pragma mark Session Implementation
Session::Session(){}
Session::~Session(){}

Persistent<Function> Session::constructor;

void Session::Init() {
    // Prepare constructor template
    Local<FunctionTemplate> tpl = FunctionTemplate::New(New);
    tpl->SetClassName(String::NewSymbol("Session"));
    tpl->InstanceTemplate()->SetInternalFieldCount(1);
    // Prototype
    tpl->PrototypeTemplate()->Set(String::NewSymbol("start"), FunctionTemplate::New(Start)->GetFunction());
    tpl->PrototypeTemplate()->Set(String::NewSymbol("stop"), FunctionTemplate::New(Stop)->GetFunction());
    tpl->PrototypeTemplate()->Set(String::NewSymbol("stats"), FunctionTemplate::New(Stats)->GetFunction());

    constructor = Persistent<Function>::New(tpl->GetFunction());
}

Handle<Value>
Session::New(const Arguments &args) {
    HandleScope scope;
    Session *sess = new Session();
    TryCatch try_catch;
    // Check for 3 args => dev, mode, filter-string
    if (args.Length() == 3) { 
        if (!args[0]->IsString()) {
            return ThrowException(Exception::TypeError(String::New("CreateSession: args[0] must be a String")));
        }
        if (!args[1]->IsNumber()) {
            return ThrowException(Exception::TypeError(String::New("CreateSession: args[1] must be a Number")));
        }
        if (!args[2]->IsString() && !args[2]->IsNull()) {
            return ThrowException(Exception::TypeError(String::New("CreateSession: args[2] must be a String")));
        }
    } else {
        return ThrowException(Exception::TypeError(String::New("CreateSession: expecting 3 arguments")));
    }
    // Create a pcap session
    String::Utf8Value dev(args[0]->ToString());
    String::Utf8Value filter_exp(args[2]->ToString());
    char errbuf[PCAP_ERRBUF_SIZE];
    bpf_u_int32 net, mask;
    struct bpf_program fp;

    if (pcap_lookupnet(*dev, &net, &mask, errbuf) == -1) {
        net = mask = 0;
        cerr << "Couldn't get netmask for device " << *dev << ": " << errbuf << endl;
    }

    sess->handle = pcap_create(*dev, errbuf);
    if (sess->handle == NULL) {
        return ThrowException(Exception::Error(String::New(errbuf)));
    }

    // 64KB is the max IPv4 packet size
    if (pcap_set_snaplen(sess->handle, 65535) != 0) {
        return ThrowException(Exception::Error(String::New("error setting snaplen")));
    }

    // check for mode
    switch(args[1]->IntegerValue()) {
        case 2:// Promiscious mdoe
        if (pcap_set_promisc(sess->handle, 1) != 0) {
            return ThrowException(Exception::Error(String::New("error setting promiscuous mode")));
        }
        break;

        case 3://Monitor mode
        if (pcap_can_set_rfmon(sess->handle)) {
            if (pcap_set_rfmon(sess->handle, 1) != 0) {
                return ThrowException(Exception::Error(String::New("error setting monitor mode")));
            }
        }
    }

    // Try to set buffer size.  Sometimes the OS has a lower limit that it will silently enforce.
    if (pcap_set_buffer_size(sess->handle, 10*1024*1024) != 0) { // 10 MB - more than enough
        return ThrowException(Exception::Error(String::New("error setting buffer size")));
    }

    // set "timeout" on read, even though we are also setting nonblock below.  On Linux this is required.
    if (pcap_set_timeout(sess->handle, 1000) != 0) {
        return ThrowException(Exception::Error(String::New("error setting read timeout")));
    }

    if (pcap_setnonblock(sess->handle, 1, errbuf) == -1) {
        return ThrowException(Exception::Error(String::New(errbuf)));
    }

    if (!args[2]->IsNull()) {
        // set the filter
        if (pcap_compile(sess->handle, &fp, *filter_exp, 0, net) == -1) {
            cerr << "Couldn't parse filter " << *filter_exp << ": " << pcap_geterr(sess->handle) << endl;
            RETURN_NULL
        }

        if (pcap_setfilter(sess->handle, &fp) == -1) {
            cerr << "Couldn't install filter " << *filter_exp << ": " << pcap_geterr(sess->handle) << endl;
            RETURN_NULL
        }
    }

    if(filter_exp.length() != 0){
      if (pcap_compile(sess->handle, &fp, (char *) *filter_exp, 1, net) == -1) {
        return ThrowException(Exception::Error(String::New(pcap_geterr(sess->handle))));
      }
      
      if (pcap_setfilter(sess->handle, &fp) == -1) {
        return ThrowException(Exception::Error(String::New(pcap_geterr(sess->handle))));
      }
      pcap_freecode(&fp);
    }

    if (try_catch.HasCaught())  {
        FatalException(try_catch);
    }
    // We're done
    sess->Wrap(args.This());
    return args.This();
}

Handle<Value>
Session::NewInstance(const Arguments &args) {
    HandleScope scope;

    const unsigned argc = 3;
    Handle<Value> argv[argc] = {args[0], args[1], args[2]};
    Local<Object> instance = constructor->NewInstance(argc, argv);

    return scope.Close(instance);
}

Handle<Value>
Session::Start(const Arguments &args) {
    HandleScope scope;
    // Start listening
    Session *sess = ObjectWrap::Unwrap<Session>(args.This());
    if (args[0]->IsFunction()) {
        Local<Function> callback = Local<Function>::Cast(args[0]);
        // bind to packet event
        if (pcap_activate(sess->handle) != 0) {
            return ThrowException(Exception::Error(String::New(pcap_geterr(sess->handle))));
        }
        if (args[1]->IsNumber()) {
            if (pcap_loop(sess->handle, args[1]->Int32Value(), PacketReady, (u_char *)&callback) == -1) {
                cerr << "Couldn't start listening " << pcap_geterr(sess->handle) << endl;
            }
        }
    }
    return Undefined();
}

Handle<Value>
Session::Stop(const Arguments &args) {
    HandleScope scope;
    // close the handle
    Session *sess = ObjectWrap::Unwrap<Session>(args.This());
    pcap_close(sess->handle);
    return Undefined();
}

Handle<Value>
Session::Stats(const Arguments &args) {
    HandleScope scope;

    struct pcap_stat ps;
    Session *sess = ObjectWrap::Unwrap<Session>(args.This());

   if (pcap_stats(sess->handle, &ps) == -1) {
        return ThrowException(Exception::Error(String::New("Error in pcap_stats")));
        // TODO - use pcap_geterr to figure out what the error was
    }

    Local<Object> stats_obj = Object::New();

    stats_obj->Set(String::New("received"), Integer::NewFromUnsigned(ps.ps_recv));
    stats_obj->Set(String::New("buffer_drops"), Integer::NewFromUnsigned(ps.ps_drop));
    
    return scope.Close(stats_obj);
}

void Session::PacketReady(u_char *cb, const struct pcap_pkthdr *packet_h, const u_char *bytes) {
    HandleScope scope;

    Local<Function> * callback = (Local<Function>*)cb;

    TryCatch try_catch;

    Local<Object> packet_header = Object::New();
    Local<Object> ts = Object::New();

    ts->Set(String::New("sec"), Integer::NewFromUnsigned(packet_h->ts.tv_sec));
    ts->Set(String::New("usec"), Integer::NewFromUnsigned(packet_h->ts.tv_usec));
    packet_header->Set(String::New("ts"), ts);
    packet_header->Set(String::New("caplen"), Integer::NewFromUnsigned(packet_h->caplen));
    packet_header->Set(String::New("len"), Integer::NewFromUnsigned(packet_h->len));

    Local<Object> packet = Object::New();
    packet->Set(String::New("header"), packet_header);
    packet->Set(String::New("payload"), String::New((const char *)bytes));//how to pass buffer object

    Local<Value> argv[1] = { packet };

    (*callback)->Call(Context::GetCurrent()->Global(), 1, argv);

    if (try_catch.HasCaught())  {
        FatalException(try_catch);
    }
}


#pragma mark Module Setup

Handle<Value>
LibVersion(const Arguments &args) {
    HandleScope scope;
    return scope.Close(String::New(pcap_lib_version()));
}

Handle<Value>
DefaultDevice(const Arguments& args)
{
    HandleScope scope;
    char *dev, errbuf[PCAP_ERRBUF_SIZE];
    dev = pcap_lookupdev(errbuf);
    if (dev == NULL) {
        return ThrowException(Exception::Error(String::New(errbuf)));
    }
    return scope.Close(String::New(dev));
}

Handle<Value>
NewSession(const Arguments &args) {
    HandleScope scope;
    return scope.Close(Session::NewInstance(args));
}

void Init(Handle<Object> target) {
    Session::Init();
    NODE_SET_METHOD(target, "newSession", NewSession);
    NODE_SET_METHOD(target, "defaultDevice", DefaultDevice);
    NODE_SET_METHOD(target, "libVersion", LibVersion);
}

NODE_MODULE(npcap_binding, Init)
