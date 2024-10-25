import sys
import frida

def on_message(message,data):
    print("[%s] -> %s" % (message, data))


PACKAGE_NAME = "owasp.mstg.uncrackable3"

jscode = """

    var p_pthread_create = Module.findExportByName("libc.so", "pthread_create");
    var pthread_create = new NativeFunction( p_pthread_create, "int", ["pointer", "pointer", "pointer", "pointer"]);
    send("NativeFunction pthread_create() replaced @ " + pthread_create);

    Interceptor.replace( p_pthread_create, new NativeCallback(function (ptr0, ptr1, ptr2, ptr3) {
        send("pthread_create() overloaded");
        var ret = ptr(0);
        if(ptr1.isNull() && ptr3.isNull()) {
            send("loading fake pthread_create because ptr1 and ptr3 are equal to 0!");
        } else {
            send("loading real pthread_create()");
            ret = pthread_create(ptr0,ptr1,ptr2,ptr3);
        }
        send("ret: " + ret);

    }, "int", ["pointer", "pointer", "pointer", "pointer"]));

"""
    
try:
    device = frida.get_usb_device(timeout=10)
    pid = device.spawn([PACKAGE_NAME])  
    print("App is starting ... pid : {}".format(pid))
    process = device.attach(pid)
    device.resume(pid)
    script = process.create_script(jscode)
    script.on('message',on_message)
    print('[*] Running Frida')
    script.load()
    sys.stdin.read()
except Exception as e:
    print(e)
