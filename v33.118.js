const base = Module.findBaseAddress("libg.so")
var ntohs = new NativeFunction(Module.findExportByName('libc.so', 'ntohs'), 'uint16', ['uint16']);
var inet_addr = new NativeFunction(Module.findExportByName('libc.so', 'inet_addr'), 'int', ['pointer']);

const RuntimePatcher = {
    nop: function(addr) {
        Memory.patchCode(addr, Process.pageSize, function(code) {
            var writer = new ArmWriter(code, {
                pc: addr
            });
            
            writer.putNop();
            writer.flush();
        });
    },
    ret: function(addr) {
        Memory.patchCode(addr, Process.pageSize, function(code) {
            var writer = new ArmWriter(code, {
                pc: addr
            });
            
            writer.putRet();
            writer.flush();
        });
    },
    replace: function(address, newInsn) {
        Memory.protect(address, newInsn.length, 'rwx');
        address.writeByteArray(newInsn);
        Memory.protect(address, newInsn.length, 'rx');
    },
    jmp: function(addr, target) {
        Memory.patchCode(addr, Process.pageSize, function(code) {
            var writer = new ArmWriter(code, {
                pc: addr
            });
            
            writer.putBranchAddress(target);
            writer.flush();
        });
    }
}

const Redirection = {
    init() {
        Interceptor.attach(Module.findExportByName('libc.so', 'connect'), {
            onEnter: function(args) {
            if (ntohs(Memory.readU16(args[1].add(2))) === 9339) {
                var host = Memory.allocUtf8String("192.168.0.18");
                var htons = new NativeFunction(Module.findExportByName('libc.so', 'ntohs'), 'uint16', ['uint16']);
                args[1].add(2).writeU16(htons(3131));
                Memory.writeInt(args[1].add(4), inet_addr(host));
            }
        }});
    }
}

const PepperKiller = {
    init() {
        Interceptor.attach(base.add(0x8E36C), {
			onEnter(args) {
				this.messaging = args[0];
				args[1] = args[2];
			},
			onLeave() {
				this.messaging.add(0xD0).writeU32(5);
			}
		});

        Interceptor.attach(base.add(0x69565C), function() {
			this.context.r0 = 10100;
		});

        Interceptor.replace(base.add(0x765FCC), new NativeCallback(function() {
			return 0;
		}, 'int', []));

        Interceptor.replace(base.add(0x2C3AF8), new NativeCallback(function(instance, input, output, length) {
			if (length > 0) {
				output.writeByteArray(input.readByteArray(length));
			}
			return 0;
		}, 'int', ['pointer', 'pointer', 'pointer', 'int']));
    }
}

const ArxanPatcher = {
    init() {
        RuntimePatcher.jmp(base.add(0xC8608), base.add(0xC9518)); // TcpSocket::create - crc check
        RuntimePatcher.jmp(base.add(0x1B39BC), base.add(0x1B4A04)); // LoginMessage::encode
        RuntimePatcher.jmp(base.add(0x3464D4), base.add(0x347894)); // InputSystem::update
        RuntimePatcher.jmp(base.add(0x44CFE8), base.add(0x44E394)); // CombatHUD::ultiButtonActivated
        RuntimePatcher.replace(base.add(0x697074), [0x00, 0xF0, 0x20, 0xE3]); // Messaging::onReceive - snprintf("%s/%s/stat")
        
        Interceptor.attach(base.add(0x361A5C), function() { // len check of game.brawlstarsgame.com
            this.context.r1 = 22;
            this.context.r2 = 22;
        })
    }
}

function init() {
    ArxanPatcher.init();
    Redirection.init();
    PepperKiller.init();
}

init()