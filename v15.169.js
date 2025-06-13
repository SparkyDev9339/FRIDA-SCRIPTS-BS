const base = Module.findBaseAddress("libg.so")
var ntohs = new NativeFunction(Module.findExportByName('libc.so', 'ntohs'), 'uint16', ['uint16']);
var inet_addr = new NativeFunction(Module.findExportByName('libc.so', 'inet_addr'), 'int', ['pointer']);

const ArxanPatcher = {
	init() {
		RuntimePatcher.jmp(base.add(0x444188), base.add(0x4445FC)); // TcpSocket::create - crc check
		RuntimePatcher.jmp(base.add(0x3AB5E0), base.add(0x3AC408)); // LoginMessage::encode
		RuntimePatcher.jmp(base.add(0x412D64), base.add(0x413E98)); // InputSystem::update
		RuntimePatcher.jmp(base.add(0x50A608), base.add(0x50B828)); // CombatHUD::ultiButtonActivated
	}
}

const Redirection = {
    init() {
        Interceptor.attach(Module.findExportByName('libc.so', 'connect'), {
            onEnter: function(args) {
            if (ntohs(Memory.readU16(args[1].add(2))) === 9339) {
                var host = Memory.allocUtf8String("192.168.0.2");
                Memory.writeInt(args[1].add(4), inet_addr(host));
            }
        }});
    }
}

const EncryptionPatcher = {
	init() {
		RuntimePatcher.replace(base.add(0x41C5D8), [0xF4, 0x03, 0x02, 0xAA])
        RuntimePatcher.replace(base.add(0x41C654), [0xA8, 0x00, 0x80, 0x52])

		
		Interceptor.attach(base.add(0x149C2C), function() {
			this.context.w0 = 10100;
		});
		
		Interceptor.replace(base.add(0x5816EC), new NativeCallback(function() {
			return 0;
		}, 'int', []));
		
		Interceptor.replace(base.add(0x1D969C), new NativeCallback(function(instance, input, output, length) {
			if (length > 0) {
				output.writeByteArray(input.readByteArray(length));
			}

			return 0;
		}, 'int', ['pointer', 'pointer', 'pointer', 'int']));

        Interceptor.attach(base.add(0x3E3AF0), {
			onEnter(args) {
				args[3] = ptr(3);
			}
		});
	}
}

rpc.exports.init = function() {
	ArxanPatcher.init();
    EncryptionPatcher.init()
    Redirection.init();
}

const RuntimePatcher = {
    nop: function(addr) {
        Memory.patchCode(addr, Process.pageSize, function(code) {
            var writer = new Arm64Writer(code, {
                pc: addr
            });
            
            writer.putNop();
            writer.flush();
        });
    },
    ret: function(addr) {
        Memory.patchCode(addr, Process.pageSize, function(code) {
            var writer = new Arm64Writer(code, {
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
            var writer = new Arm64Writer(code, {
                pc: addr
            });
            
            writer.putBranchAddress(target);
            writer.flush();
        });
    }
}