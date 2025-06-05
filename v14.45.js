const Libg = {
	init() {
		this.base = Module.findBaseAddress('libg.so');
	},
	offset(off) {
		return this.base.add(off);
	}
}


const ArxanPatcher = {
	init() {
		RuntimePatcher.jmp(Libg.offset(0x4CADBC), Libg.offset(0x4CBB10)); // TcpSocket::create - crc check
		RuntimePatcher.jmp(Libg.offset(0x386ED0), Libg.offset(0x387C20)); // LoginMessage::encode
		RuntimePatcher.jmp(Libg.offset(0x381990), Libg.offset(0x382B38)); // InputSystem::update
		RuntimePatcher.jmp(Libg.offset(0x464B2C), Libg.offset(0x465CBC)); // CombatHUD::ultiButtonActivated
	}
}

rpc.exports.init = function() {
	Libg.init();
	ArxanPatcher.init();
}

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