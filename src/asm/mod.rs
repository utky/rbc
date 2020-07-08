pub struct Reg(u8);
impl Reg {
  fn index(self) -> u8 {
    self.0
  }
}

pub struct Insn {

}

pub struct Opcode(u8);
impl Opcode {
  fn code(self) -> u8 {
    self.0 & 0xF0
  }
  fn source(self) -> u8 {
    self.0 & 0x08
  }
  fn class(self) -> u8 {
    self.0 & 0x06
  }
}

enum Op {
  BPF_LD     ,
  BPF_LDX    ,
  BPF_ST     ,
  BPF_STX    ,
  BPF_ALU    ,
  BPF_JMP    ,
  BPF_JMP32  ,
  BPF_ALU64  ,
}

impl Into<u8> for Op {
  fn into(self) -> u8 {
    match self {
      BPF_LD    => 0x00 ,
      BPF_LDX   => 0x01 ,
      BPF_ST    => 0x02 ,
      BPF_STX   => 0x03 ,
      BPF_ALU   => 0x04 ,
      BPF_JMP   => 0x05 ,
      BPF_JMP32 => 0x06 ,
      BPF_ALU64 => 0x07 ,
    }
  }
}

impl Op {
  fn v(self) -> u8 {

  }
}