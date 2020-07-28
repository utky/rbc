// Raw representatin of eBPF instruction
// op:8, dst_reg:4, src_reg:4, off:16, imm:32
#[derive(Debug)]
#[repr(C)]
pub struct Insn {
  op: u8,
  reg: u8,
  off: u16,
  imm: u32
}

impl Insn {
  fn new(op: u8, dst_reg: Reg, src_reg: Reg, off: u16, imm: u32) -> Insn {
    Insn {
      op: op,
      reg: (u8::from(dst_reg) << 4) | u8::from(src_reg),
      off: off,
      imm: imm
    }
  }
}

#[derive(Debug)]
pub enum Reg {
  R0,
  R1,
  R2,
  R3,
  R4,
  R5,
  R6,
  R7,
  R8,
  R9,
  R10,
}

impl From<Reg> for u8 {
  fn from(r: Reg) -> Self {
    match r {
      Reg::R0 =>  0,
      Reg::R1 =>  1,
      Reg::R2 =>  2,
      Reg::R3 =>  3,
      Reg::R4 =>  4,
      Reg::R5 =>  5,
      Reg::R6 =>  6,
      Reg::R7 =>  7,
      Reg::R8 =>  8,
      Reg::R9 =>  9,
      Reg::R10 => 10,
    }
  }
}

pub struct Opcode(u8);

// impl Opcode {
//   fn from_arith_jump(class: ) -> Opcdoe {}
//   fn from_load_store() -> Opcode {}
// }

pub enum Class {
  Ld     ,
  Ldx    ,
  St     ,
  Stx    ,
  Alu    ,
  Jmp    ,
  Jmp32  ,
  Alu64  ,
}

impl From<Class> for u8 {
  fn from(c: Class) -> u8 {
    match c {
      Class::Ld    => 0x00 ,
      Class::Ldx   => 0x01 ,
      Class::St    => 0x02 ,
      Class::Stx   => 0x03 ,
      Class::Alu   => 0x04 ,
      Class::Jmp   => 0x05 ,
      Class::Jmp32 => 0x06 ,
      Class::Alu64 => 0x07 ,
    }
  }
}

pub enum OpAlu {
  Add ,
  Sub ,
  Mul ,
  Div ,
  Or  ,
  And ,
  Lsh ,
  Rsh ,
  Neg ,
  Mod ,
  Xor ,
  Mov ,
  Arsh,
  End ,
}

impl From<OpAlu> for u8 {
  fn from(o: OpAlu) -> Self {
    match o {
      OpAlu::Add   => 0x00,
      OpAlu::Sub   => 0x10,
      OpAlu::Mul   => 0x20,
      OpAlu::Div   => 0x30,
      OpAlu::Or    => 0x40,
      OpAlu::And   => 0x50,
      OpAlu::Lsh   => 0x60,
      OpAlu::Rsh   => 0x70,
      OpAlu::Neg   => 0x80,
      OpAlu::Mod   => 0x90,
      OpAlu::Xor   => 0xa0,
      OpAlu::Mov   => 0xb0, /* eBPF only: mov reg to reg */
      OpAlu::Arsh  => 0xc0, /* eBPF only: sign extending shift right */
      OpAlu::End   => 0xd0, /* eBPF only: endianness conversion */
    }
  }
}

pub enum OpJmp {
  Ja,   /* BPF_JMP only */
  Jeq,
  Jgt,
  Jge,
  Jset,
  Jne,  /* eBPF only: jump != */
  Jsgt, /* eBPF only: signed '>' */
  Jsge, /* eBPF only: signed '>=' */
  Call, /* eBPF BPF_JMP only: function call */
  Exit, /* eBPF BPF_JMP only: function return */
  Jlt,  /* eBPF only: unsigned '<' */
  Jle,  /* eBPF only: unsigned '<=' */
  Jslt, /* eBPF only: signed '<' */
  Jsle, /* eBPF only: signed '<=' */
}

impl From<OpJmp> for u8 {
  fn from(o: OpJmp) -> Self {
    match o {
      OpJmp::Ja    => 0x00,
      OpJmp::Jeq   => 0x10,
      OpJmp::Jgt   => 0x20,
      OpJmp::Jge   => 0x30,
      OpJmp::Jset  => 0x40,
      OpJmp::Jne   => 0x50,
      OpJmp::Jsgt  => 0x60,
      OpJmp::Jsge  => 0x70,
      OpJmp::Call  => 0x80,
      OpJmp::Exit  => 0x90,
      OpJmp::Jlt   => 0xa0,
      OpJmp::Jle   => 0xb0,
      OpJmp::Jslt  => 0xc0,
      OpJmp::Jsle  => 0xd0,
    }
  }
}