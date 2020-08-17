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
  pub fn new<O>(op: O, dst_reg: Reg, src_reg: Reg, off: u16, imm: u32) -> Insn
    where O: Into<Opcode> {
    Insn {
      op: op.into().0,
      reg: (dst_reg as u8) << 4 | src_reg as u8,
      off: off,
      imm: imm
    }
  }

  pub fn serialize(self) -> [u8; 8] {
    let opreg: [u8; 2] = [ self.op, self.reg ];
    let mut off: [u8; 2];
    let mut imm: [u8; 4];
    [1 .. 0].iter().for_each(|i|
      off.insert(i, (self.off & (0xFF << i * 8)) >> (i * 8))
    );
    [3 .. 0].iter().for_each(|i|
      imm.insert(i, (self.imm & (0xFF << i * 8)) >> (i * 8))
    );
    [opreg, off, imm].concat()
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
      Reg::R0  =>  0,
      Reg::R1  =>  1,
      Reg::R2  =>  2,
      Reg::R3  =>  3,
      Reg::R4  =>  4,
      Reg::R5  =>  5,
      Reg::R6  =>  6,
      Reg::R7  =>  7,
      Reg::R8  =>  8,
      Reg::R9  =>  9,
      Reg::R10 => 10,
    }
  }
}

#[derive(Debug)]
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

#[derive(Debug)]
pub struct Opcode(u8);

#[derive(Debug)]
pub struct AluJmp(u8);

impl AluJmp {
  #[inline(always)]
  fn code(self) -> u8 {
    (self.0 & 0xF0) >> 4
  }

  #[inline(always)]
  fn source(self) -> u8 {
    (self.0 & 0x08) >> 3
  }

  #[inline(always)]
  fn class(self) -> u8 {
    self.0 & 0x07
  }
}

impl From<AluJmp> for Opcode {
  fn from(o: AluJmp) -> Self { Opcode(o.0) }
}

#[derive(Debug)]
pub enum Src {
  K,
  X,
}

impl From<Src> for u8 {
  fn from(s: Src) -> Self {
    match s {
      Src::K   => 0x00,
      Src::X   => 0x08,
    }
  }
}

#[derive(Debug)]
pub enum Alu {
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

impl Alu {
  #[inline(always)]
  fn make(self, source: Src) -> AluJmp {
    AluJmp(u8::from(self) | u8::from(source) | u8::from(Class::Alu64))
  }
}

impl From<Alu> for u8 {
  fn from(o: Alu) -> Self {
    match o {
      Alu::Add   => 0x00,
      Alu::Sub   => 0x10,
      Alu::Mul   => 0x20,
      Alu::Div   => 0x30,
      Alu::Or    => 0x40,
      Alu::And   => 0x50,
      Alu::Lsh   => 0x60,
      Alu::Rsh   => 0x70,
      Alu::Neg   => 0x80,
      Alu::Mod   => 0x90,
      Alu::Xor   => 0xa0,
      Alu::Mov   => 0xb0, /* eBPF only: mov reg to reg */
      Alu::Arsh  => 0xc0, /* eBPF only: sign extending shift right */
      Alu::End   => 0xd0, /* eBPF only: endianness conversion */
    }
  }
}

#[derive(Debug)]
pub enum Jmp {
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

impl Jmp {
  #[inline(always)]
  fn make(self, source: Src) -> AluJmp {
    AluJmp(u8::from(self) | u8::from(source) | u8::from(Class::Jmp64))
  }
}

impl From<Jmp> for u8 {
  fn from(o: Jmp) -> Self {
    match o {
      Jmp::Ja    => 0x00,
      Jmp::Jeq   => 0x10,
      Jmp::Jgt   => 0x20,
      Jmp::Jge   => 0x30,
      Jmp::Jset  => 0x40,
      Jmp::Jne   => 0x50,
      Jmp::Jsgt  => 0x60,
      Jmp::Jsge  => 0x70,
      Jmp::Call  => 0x80,
      Jmp::Exit  => 0x90,
      Jmp::Jlt   => 0xa0,
      Jmp::Jle   => 0xb0,
      Jmp::Jslt  => 0xc0,
      Jmp::Jsle  => 0xd0,
    }
  }
}

#[derive(Debug)]
pub struct StLd(u8);

impl StLd {
  #[inline(always)]
  fn mode(self) -> u8 {
    (self.0 & 0xE0) >> 5
  }

  #[inline(always)]
  fn size(self) -> u8 {
    (self.0 & 0x18) >> 3
  }

  #[inline(always)]
  fn class(self) -> u8 {
    self.0 & 0x07
  }
}

impl From<StLd> for Opcode {
  fn from(o: StLd) -> Self { Opcode(o.0) }
}

#[cfg(test)]
mod test {
  use super::*;
  fn encode() {
    let insn = Insn::new(Jmp::Exit, Reg::R0, 0, 0, 0)
    assert_eq!()
    asm::Insn{ op: 0x05 | 0x90, reg: 0, off: 0, imm: 0 },
  }
}