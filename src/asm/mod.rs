// Raw representatin of eBPF instruction
// op:8, dst_reg:4, src_reg:4, off:16, imm:32
#[derive(Debug)]
#[repr(C)]
pub struct Insn {
  op: u8,
  reg: u8,
  off: i16,
  imm: i32
}

impl Insn {
  pub fn new(op: Opcode, dst_reg: Reg, src_reg: Reg, off: i16, imm: i32) -> Insn {
    Insn {
      op: u8::from(op),
      reg: u8::from(dst_reg) << 4 | u8::from(src_reg),
      off: off,
      imm: imm
    }
  }

  pub fn serialize(&self) -> [u8; 8] {
    [
      self.op,
      self.reg,
      (self.off >> 8) as u8,
      self.off as u8,
      (self.imm >> 24) as u8,
      (self.imm >> 16) as u8,
      (self.imm >> 8) as u8,
      self.imm as u8,
    ]
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
pub enum Opcode {
  Ld(Mode, Size),
  Ldx(Mode, Size),
  St(Mode, Size),
  Stx(Mode, Size),
  Alu(Alu, Src),
  Jmp(Jmp, Src),
  Jmp32(Jmp, Src),
  Alu64(Alu, Src),
}

impl From<Opcode> for u8 {
  fn from(o: Opcode) -> u8 {
    match o {
      Opcode::Ld(mode, size)  => u8::from(mode) | u8::from(size) | 0x00,
      Opcode::Ldx(mode, size) => u8::from(mode) | u8::from(size) | 0x01,
      Opcode::St(mode, size)  => u8::from(mode) | u8::from(size) | 0x02,
      Opcode::Stx(mode, size) => u8::from(mode) | u8::from(size) | 0x03,
      Opcode::Alu(alu, src)   => u8::from(alu)  | u8::from(src)  | 0x04,
      Opcode::Jmp(jmp, src)   => u8::from(jmp)  | u8::from(src)  | 0x05,
      Opcode::Jmp32(jmp, src) => u8::from(jmp)  | u8::from(src)  | 0x06,
      Opcode::Alu64(alu, src) => u8::from(alu)  | u8::from(src)  | 0x07,
    }
  }
}

/// 4th bit encodes source operand
#[derive(Debug)]
pub enum Src {
  /// use 32-bit immediate as source operand
  K,
  /// use 'src_reg' register as source operand
  X,
}

impl From<Src> for u8 {
  fn from(s: Src) -> Self {
    match s {
      Src::K => 0x00,
      Src::X => 0x08,
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
  End(Endiness),
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
      Alu::End(endiness)   => 0xd0 | u8::from(endiness), /* eBPF only: endianness conversion */
    }
  }
}

#[derive(Debug)]
pub enum Endiness {
  Le,
  Be,
}

impl From<Endiness> for u8 {
  fn from(o: Endiness) -> Self {
    match o {
      Endiness::Le => 0x00,
      Endiness::Be => 0x08,
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
  /// eBPF only: jump !=
  Jne,
  /// eBPF only: signed '>'
  Jsgt,
  /// eBPF only: signed '>='
  Jsge,
  /// eBPF BPF_JMP only: function call
  Call,
  /// eBPF BPF_JMP only: function return
  Exit,
  /// eBPF only: unsigned '<'
  Jlt,
  /// eBPF only: unsigned '<='
  Jle,
  /// eBPF only: signed '<'
  Jslt,
  /// eBPF only: signed '<='
  Jsle,
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
pub enum Size {
  /// word
  W,
  /// half word
  H,
  /// byte
  B,
  /// eBPF only, double word
  DW,
}

impl From<Size> for u8 {
  fn from(s: Size) -> Self {
    match s {
      Size::W  => 0x00, /* word */
      Size::H  => 0x08, /* half word */
      Size::B  => 0x10, /* byte */
      Size::DW => 0x18, /* eBPF only, double word */
    }
  }
}

#[derive(Debug)]
pub enum Mode {
  Imm, /* used for 32-bit mov in classic BPF and 64-bit in eBPF */
  Abs,
  Ind,
  Mem,
  Len, /* classic BPF only, reserved in eBPF */
  Msh, /* classic BPF only, reserved in eBPF */
  Xadd, /* eBPF only, exclusive add */
}

impl From<Mode> for u8 {
  fn from(m: Mode) -> Self {
    match m {
      Mode::Imm  => 0x00, /* used for 32-bit mov in classic BPF and 64-bit in eBPF */
      Mode::Abs  => 0x20,
      Mode::Ind  => 0x40,
      Mode::Mem  => 0x60,
      Mode::Len  => 0x80, /* classic BPF only, reserved in eBPF */
      Mode::Msh  => 0xa0, /* classic BPF only, reserved in eBPF */
      Mode::Xadd => 0xc0, /* eBPF only, exclusive add */
    }
  }
}

#[cfg(test)]
mod test {
  use super::{
    Insn,
    Opcode::*,
    Reg::*,
    Alu::*,
    Jmp::*,
    Src::*,
    Mode::*,
    Size::*,
  };
  #[test]
  fn encode_alu() {
    assert_eq!(
      Insn::new(Alu64(Mov, K), R0, R0, 0, !1 + 1).serialize(),
      [0xb7, 0x00, 0x00, 0x00, 0xff, 0xff, 0xff, 0xff]
    );
  }

  #[test]
  fn encode_jmp() {
    assert_eq!(
      Insn::new(Jmp(Exit, K), R0, R0, 0, 0).serialize(),
      [0x95, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00]
    );
  }

  #[test]
  fn encode_st() {
    assert_eq!(
      Insn::new(St(Imm, DW), R0, R0, 0, 1).serialize(),
      [0x00 | 0x18 | 0x02, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01]
    );
  }

  /// eBPF has two non-generic instructions: (BPF_ABS | <size> | BPF_LD) and
  /// (BPF_IND | <size> | BPF_LD) which are used to access packet data.
  #[test]
  fn encode_ld() {
    assert_eq!(
      Insn::new(Ld(Ind, H), R0, R0, 0, 1).serialize(),
      [0x40 | 0x08 | 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01]
    );
  }
}