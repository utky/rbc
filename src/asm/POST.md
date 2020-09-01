手書きでeBPFバイトコード

https://www.kernel.org/doc/Documentation/networking/filter.txt

eBPFのISA

* レジスタは10本

* R0 : 返却値を格納
* R1 - R5 : 
* R6 - R9 : 

opecode

# WIP eBPFプログラムの位置づけ

eBPFプログラムはカーネル空間で実行されるが、そのプログラム単体では不十分なユースケースが多い。
ほとんどの場合、ユーザ空間のプログラムからeBPFプログラムの出力をBPF_MAP経由で取り出す必要がある。
そのためeBPFプログラムはその出力を観測するユーザ空間プログラムを合わせて考える必要がある。

[bpf(2)] を読む限りでもeBPFのシステムコールで作られたfdはプロセス終了と同時に閉じられるようになっている。
このことからもeBPFプログラムはユーザ空間側のプログラムとセットで管理される想定になっていることが伺える。

このように2種類のプログラムをペアにして管理するモデルとして類似した問題は何かあるだろうか？

[bpf(2)]: https://man7.org/linux/man-pages/man2/bpf.2.html

# WIP 手書きでeBPF 命令のデータ型

[前回]はeBPFのごく単純なプログラムを書いて実行可能なユーザ空間側のプログラムを作ることに専念した。
今回は色々な命令を試していくにあたっての準備として、命令をRust上で作りやすいようにする。

[Linux Socket Filtering aka Berkeley Packet Filter (BPF)]()

を参考にする。

## フォーマット

eBPFの命令フォーマットは下記のように定義されている。

```
op:8, dst_reg:4, src_reg:4, off:16, imm:32
```

合計64bitで一つの命令を表し、これが配列として並べられたものをeBPFプログラムと呼ぶ。

例えばC言語上で作った下記の命令があるとする。

```c
  struct bpf_insn insns[] = {
    { BPF_ALU64 | BPF_MOV | BPF_K, 0, 0, 0, -1 },
    { BPF_JMP | BPF_EXIT, 0, 0, 0, 0 }
  };
```
これらをメモリ上で表現すると下記のようになる。
```
0x7fffffffe800: 0xb7    0x00    0x00    0x00    0xff    0xff    0xff    0xff
0x7fffffffe808: 0x95    0x00    0x00    0x00    0x00    0x00    0x00    0x00
```

最初の `BPF_MOV` 命令をフィールドに分解すると下記のようになる。
```
0xb7    0x00    0x00    0x00    0xff    0xff    0xff    0xff
|opcode |reg    |off            |imm                        |
```

カーネルはメモリに配置されたこのバイト列を64bitごとに命令として解析していることになる。

## 命令の種類

eBPFの命令の種類をクラス(BPF_CLASS)と呼ぶ。

* BPF_LD
* BPF_LDX
* BPF_ST
* BPF_STX
* BPF_ALU
* BPF_JMP
* BPF_JMP32
* BPF_ALU64

これらには暗黙的にグループ分けが存在しており、そのグループによって opcode フィールドの形式がやや異なる。
現時点の実装では2種類のグループがある。

### arithmetic and jump
```
  +----------------+--------+--------------------+
  |   4 bits       |  1 bit |   3 bits           |
  | operation code | source | instruction class  |
  +----------------+--------+--------------------+
  (MSB)                                      (LSB)
```
算術演算とジャンプを行うための命令グループ。

### load and store
```
  +--------+--------+-------------------+
  | 3 bits | 2 bits |   3 bits          |
  |  mode  |  size  | instruction class |
  +--------+--------+-------------------+
  (MSB)                             (LSB)
```
メモリからレジスタへのデータの移動を行うための命令グループ。

Rust上ではこの命令クラス別のフィールドの違いを`enum`で下記のように表現する。
各フィールドが取りうる値の範囲を正しく制限できるように、`Mode`、`Size`、`Alu`、`Jmp`、`Src`もそれぞれ`enum`として定義しておく。
```rust
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
```
クラスを8ビットのデータに変換する方法は`From`トレイトを使う。
`Mode`や`Size`等の各フィールドのデータも`From`トレイトで`u8`にエンコードできるようにしておく。
```rust
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
```

ALU、JMPのクラスはさらに細分化された命令があるため、それぞれどういう操作が可能なのかを把握しておく必要がある。

あまりアセンブリ言語や抽象機械の命令をまじまじと眺めたことがないので、
結構よく解らない命令もちょくちょくあるので分からないところを拾っている。

どんな命令かを直感的につかむには [disasm.c] でのhuman readableなオペレータの記号を読むと大体わかる。

### 算術演算

算術演算オペレータ。

disasm上での表記は下記を参考にする。
[disasm.c#L66](https://elixir.bootlin.com/linux/v5.7.7/source/kernel/bpf/disasm.c#L66)

* BPF_ADD: `+=`
* BPF_SUB: `-=`
* BPF_MUL: `*=`
* BPF_DIV: `/=`
* BPF_OR: `|=`
* BPF_AND: `&=`
* BPF_LSH: `<<=`
* BPF_RSH: `>>=`
* BPF_NEG: `neg`
* BPF_MOD: `%=`
* BPF_XOR: `^=`
* BPF_MOV: `=`
* BPF_ARSH: `s>>=` 符号を維持したまま右シフト
* BPF_END: `endian` エンディアンの変換

[Linux Socket Filtering aka Berkeley Packet Filter (BPF)] にはとくに言及がないけど、
BPF_ENDはendinessを指定する必要がある。

https://elixir.bootlin.com/linux/v5.7.7/source/include/uapi/linux/bpf.h#L32

### ジャンプ

dst_reg と (src_reg または imm) を比較して true なら off の分だけ飛ぶ。
false なら fall-through でそのままプログラムカウンタをインクリメントする。

disasm上での表記は下記を参考にする
[disasm.c#L90](https://elixir.bootlin.com/linux/v5.7.7/source/kernel/bpf/disasm.c#L90)

#### 同値性テスト

* BPF_JEQ: `==`
* BPF_JNE: `!=`

#### 符号なし整数の比較

* BPF_JGT: `>`
* BPF_JGE: `>=`
* BPF_JLT: `<`
* BPF_JLE: `<=`
* BPF_JSET: `&`

#### 符号つき整数の比較

* BPF_JSGT: `s>`
* BPF_JSGE: `s>=`
* BPF_JSLT: `s<`
* BPF_JSLE `s<=`:

#### その他

* BPF_JA: プログラムカウンタにimmを加算した場所へ飛ぶ
* BPF_CALL: 関数を呼び出す
* BPF_EXIT: 関数呼び出しから復帰する

# eBPF Map を使ってみる

## 準備

毎回構造体をいちから初期化するのも面倒なので少しまとめておく。
Cだとマクロで構造体の初期化をinline展開しているようだ。
Rustだと関数書いてinline attribute設定すればよさそう。

ここではasmというモジュールに切り出しておく。

[前回]: /posts/note/run-ebpf-socket-filter/
[Linux Socket Filtering aka Berkeley Packet Filter (BPF)]: https://www.kernel.org/doc/Documentation/networking/filter.txt
[disasm.c]: https://elixir.bootlin.com/linux/v5.7.7/source/kernel/bpf/disasm.c

# WIP 手書きでeBPF ジャンプ

# WIP 手書きでeBPF ロード/ストア

# WIP 手書きでeBPF 関数呼び出し

# WIP 手書きでeBPF BPF_MAP

# WIP ELF形式のeBPFプログラムの使い方

eBPFプログラムのポータビリティを表すスローガンを"Compile Once, Run Everywhere"という。
これはコンパイル済みのeBPFプログラムが*異なるカーネルバージョンで正しく動作する*ことを目指した標語だ。

[BPF Portability and CO-RE](https://facebookmicrosites.github.io/bpf/blog/2020/02/19/bpf-portability-and-co-re.html)

実行可能なeBPFプログラムそれ自体はただの命令の配列として表現される。
しかし実際にファイルシステム上で取りまわす際にはELF形式のオブジェクトファイルとして扱うことが多いようだ。

これはELFのセクションを活用してeBPFプログラムのインタフェースを記述するのが便利だからであるようだ。
実際libbpfではそれを実装として取り込んでいる。

