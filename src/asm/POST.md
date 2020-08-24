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

カーネルはメモリに配置されたこのバイト列を64bitごとに命令として読みだしてverifierにかけていることになる。

## 

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

arithmetic and jump
```
  +----------------+--------+--------------------+
  |   4 bits       |  1 bit |   3 bits           |
  | operation code | source | instruction class  |
  +----------------+--------+--------------------+
  (MSB)                                      (LSB)
```

load and store
```
  +--------+--------+-------------------+
  | 3 bits | 2 bits |   3 bits          |
  |  mode  |  size  | instruction class |
  +--------+--------+-------------------+
  (MSB)                             (LSB)
```

program = { instruction }
instruction = 

## 準備

毎回構造体をいちから初期化するのも面倒なので少しまとめておく。
Cだとマクロで構造体の初期化をinline展開しているようだ。
Rustだと関数書いてinline attribute設定すればよさそう。

ここではasmというモジュールに切り出しておく。

[前回]: /posts/note/run-ebpf-socket-filter/
[Linux Socket Filtering aka Berkeley Packet Filter (BPF)]: https://www.kernel.org/doc/Documentation/networking/filter.txt

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

