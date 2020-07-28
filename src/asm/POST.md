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

# WIP 手書きでeBPF 算術命令

[前回]はeBPFのごく単純なプログラムを書いて実行可能なユーザ空間側のプログラムを作ることに専念した。
今回は基本的な命令を試していく。

x86_64などの実際のプロセッサを使ったアセンブリプログラミングを嗜んでいる人にとっては何のことはない話なので読み飛ばし可。

## 準備

毎回構造体をいちから初期化するのも面倒なので少しまとめておく。
Cだとマクロで構造体の初期化をinline展開しているようだ。
Rustだと関数書いてinline attribute設定すればよさそう。

ここではasmというモジュールに切り出しておく。

[前回]: /posts/note/run-ebpf-socket-filter/

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

