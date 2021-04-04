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

# eBPF Map を使ってみる

##  maps

mapsはeBPFプログラムから利用可能な汎用データストレージである。カーネルとユーザ空間でデータを交換するためにも使われる。
eBPFプログラムとユーザ空間プログラムは非同期にmapを操作することができる。

mapsという名前が示すように構造はKey-Valueストアになっている。
領域そのものはカーネル空間側に確保されており、ユーザ空間からの操作は全て[bpf(2)]のシステムコール経由で行われる。
Key-Valueのデータ型はそれぞれ事前にユーザからサイズ指定された固定長のバイナリデータとなる。
そのためプログラムから意味のあるデータ型に復元する作業は利用者側に委ねられている。

mapを作成すると作成元プロセスローカルなfdが返る。mapの識別にはそのfdを用いる。
使い終わったmapを破棄するのはfdをcloseするだけでよい。

複数のeBPFプログラムがmapを共有することもできる。
(eBPFプログラム間の通信チャネルとして活用できることを示唆している)

### 

mapはCPUごとまたは複数CPUにまたがってデータを保持することができる。


### 操作

KVSらしくlookup, insert, update, deleteがある。

### 種類

[bpf.h#L118] に定義がある。

hash, array, queue, stack など汎用的な構造があるのが分かる。
一方で `BPF_MAP_TYPE_PROG_ARRAY`, `BPF_MAP_TYPE_PERF_EVENT_ARRAY` など特定用途に限定されていそうな名前のものもある。
たとえば `BPF_MAP_TYPE_PROG_ARRAY` はtail callによりeBPFプログラム間をジャンプする

### fdでmapsを管理することの弊害

fdはプロセスローカルであるため、プロセスをまたがったmapsの共有は難しい。

[公式ドキュメント]: https://www.kernel.org/doc/Documentation/networking/filter.txt
[bpf(2)]: https://man7.org/linux/man-pages/man2/bpf.2.html
[BPF and XDP Reference Guide#Maps]: https://docs.cilium.io/en/latest/bpf/#maps
[bpf.h#L118]: https://elixir.bootlin.com/linux/v5.7.7/source/include/uapi/linux/bpf.h#L118

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

