# algokey
Generate Algorand keys using mnemonics or hex seed

## disclaimer
> The use of this tool does not guarantee security or usability for any
> particular purpose. Please review the code and use at your own risk.

## installation
This step assumes you have [Go compiler toolchain](https://go.dev/dl/)
installed on your system.

```bash
go install github.com/kubetrail/algokey@latest
```
Add autocompletion for `bash` to your `.bashrc`
```bash
source <(algokey completion bash)
```

## generate keys
Ethereum keys can be generated using mnemonic. [bip39](https://github.com/kubetrail/bip39)
can be used for generating new mnemonics:
```bash
bip39 gen
```
```text
patient board palm abandon right sort find blood grace sweet vote load action bag trash calm burden glow phrase shoot frog vacant elegant tourist
```

```bash
algokey gen
```
```yaml
Enter mnemonic: patient board palm abandon right sort find blood grace sweet vote load action bag trash calm burden glow phrase shoot frog vacant elegant tourist
seed: 83302d7a03b461c84f9c8b80ddc2b5c9f46323b567b8aa9b92c82d2b710abd4a
prv: 83302d7a03b461c84f9c8b80ddc2b5c9f46323b567b8aa9b92c82d2b710abd4aeb368d172b549116b3fd4d770d3268368ab714a8e07cde4b609a63edf0800955
pub: eb368d172b549116b3fd4d770d3268368ab714a8e07cde4b609a63edf0800955
addr: 5M3I2FZLKSIRNM75JV3Q2MTIG2FLOFFI4B6N4S3ATJR634EABFK2X3R5I4
keyType: ed25519
```

> Please note that this tool does not currently support 25 word mnemonic
> and uses either 12, 15, 18, 21 or 24 word mnemonic sentences

Alternatively, pass mnemonic as CLI args
```bash
algokey gen patient board palm abandon right sort find blood grace sweet vote load action bag trash calm burden glow phrase shoot frog vacant elegant tourist
```

Keys can be additionally protected using a passphrase:
```bash
algokey gen --use-passphrase
```
```yaml
Enter mnemonic: patient board palm abandon right sort find blood grace sweet vote load action bag trash calm burden glow phrase shoot frog vacant elegant tourist
Enter secret passphrase: 
Enter secret passphrase again: 
seed: e393f67697aecc395a187f44439113a7ad8368407c6268b9d1f7cef15f8b01d4
prv: e393f67697aecc395a187f44439113a7ad8368407c6268b9d1f7cef15f8b01d4ebdf068402c9d15ab2ad2c24510ced7999d0e1806c865bb4d845685daadc8538
pub: ebdf068402c9d15ab2ad2c24510ced7999d0e1806c865bb4d845685daadc8538
addr: 5PPQNBACZHIVVMVNFQSFCDHNPGM5BYMANSDFXNGYIVUF3KW4QU4B7GRF74
keyType: ed25519
```

Mnemonic is validated and expected to comply to `BIP-39` standard.
Furthermore, a mnemonic in a language different from English is first
translated to English such that the underlying entropy is preserved.

```bash
bip39 translate --to-language=Japanese patient board palm abandon right sort find blood grace sweet vote load action bag trash calm burden glow phrase shoot frog vacant elegant tourist
```
```text
てぶくろ うりきれ てすり あいこくしん ねむい ひりつ こんしゅう うやまう しねん ほうそう らいう そんぞく あつい いわば むかい おおよそ おいこす しちりん でんち はんい さとる やめる けらい みのがす
```

Now using the Japenese mnemonic will result in same keys as those generated using
it's English mnemonic equivalent:
```bash
algokey gen --mnemonic-language=Japanese てぶくろ うりきれ てすり あいこくしん ねむい ひりつ こんしゅう うやまう しねん ほうそう らいう そんぞく あつい いわば むかい おおよそ おいこす しちりん でんち はんい さとる やめる けらい みのがす
```
```yaml
seed: 83302d7a03b461c84f9c8b80ddc2b5c9f46323b567b8aa9b92c82d2b710abd4a
prv: 83302d7a03b461c84f9c8b80ddc2b5c9f46323b567b8aa9b92c82d2b710abd4aeb368d172b549116b3fd4d770d3268368ab714a8e07cde4b609a63edf0800955
pub: eb368d172b549116b3fd4d770d3268368ab714a8e07cde4b609a63edf0800955
addr: 5M3I2FZLKSIRNM75JV3Q2MTIG2FLOFFI4B6N4S3ATJR634EABFK2X3R5I4
keyType: ed25519
```

However, an arbitrary mnemonic can be used by switching off validation

```bash
algokey gen --skip-mnemonic-validation this is an invalid mnemonic
```
```yaml
seed: bb06e6570ed0b71ac71e4feefeb3a7e2e4cf04ba80a065408150800f86583add
prvHex: bb06e6570ed0b71ac71e4feefeb3a7e2e4cf04ba80a065408150800f86583add62b64e5e811314c1f6b423ab07a2216929df479417ee0bba2d71050522b442a7
pubHex: 62b64e5e811314c1f6b423ab07a2216929df479417ee0bba2d71050522b442a7
addr: MK3E4XUBCMKMD5VUEOVQPIRBNEU56R4UC7XAXORNOECQKIVUIKT2A6YPPI
keyType: ed25519
```

> It is a good practice to use valid mnemonics and also enter them
> via STDIN to avoid getting them captured in command history

## generate hash
Hash can be generated for an input
```bash
algokey hash this arbitrary input \
  --output-format=yaml
```
```yaml
hash: 9PW5sgZmMnaBYgJxUQASyDQoeKoxPcgBLvCJEHVEFqb5
```

## sign hash
Hash generated in previous step can be signed using private key
```bash
algokey sign \
  --key=83302d7a03b461c84f9c8b80ddc2b5c9f46323b567b8aa9b92c82d2b710abd4aeb368d172b549116b3fd4d770d3268368ab714a8e07cde4b609a63edf0800955 \
  --hash=9PW5sgZmMnaBYgJxUQASyDQoeKoxPcgBLvCJEHVEFqb5 \
  --output-format=yaml
```
```yaml
sign: 2AoPwaCga2Rcp93yXVSPuR6kfst45e4YACKgTgaSKAbf8J33nstdtzjXwTv71LwJCLSX1Y153ZKq17vg4jmws96N
```

## verify signature
```bash
algokey verify \
  --key=eb368d172b549116b3fd4d770d3268368ab714a8e07cde4b609a63edf0800955 \
  --hash=9PW5sgZmMnaBYgJxUQASyDQoeKoxPcgBLvCJEHVEFqb5 \
  --sign=2AoPwaCga2Rcp93yXVSPuR6kfst45e4YACKgTgaSKAbf8J33nstdtzjXwTv71LwJCLSX1Y153ZKq17vg4jmws96N \
  --output-format=yaml
```
```yaml
verified: true
```

## references:
* https://github.com/w3f/hd-ed25519
* https://medium.com/@robbiehanson15/the-math-behind-bip-32-child-key-derivation-7d85f61a6681
* https://nbeguier.medium.com/a-real-world-comparison-of-the-ssh-key-algorithms-b26b0b31bfd9
* http://safecurves.cr.yp.to/
