# create2crunch

> A Rust program for finding salts that create gas-efficient Ethereum addresses via CREATE2.

Provide three arguments: a factory address (or contract that will call CREATE2), a caller address (for factory addresses that require it as a protection against frontrunning), and the keccak-256 hash of the initialization code of the contract that the factory will deploy.

```sh
$ git clone https://github.com/0age/create2crunch
$ cd create2crunch
$ cargo run --release \
  0xfe55836c5e9510ac58c8f8adc78fa6ddd03cdcd0 `#factory address` \
  0x0734d56da60852a03e2aafae8a36ffd8c12b32f1 `#caller address` \
  0x6336b407593e680555d2a5b24b983249db9db012dd5f1e1f589c916ffc609567 # init code
```

For each efficient address found, the salt, resultant addresses, and value *(i.e. approximate rarity)* will be written to `efficient_addresses.txt`. Verify that one of the salts actually results in the intended address before getting in too deep - ideally, the CREATE2 factory will have a view method for checking what address you'll get for submitting a particular salt. Be sure not to change the factory address or the init code without first removing any existing data to prevent the two salt types from becoming commingled. There's also a *very* simple monitoring tool available if you run `$python3 analysis.py` in another tab.

This tool was originally built for use with [`Pr000xy`](https://github.com/0age/Pr000xy), including with `Create2Factory` directly. This version only utilizes the CPU - a GPU implementation would be much more effective.

PRs welcome!
