# ethereum_proxy
ethereum_proxy

```
go build -o ./bin/ethereum_proxy ./cmd
```

```asciidoc
export PROXY_HOST=127.0.0.1:37101
export PROXY_PORT=5000

./bin/ethereum_proxy
```

```
curl -H "Content-Type:application/json" -d '{"jsonrpc":"2.0","method":"eth_estimateGas","params":[],"id":1}' 127.0.0.1:5000

curl -H "Content-Type:application/json" -d '{"jsonrpc":"2.0","method":"eth_blockNumber","params":[],"id":1}' 127.0.0.1:5000

curl -H "Content-Type:application/json" -d '{"jsonrpc":"2.0","method":"eth_getBlockByNumber","params":["0x3e8", true],"id":1}' 127.0.0.1:5000

// dpzuVdosQrF2kmzumhVeFQZa1aYcdgFpN => 0x93F86A462A3174C7AD1281BCF400A9F18D244E06
curl -H "Content-Type:application/json" -d '{"jsonrpc":"2.0","method":"eth_getBalance","params":["0x93F86A462A3174C7AD1281BCF400A9F18D244E06", "latest"],"id":1}' 127.0.0.1:5000

curl -H "Content-Type:application/json" -d '{"jsonrpc":"2.0","method":"eth_getTransactionByHash","params":["0x27f55958c8c1656699563b2f7bf3e3ad4e4476f5526d41065a9efa6e50b082b5"],"id":1}' 127.0.0.1:5000

// If true it returns the full transaction objects, if false only the hashes of the transactions.
curl -H "Content-Type:application/json" -d '{"jsonrpc":"2.0","method":"eth_getBlockByHash","params":["0x494181a8688c1550e8deea48e1eca750790169cf1b654089f88b126e4624c33e",false],"id":1}' 127.0.0.1:5000


// contractName => 0x
curl -H "Content-Type:application/json" -d '{"jsonrpc":"2.0","method":"eth_getCode","params":["0x313131312D2D2D2D2D476574436F646554657372"],"id":1}' 127.0.0.1:5000

curl -H "Content-Type:application/json" -d '{"jsonrpc":"2.0","method":"eth_getTransactionReceipt","params":["0xa46a766ce422e1e1a9827efe6989eeacc82a2352765287fe557497465751d9ab"],"id":1}' 127.0.0.1:5000

curl -H "Content-Type:application/json" -d '{"jsonrpc":"2.0","method":"eth_getLogs","params":[{"fromBlock":"0","toBlock":"13672"}],"id":1}' 127.0.0.1:5000

curl -H "Content-Type:application/json" -d '{"jsonrpc":"2.0","method":"eth_newFilter","params":[{"fromBlock":"0","toBlock":"13672"}],"id":1}' 127.0.0.1:5000

curl -H "Content-Type:application/json" -d '{"jsonrpc":"2.0","method":"eth_uninstallFilter","params":["0x282b21d7db0eaedb137e25b56337666d"],"id":1}' 127.0.0.1:5000

curl -H "Content-Type:application/json" -d '{"jsonrpc":"2.0","method":"eth_getFilterLogs","params":["0xdcccf7c1c88df9e5e8249f8caf0861a"],"id":1}' 127.0.0.1:5000


```

