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

curl -H "Content-Type:application/json" -d '{"jsonrpc":"2.0","method":"eth_getBlockByNumber","params":["10000", true],"id":1}' 127.0.0.1:5000
```

