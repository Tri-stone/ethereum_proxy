module github.com/Tri-stone/ethereum_proxy

go 1.13

require (
	github.com/golang/protobuf v1.5.0
	github.com/gorilla/handlers v1.5.1
	github.com/gorilla/mux v1.8.0
	github.com/gorilla/rpc v1.2.0
	github.com/hyperledger/burrow v0.30.5
	github.com/pkg/errors v0.9.1
	github.com/spf13/cobra v1.1.3
	github.com/spf13/viper v1.7.1
	github.com/xuperchain/xuperchain v0.0.0-20210208123615-2d08ff11de3e
	go.uber.org/zap v1.16.0
	golang.org/x/tools v0.0.0-20210106214847-113979e3529a // indirect
	google.golang.org/grpc v1.36.0
)

replace github.com/hyperledger/burrow => github.com/xuperchain/burrow v0.30.6-0.20210304060557-02933899eeb0

//todo 此处需要修改
replace github.com/xuperchain/xuperchain => /Users/shikenian/go/src/github.com/xuperchain/xuperchain
