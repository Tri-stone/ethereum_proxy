/*
Copyright IBM Corp. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package ethereum_proxy

import (
	"context"
	"crypto/rand"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	mathRand "math/rand"
	"strings"
	"time"

	"math/big"
	"net/http"
	"strconv"
	"sync"

	"github.com/golang/protobuf/proto"
	"github.com/hyperledger/burrow/crypto"
	"github.com/xuperchain/xuperchain/core/contract/evm"
	"github.com/xuperchain/xuperchain/core/global"
	"github.com/xuperchain/xuperchain/core/pb"
	"go.uber.org/zap"

	"github.com/Tri-stone/ethereum_proxy/types"
)

var ZeroAddress = make([]byte, 20)

const (
	bcName                = "xuper"
	txHashLength          = 66
	blockHashLength       = 66
	AddressLength         = 42
	coinBaseFrom          = "0x000000000000000000000000000000000"
	contracrLength        = 42
	filteredLogBufferSize = 8
	LogsBloomZore         = "0x00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000"
)

var FilterMap = make(map[string]*types.Filter)
var deadline = 5 * time.Minute

// EthService is the rpc server implementation. Each function is an
// implementation of one ethereum json-rpc
// https://github.com/ethereum/wiki/wiki/JSON-RPC
//
// Arguments and return values are formatted as HEX value encoding
// https://github.com/ethereum/wiki/wiki/JSON-RPC#hex-value-encoding
//
// gorilla RPC is the receiver of these functions, they must all take three
// pointers, and return a single error
//
// see godoc for RegisterService(receiver interface{}, name string) error
//
type EthService interface {
	GetCode(r *http.Request, arg *string, reply *string) error
	//Call(r *http.Request, args *types.EthArgs, reply *string) error
	//SendTransaction(r *http.Request, args *types.EthArgs, reply *string) error
	//GetTransactionReceipt(r *http.Request, arg *string, reply *types.TxReceipt) error
	//Accounts(r *http.Request, arg *string, reply *[]string) error
	EstimateGas(r *http.Request, args *types.EthArgs, reply *string) error
	GetBalance(r *http.Request, p *[]string, reply *string) error
	GetBlockByNumber(r *http.Request, p *[]interface{}, reply *types.Block) error
	GetBlockByHash(r *http.Request, p *[]interface{}, reply *types.Block) error
	BlockNumber(r *http.Request, _ *interface{}, reply *string) error
	GetTransactionByHash(r *http.Request, txID *string, reply *types.Transaction) error
	//GetTransactionCount(r *http.Request, _ *interface{}, reply *string) error
	GetLogs(*http.Request, *types.GetLogsArgs, *[]types.Log) error
	NewFilter(*http.Request, *types.GetLogsArgs, *string) error
	GetFilterLogs(*http.Request, *string, *[]types.Log) error
	UninstallFilter(*http.Request, *string, *bool) error
	GetFilter(*http.Request, *string, *types.Filter) error
}

type ethService struct {
	xchainClient pb.XchainClient
	eventClient  pb.EventServiceClient
	//filterClient  pb.EvmFilterClient
	logger        *zap.SugaredLogger
	filterMapLock sync.Mutex
	filterMap     map[uint64]interface{}
	filterSeq     uint64
}

func NewEthService(xchainClient pb.XchainClient, eventClient pb.EventServiceClient, logger *zap.SugaredLogger) EthService {
	return &ethService{
		xchainClient: xchainClient,
		eventClient:  eventClient,
		logger:       logger.Named("ethservice"),
		filterMap:    make(map[uint64]interface{}),
	}
}

//func (s *ethService) Call(r *http.Request, args *types.EthArgs, reply *string) error {
//	response, err := s.query(s.ccid, strip0x(args.To), [][]byte{[]byte(strip0x(args.Data))})
//
//	if err != nil {
//		return fmt.Errorf("Failed to query the ledger: %s", err)
//	}
//
//	// Clients expect the prefix to present in responses
//	*reply = "0x" + hex.EncodeToString(response.Payload)
//
//	return nil
//}

//func (s *ethService) SendTransaction(r *http.Request, args *types.EthArgs, reply *string) error {
//	if args.To == "" {
//		args.To = hex.EncodeToString(ZeroAddress)
//	}
//
//	response, err := s.channelClient.Execute(channel.Request{
//		ChaincodeID: s.ccid,
//		Fcn:         strip0x(args.To),
//		Args:        [][]byte{[]byte(strip0x(args.Data))},
//	})
//
//	if err != nil {
//		return fmt.Errorf("Failed to execute transaction: %s", err)
//	}
//	*reply = string(response.TransactionID)
//	return nil
//}

//func (s *ethService) GetTransactionReceipt(r *http.Request, arg *string, reply *types.TxReceipt) error { //todo
//	txHash := *arg
//	if len(txHash) != txHashLength {
//		return fmt.Errorf("invalid transaction hash,expect length:%d, but got:%d", txHashLength, len(txHash))
//	}
//	rawTxId, err := hex.DecodeString(txHash[2:])
//	if err != nil {
//		s.logger.Error(err)
//		return fmt.Errorf("invalid transcation hash")
//	}
//	pbTxStatus := &pb.TxStatus{
//		Header: &pb.Header{
//			Logid: global.Glogid(),
//		},
//		Bcname: bcName,
//		Txid:   rawTxId,
//	}
//	receipt, err := s.xchainClient.GetTransactionReceipt(context.TODO(), pbTxStatus)
//	if err != nil {
//		s.logger.Error(err)
//		return fmt.Errorf("get transactionReceipt error")
//	}
//	if receipt.TxStatus.Status == pb.TransactionStatus_NOEXIST {
//		return fmt.Errorf("Transaction Not Exit\n")
//	}
//	if receipt.TxStatus.Status != pb.TransactionStatus_CONFIRM {
//		return fmt.Errorf("Get TransactionReceipt Err\n")
//	}
//	result := &types.TxReceipt{}
//	result.TransactionHash = fmt.Sprintf("%x", receipt.TxStatus.Txid)
//	result.BlockHash = fmt.Sprintf("%x", receipt.TxStatus.Tx.Blockid)
//	result.BlockNumber = fmt.Sprintf("%d", receipt.BlockNumber)
//	//reply.ContractAddress
//	logs := parseEvmLog2TyepLogs(receipt.Log)
//	result.Logs = logs
//	result.From = receipt.TxStatus.Tx.Initiator
//	//reply.To
//	*reply = *result
//	return nil
//}

func (s *ethService) EstimateGas(r *http.Request, _ *types.EthArgs, reply *string) error {
	s.logger.Debug("EstimateGas called")
	*reply = "0x0"
	return nil
}

func (s *ethService) GetBalance(r *http.Request, p *[]string, reply *string) error {
	params := *p
	if len(params) != 2 {
		return fmt.Errorf("need 2 params, got %q", len(params))
	}

	switch params[1] {
	case "latest":
	case "earliest":
		return fmt.Errorf("earliest status query balance is not supported at present")
	case "pending":
		return fmt.Errorf("pending status query balance is not supported at present")
	default:
		return fmt.Errorf("only the latest is supported now")
	}

	evmAddr, err := crypto.AddressFromHexString(params[0][2:])
	if err != nil {
		return fmt.Errorf("can not transfer the address:%s to xuperChain account", params[0])
	}

	addr, _, err := evm.DetermineEVMAddress(evmAddr)
	if err != nil {
		return fmt.Errorf("can not transfer the address:%s to xuperChain account", params[0])
	}

	pbAddrStatus := &pb.AddressStatus{
		Address: addr,
		Bcs: []*pb.TokenDetail{
			{Bcname: bcName},
		},
	}
	addrStatus, err := s.xchainClient.GetBalance(context.TODO(), pbAddrStatus)
	if err != nil {
		s.logger.Error(err)
		return fmt.Errorf("can not get Balance from ledger\n")
	}
	balance, ok := big.NewInt(0).SetString(addrStatus.Bcs[0].Balance, 10) // todo 如果有多个币种？
	if !ok {
		s.logger.Errorf("parse balance to Ox error\n")
		return fmt.Errorf("Server Internal error\n")
	}
	*reply = fmt.Sprintf("0x%x", balance)
	return nil
}

func (s *ethService) BlockNumber(r *http.Request, _ *interface{}, reply *string) error {
	blockNumber, err := s.parseBlockNum("latest")
	if err != nil {
		return fmt.Errorf("failed to get latest block number: %s", err)
	}
	*reply = "0x" + strconv.FormatUint(blockNumber, 16)
	return nil
}

func (s *ethService) GetBlockByNumber(r *http.Request, p *[]interface{}, reply *types.Block) error {
	s.logger.Debug("Received a request for GetBlockByNumber")
	params := *p
	s.logger.Debug("Params are : ", params)

	numParams := len(params)
	if numParams != 2 {
		return fmt.Errorf("need 2 params, got %q", numParams)
	}
	// first arg is string of block to get
	number, ok := params[0].(string)
	if !ok {
		s.logger.Debugf("Incorrect argument received: %#v", params[0])
		return fmt.Errorf("Incorrect first parameter sent, must be string")
	}
	if len(number) < 2 || number[:2] != "0x" {
		return fmt.Errorf("please input correct number")
	}

	// second arg is bool for full txn or hash txn
	fullTransactions, ok := params[1].(bool)
	if !ok {
		return fmt.Errorf("Incorrect second parameter sent, must be boolean")
	}

	blockHeight, err := strconv.ParseInt(number[2:], 16, 64)
	if err != nil {
		return fmt.Errorf("Incorrect first parameter sent, invalid block height")
	}

	blockHeightPB := &pb.BlockHeight{
		Header: &pb.Header{
			Logid: global.Glogid(),
		},
		Bcname: "xuper",
		Height: blockHeight,
	}

	block, err := s.xchainClient.GetBlockByHeight(context.TODO(), blockHeightPB)
	if err != nil {
		s.logger.Debug(err)
		return fmt.Errorf("failed to query the ledger: %v", err)
	}

	blk, err := parseBlock(block, fullTransactions)
	if err != nil {
		s.logger.Debug(err)
		return err
	}

	*reply = *blk
	return nil
}

func (s *ethService) GetBlockByHash(r *http.Request, p *[]interface{}, reply *types.Block) error {
	params := *p
	if len(params) != 2 {
		return fmt.Errorf("need 2 params, got %q", len(params))
	}
	blockHash, ok := params[0].(string)
	if !ok {
		s.logger.Debugf("Incorrect argument received: %#v", params[0])
		return fmt.Errorf("Incorrect first parameter sent, must be string")
	}
	if len(blockHash) != blockHashLength {
		return fmt.Errorf("invalid block hash,expect length:%d, but got:%d", txHashLength, len(blockHash))
	}

	fullTransactions, ok := params[1].(bool)
	if !ok {
		return fmt.Errorf("Incorrect second parameter sent, must be boolean")
	}
	block, err := s.getBlockByHash(blockHash, fullTransactions)
	if err != nil {
		s.logger.Errorf("getBlockHash error: %#v", err.Error())
		return err
	}
	*reply = *block
	return nil
}

func (s *ethService) GetTransactionByHash(r *http.Request, txID *string, reply *types.Transaction) error {
	if len(*txID) != txHashLength {
		return fmt.Errorf("invalid transaction hash,expect length:%d, but got:%d", txHashLength, len(*txID))
	}
	rawTxId, err := hex.DecodeString((*txID)[2:])
	if err != nil {
		s.logger.Error(err)
		return fmt.Errorf("Invalid Transcation Hash\n")
	}
	pbTxStatus := &pb.TxStatus{
		Header: &pb.Header{
			Logid: global.Glogid(),
		},
		Bcname: bcName,
		Txid:   rawTxId,
	}
	txStatus, err := s.xchainClient.QueryTx(context.TODO(), pbTxStatus)
	if err != nil {
		s.logger.Error(err)
		return fmt.Errorf("Get The Transaction Error\n")
	}
	if txStatus.Status == pb.TransactionStatus_NOEXIST {
		return fmt.Errorf("The Transaction NOT EXIST\n")
	}

	if txStatus.Status != pb.TransactionStatus_CONFIRM {
		return fmt.Errorf("Get The Transaction Error\n")
	}

	tx, err := parseTransaction(txStatus.Tx)
	if err != nil {
		s.logger.Error(err)
		return fmt.Errorf("Can Not Parse The Transaction\n")
	}

	block, err := s.getBlockByHash(tx.BlockHash, false)
	if err != nil {
		s.logger.Error(err)
		return fmt.Errorf("Get Block Number Error:%s\n", err.Error())
	}

	tx.BlockNumber = block.Number
	*reply = *tx
	return nil
}

func (s *ethService) GetLogs(r *http.Request, args *types.GetLogsArgs, logs *[]types.Log) error {
	if args == nil {
		return fmt.Errorf("Filter can not be nil \n")
	}
	var err error
	logsFrom, err := s.getLogs(args)
	if err != nil {
		return err
	}
	*logs = *logsFrom
	return nil
}

func (s *ethService) getLogs(args *types.GetLogsArgs) (logs *[]types.Log, err error) {
	filter, err := s.specsParams(args)
	if err != nil {
		return nil, err
	}

	buf, _ := proto.Marshal(filter)
	request := &pb.SubscribeRequest{
		Type:   pb.SubscribeType_BLOCK,
		Filter: buf,
	}
	endBlock, err := strconv.ParseInt(args.ToBlock, 10, 64)
	if err != nil {
		return nil, err
	}
	logs, err = s.getEvent(request, endBlock)
	return
}

func (s *ethService) specsParams(args *types.GetLogsArgs) (*pb.BlockFilter, error) {
	latestBlockNumber, err := s.parseBlockNum("latest")
	if err != nil {
		return nil, err
	}

	filter := &pb.BlockFilter{
		Bcname: bcName,
		Range:  &pb.BlockRange{},
	}

	if args.FromBlock == "" {
		args.FromBlock = fmt.Sprintf("%d", latestBlockNumber)
	}
	fromBlock, err := strconv.Atoi(args.FromBlock)
	if err != nil {
		return nil, err
	}
	if fromBlock > int(latestBlockNumber) {
		args.FromBlock = fmt.Sprintf("%d", latestBlockNumber)
	}
	filter.Range.Start = args.FromBlock

	if args.ToBlock == "" {
		args.ToBlock = fmt.Sprintf("%d", latestBlockNumber+1)
	}
	toBlock, err := strconv.Atoi(args.ToBlock)
	if err != nil {
		return nil, err
	}
	if toBlock > int(latestBlockNumber) {
		args.ToBlock = fmt.Sprintf("%d", latestBlockNumber+1)
	}
	filter.Range.End = args.ToBlock

	//if toBlock - fromBlock > 100000 {						// todo 讨论 查询范围不超过100000，为了避免接口返回时间过长
	//	return nil,fmt.Errorf("the range of block should not be more than 100000")
	//}

	if len(args.Address) > 0 {
		name, err := evm2xuper(args.Address[0]) // 暂不支持多个地址查询
		if err != nil {
			return nil, err
		}
		filter.Contract = name
	}
	return filter, nil
}

func (s *ethService) getEvent(req *pb.SubscribeRequest, endBlock int64) (*[]types.Log, error) {
	stream, err := s.eventClient.Subscribe(context.TODO(), req)
	if err != nil {
		return nil, err
	}

	var logs []types.Log

	for {
		event, err := stream.Recv()
		if err == io.EOF {
			return nil, err
		}
		if err != nil {
			return nil, err
		}
		var block pb.FilteredBlock
		err = proto.Unmarshal(event.Payload, &block)
		if err != nil {
			return nil, err
		}

		if len(block.GetTxs()) == 0 {
			continue
		}
		for _, tx := range block.GetTxs() {
			if len(tx.Events) == 0 {
				continue
			}
			for _, eventLog := range tx.GetEvents() {
				log := types.Log{}
				contractName := eventLog.Contract
				eventAddr, err := xuper2evm(contractName)
				if err != nil {
					return nil, fmt.Errorf("can not parse the contractName")
				}
				log.Address = eventAddr
				log.Data = string(eventLog.Body)
				log.BlockNumber = fmt.Sprintf("%x", block.GetBlockHeight())
				log.BlockHash = "0x" + block.GetBlockid()
				log.TxHash = "0x" + tx.Txid
				//log.Index
				//log.TxIndex
				logs = append(logs, log)
			}
		}
		if block.BlockHeight >= endBlock-1 {
			return &logs, nil
		}
	}

}

func (s *ethService) NewFilter(r *http.Request, args *types.GetLogsArgs, result *string) error {
	if args == nil {
		return fmt.Errorf("Filter can not be nil\n")
	}
	filterID := generateID()
	filter := &types.Filter{
		*args,
		time.Now().Unix(),
		filterID,
	}

	if _, ok := FilterMap[filterID]; !ok {
		FilterMap[filterID] = filter
	}
	go filterRecycling(filterID) // filter定期回收
	*result = filterID
	return nil
}

func filterRecycling(filterID string) {
	deadDuration := int64(deadline.Seconds())
	ticker := time.NewTicker(deadline)
	for {
		<-ticker.C
		filter := &types.Filter{}
		var ok bool
		if filter, ok = FilterMap[filterID]; !ok {
			return
		}
		timeNow := time.Now().Unix()
		lastUpdateTime := filter.Time
		if (timeNow - lastUpdateTime) > deadDuration {
			delete(FilterMap, filterID)
		}
	}
}

func generateID() string {
	var buf = make([]byte, 8)
	var seed int64
	if _, err := rand.Read(buf); err != nil {
		seed = int64(binary.BigEndian.Uint64(buf))
	} else {
		seed = int64(time.Now().Nanosecond())
	}
	rng := mathRand.New(mathRand.NewSource(seed))
	mu := sync.Mutex{}
	mu.Lock()
	bz := make([]byte, 16)
	rng.Read(bz)

	id := hex.EncodeToString(bz)
	id = strings.TrimLeft(id, "0")
	if id == "" {
		id = "0" // ID's are RPC quantities, no leading zero's and 0 is 0x0.
	}
	return "0x" + id
}

func getFilter(filterID string) (*types.Filter, error) {
	filter := &types.Filter{}
	var ok bool
	if filter, ok = FilterMap[filterID]; !ok {
		return nil, fmt.Errorf("%s filter does not exist，it may have been unused for more than 5 minutes and destroyed", filterID)
	} else {
		filter.Time = time.Now().Unix()
		return filter, nil
	}
}

func (s *ethService) GetFilter(r *http.Request, id *string, logArgs *types.Filter) error {
	if id == nil {
		return fmt.Errorf("FilterID can not be nil")
	}

	filter, err := getFilter(*id)
	if err != nil {
		return err
	}
	logArgs = filter
	return nil
}

func (s *ethService) UninstallFilter(r *http.Request, id *string, ok *bool) error {
	if id == nil {
		return fmt.Errorf("FilterID can not be nil")
	}
	filterID := *id

	if _, exist := FilterMap[filterID]; exist {
		delete(FilterMap, filterID)
		*ok = true
		return nil
	} else {
		return fmt.Errorf("filter: %s not found", filterID)
	}
}

func (s *ethService) GetFilterLogs(r *http.Request, id *string, logs *[]types.Log) error {
	filterID := *id
	filter, err := getFilter(filterID)
	if err != nil {
		return err
	}

	logsFrom, err := s.getLogs(&(filter.GetLogsArgs))
	if err != nil {
		return err
	}
	*logs = *logsFrom
	return nil
}

func (s *ethService) getBlockByHash(blockHash string, fullTransactions bool) (*types.Block, error) {
	rawBlockid, err := hex.DecodeString(blockHash[2:]) // 去掉0x
	if err != nil {
		return nil, fmt.Errorf("invalid blockHash")
	}

	blockId := &pb.BlockID{
		Header: &pb.Header{
			Logid: global.Glogid(),
		},
		Bcname:      bcName,
		Blockid:     rawBlockid,
		NeedContent: true,
	}

	b, err := s.xchainClient.GetBlock(context.TODO(), blockId)
	if err != nil {
		return nil, fmt.Errorf("failed to query the ledger: %v", err)
	}

	if b.Status == pb.Block_NOEXIST {
		return nil, fmt.Errorf("Block Not Exits\n")
	}
	if b.Status != pb.Block_TRUNK {
		return nil, fmt.Errorf("Query Block Error\n")
	}

	block, err := parseBlock(b, fullTransactions)
	if err != nil {
		s.logger.Debug(err)
		return nil, fmt.Errorf("Failed to Query The Block: %s\n", err.Error())
	}
	return block, nil
}

func parseBlock(block *pb.Block, fullTransactions bool) (*types.Block, error) {
	blockHash := "0x" + hex.EncodeToString(block.Block.Blockid)
	blockNumber := "0x" + strconv.FormatUint(uint64(block.Block.CurBlockNum), 16)

	data := block.GetBlock().GetTransactions()
	txns := make([]interface{}, 0, len(data))
	for index, transactionData := range data {
		if transactionData == nil {
			continue
		}

		if fullTransactions { // todo 交易解析
			txn := types.Transaction{
				BlockHash:        blockHash,
				BlockNumber:      blockNumber,
				TransactionIndex: "0x" + strconv.FormatUint(uint64(index), 16),
				Hash:             "0x" + hex.EncodeToString(transactionData.GetTxid()),
			}
			tx, err := parseTransaction(transactionData)
			if err != nil {
				return nil, fmt.Errorf("parse Transaction error")
			}

			txn.To = "0x" + tx.To
			txn.Input = "0x" + tx.Input
			txn.From = tx.From
			txns = append(txns, txn)
		} else {
			txns = append(txns, "0x"+hex.EncodeToString(transactionData.GetTxid()))
		}
	}

	blk := &types.Block{
		BlockData: types.BlockData{
			Number:     blockNumber,
			Hash:       blockHash,
			ParentHash: "0x" + hex.EncodeToString(block.Block.PreHash),
			//TransactionsRoot:string(block.Block.MerkleRoot),		//todo merkerRoot是一个[][]byte
			Miner: string(block.Block.Proposer),
			// todo 复用了以太坊过滤器的零值,512位，这里是否真的需要这么长
			LogsBloom:  LogsBloomZore,
			Difficulty: fmt.Sprintf("0x%x", block.Block.TargetBits),
			//GasUsed:
			Timestamp: "0x" + strconv.FormatInt(block.Block.Timestamp/100000000, 16), //时间戳修改为秒为单位，此处/100000000
		},
		Transactions: txns,
	}
	return blk, nil
}

func (s *ethService) parseBlockNum(input string) (uint64, error) {
	bcStatusPB := &pb.BCStatus{
		Header: &pb.Header{
			Logid: global.Glogid(),
		},
		Bcname: "xuper",
	}
	switch input {
	case "latest":
		// latest
		bcStatus, err := s.xchainClient.GetBlockChainStatus(context.TODO(), bcStatusPB)
		if err != nil {
			s.logger.Debug(err)
			return 0, fmt.Errorf("failed to query the ledger: %v", err)
		}
		// height is the block being worked on now, we want the previous block
		s.logger.Info(bcStatus.GetBlock().GetHeight())
		topBlockNumber := uint64(bcStatus.GetBlock().GetHeight())
		return topBlockNumber, nil
	case "earliest":
		return 0, nil
	case "pending":
		return 0, fmt.Errorf("unsupported: fabric does not have the concept of in-progress blocks being visible")
	default:
		return strconv.ParseUint(input, 16, 64)
	}
}

func (s *ethService) GetCode(r *http.Request, arg *string, reply *string) error {
	if len(*arg) != contracrLength {
		return fmt.Errorf("Invalid Transaction Hash,Expect Length:%d, But Got:%d\n", contracrLength, len(*arg))
	}
	evmAddrStr := *arg
	name, err := evm2xuper(evmAddrStr)
	if err != nil {
		return err
	}

	pbContractParams := &pb.ContractParams{
		Header: &pb.Header{
			Logid: global.Glogid(),
		},
		Bcname: "xuper",
		Name:   name,
	}
	contractParams, err := s.xchainClient.GetContractParams(context.TODO(), pbContractParams)
	if err != nil {
		s.logger.Error(err)
		return fmt.Errorf("Can Not Get the Code\n")
	}
	*reply = string(contractParams.Code)
	return nil

}

func parseTransaction(tx *pb.Transaction) (*types.Transaction, error) {
	fmt.Printf("Tom Parse Transaction")
	from := tx.Initiator
	if tx.Coinbase {
		from = coinBaseFrom
	}
	to := ""
	valueTotal := big.NewInt(0)
	feeTotal := big.NewInt(0)
	for _, output := range tx.TxOutputs {
		if string(output.ToAddr) != from && string(output.ToAddr) != "$" {
			to = string(output.ToAddr) // todo 如果有多个地址怎么办
			val := big.NewInt(0).SetBytes(output.Amount)
			valueTotal = valueTotal.Add(valueTotal, val)
		}
		if string(output.ToAddr) == "$" {
			val := big.NewInt(0).SetBytes(output.Amount)
			feeTotal = feeTotal.Add(feeTotal, val)
		}
	}
	blockHash := "0x" + hex.EncodeToString(tx.Blockid)
	txHash := "0x" + hex.EncodeToString(tx.Txid)

	type InvokeRequest struct {
		ModuleName   string            `json:"moduleName"`
		ContractName string            `json:"contractName"`
		MethodName   string            `json:"methodName"`
		Args         map[string]string `json:"args"` // resourceLimit没有记录
	}

	tmpReq := InvokeRequest{}
	if tx.ContractRequests != nil {
		for i := 0; i < len(tx.ContractRequests); i++ {
			req := tx.ContractRequests[i]
			tmpReq.ModuleName = req.ModuleName
			tmpReq.ContractName = req.ContractName
			tmpReq.MethodName = req.MethodName
			tmpReq.Args = map[string]string{}
			for argKey, argV := range req.Args {
				tmpReq.Args[argKey] = string(argV)
			}
		}
	}
	bz, err := json.MarshalIndent(tmpReq, "", "")
	if err != nil {
		return nil, fmt.Errorf("Marshal input error\n")
	}

	transaction := &types.Transaction{
		BlockHash: blockHash,
		//BlockNumber:"0",
		Hash:             txHash,
		From:             from,
		To:               to,
		TransactionIndex: "0", // 暂不支持
		Input:            string(bz),
		Gas:              feeTotal.String(),
		GasPrice:         "0x1",
		Value:            valueTotal.String(),
	}
	return transaction, nil
}

func evm2xuper(evmAddrStr string) (string, error) {
	evmAddr, err := crypto.AddressFromHexString(evmAddrStr[2:])
	if err != nil {
		return "", fmt.Errorf("can not parse the string address to evm address")
	}
	name, _, err := evm.DetermineEVMAddress(evmAddr)
	if err != nil {
		return "", fmt.Errorf("can not parse the evm address to contract name")
	}
	return name, nil
}

func xuper2evm(name string) (string, error) {
	addr, _, err := evm.DetermineXchainAddress(name)
	if err != nil {
		return "", err
	}
	return "0x" + addr, nil
}
