package ethereum_proxy

import (
	"context"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"github.com/Tri-stone/ethereum_proxy/types"
	"github.com/xuperchain/xuperchain/core/global"
	"github.com/xuperchain/xuperchain/core/pb"
	"math/big"
	"net/http"
	"strconv"
)

//func (s *ethService) GetTransactionReceipt(r *http.Request, arg *string, reply *types.TxReceipt) error{    //todo
//	if len(*arg) != txLength {
//		return fmt.Errorf("invalid transaction hash,expect length:%d, but got:%d", txLength, len(*txID))
//	}
//	rawTxId, err := hex.DecodeString(*arg)
//	if err != nil {
//		s.logger.Error(err)
//		return fmt.Errorf("invalid transcation hash")
//	}
//
//
//
//
//}

func (s *ethService) GetTransactionByHash(r *http.Request, txID *string, reply *types.Transaction) error {
	if len(*txID) != txHadhLength {
		return fmt.Errorf("invalid transaction hash,expect length:%d, but got:%d", txHadhLength, len(*txID))
	}
	rawTxId, err := hex.DecodeString((*txID)[2:])
	if err != nil {
		s.logger.Error(err)
		return fmt.Errorf("invalid transcation hash")
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
		return fmt.Errorf("get transaction error")
	}
	tx, err := parseTransaction(txStatus.Tx)
	if err != nil {
		s.logger.Error(err)
		return fmt.Errorf("can not parse the transaction")
	}

	block,err := s.getBlockByHash(tx.BlockHash,false)
	if err != nil {
		s.logger.Error(err)
		return fmt.Errorf("get Block number error:%s\n",err.Error())
	}
	tx.BlockNumber = block.Number
	*reply = *tx
	return nil
}

func parseTransaction(tx *pb.Transaction) (*types.Transaction, error) {
	from := tx.Initiator
	if tx.Coinbase {
		from = coinBaseFrom
	}
	to := tx.Initiator
	valueTotal := big.NewInt(0)
	for _, output := range tx.TxOutputs {
		if string(output.ToAddr) != from && string(output.ToAddr) != "$" {
			to = string(output.ToAddr)
			val := big.NewInt(0).SetBytes(output.Amount)
			valueTotal = valueTotal.Add(valueTotal, val)
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
		BlockHash:        blockHash,
		Hash:             txHash,
		From:             from,
		To:               to,
		Input:            string(bz),
		GasPrice:         "",
		Value:            valueTotal.String(),
	}
	return transaction, nil
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
	account := params[0]
	pbAddrStatus := &pb.AddressStatus{
		Address: account,
		Bcs: []*pb.TokenDetail{
			{Bcname: bcName},
		},
	}
	addrStatus, err := s.xchainClient.GetBalance(context.TODO(), pbAddrStatus)
	if err != nil {
		s.logger.Error(err)
		return fmt.Errorf("can not get Balance from ledger\n")
	}
	balance := addrStatus.Bcs[0].Balance	// todo 如果有多个币种？
	*reply = balance
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
		return fmt.Errorf("invalid block hash,expect length:%d, but got:%d", txHadhLength, len(blockHash))
	}

	fullTransactions, ok := params[1].(bool)
	if !ok {
		return fmt.Errorf("Incorrect second parameter sent, must be boolean")
	}
	block,err := s.getBlockByHash(blockHash,fullTransactions)
	if err != nil {
		s.logger.Errorf("getBlockHash error: %#v", err.Error())
		return fmt.Errorf("getBlockHash error")
	}
	*reply = *block
	return nil
}


func (s *ethService)getBlockByHash(blockHash string,fullTransactions bool) (*types.Block,error) {
	rawBlockid, err := hex.DecodeString(blockHash[2:])		// 去掉0x
	if err != nil {
		return nil,fmt.Errorf("invalid blockHash")
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
		return nil,fmt.Errorf("failed to query the ledger: %v", err)
	}

	block, err := parseBlock(b, fullTransactions)
	if err != nil {
		s.logger.Debug(err)
		return nil,fmt.Errorf("failed to query the ledger: %v", err)
	}
	return block,nil
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

		if fullTransactions {
			txn := types.Transaction{
				BlockHash:        blockHash,
				BlockNumber:      blockNumber,
				TransactionIndex: "0x" + strconv.FormatUint(uint64(index), 16),
				Hash:             "0x" + hex.EncodeToString(transactionData.GetTxid()),
			}
			//from, to, input, err := getTransactionInformation(transactionData)
			//if err != nil {
			//	return nil, err
			//}


			tx,err := parseTransaction(transactionData)
			if err != nil {
				return nil,fmt.Errorf("parse Transaction error")
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
		},
		Transactions: txns,
	}
	return blk, nil
}
