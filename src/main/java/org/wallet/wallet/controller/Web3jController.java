package org.wallet.wallet.controller;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;
import org.web3j.protocol.Web3j;
import org.web3j.protocol.core.DefaultBlockParameterNumber;
import org.web3j.protocol.core.Request;
import org.web3j.protocol.core.methods.response.EthBlockNumber;
import org.web3j.protocol.core.methods.response.EthGasPrice;
import org.web3j.protocol.core.methods.response.EthGetBalance;
import org.web3j.protocol.core.methods.response.EthBlock;
import org.web3j.utils.Convert;

import java.io.IOException;
import java.math.BigDecimal;
import java.math.BigInteger;

@RestController
public class Web3jController {

    @Autowired
    private Web3j web3j;


    @GetMapping("/getBlockNumber")
    public BigInteger getBlockNumber() throws IOException {
        Request<?, EthBlockNumber> ethBlockNumberRequest = web3j.ethBlockNumber();
        BigInteger blockNumber = ethBlockNumberRequest.send().getBlockNumber();
        return blockNumber;
    }

    @GetMapping("/getGasPrice")
    public BigInteger getGasPrice() throws IOException {
        EthGasPrice ethGasPrice = web3j.ethGasPrice().send();
        BigInteger gasFee = ethGasPrice.getGasPrice();
        return gasFee;
    }

    @GetMapping("/getGasLimit")
    public BigInteger getGasLimit() throws IOException {
        EthBlock send = web3j.ethGetBlockByNumber(new DefaultBlockParameterNumber(5686059), true).send();
        BigInteger gasLimit = send.getBlock().getGasLimit();
        return gasLimit;
    }

    @GetMapping("/getBalance")
    public BigDecimal getBalance(@RequestParam("address") String address) throws IOException {
        EthGetBalance ethGetBalance = web3j.ethGetBalance(address, new DefaultBlockParameterNumber(5686059)).send();
        BigInteger balance = ethGetBalance.getBalance();
        BigDecimal bigDecimal = Convert.fromWei(balance.toString(), Convert.Unit.ETHER);
        return bigDecimal;
    }
}
