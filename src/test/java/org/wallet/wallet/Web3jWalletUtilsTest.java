package org.wallet.wallet;

import com.alibaba.fastjson.JSON;
import com.alibaba.fastjson.JSONObject;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.scheduling.concurrent.ThreadPoolTaskExecutor;
import org.wallet.wallet.utils.Web3jWalletUtils;
import org.web3j.crypto.CipherException;
import org.web3j.crypto.Credentials;
import org.web3j.crypto.WalletUtils;

import java.io.IOException;


class Web3jWalletUtilsTest {
    private Logger log = LoggerFactory.getLogger(this.getClass());
    private static Web3jWalletUtils web3jWalletUtils;

    private static final String COMMON_WALLET_PATH = "C:\\tmp\\wallet_home\\common_wallet";
    private static final String BIP39_WALLET_PATH = "C:\\tmp\\wallet_home\\bip39_wallet";

    @BeforeEach
    void setUp() {
        web3jWalletUtils = new Web3jWalletUtils();
    }

    /**
     * generateCommonWallet -- json
     *
     * @throws Exception e
     */
    @Test
    void generateCommonWalletTest() throws Exception {
        Web3jWalletUtils.CommonWallet commonWallet = web3jWalletUtils.generateCommonWallet("");
        log.debug(JSON.toJSONString(commonWallet));
        // load from json
        Web3jWalletUtils.CommonWallet commonWallet1 = web3jWalletUtils.loadCommonWalletFromJson("", commonWallet.getJson());
        log.debug("load from json: " + commonWallet1.getJson());
    }

    /**
     * generateCommonWallet with path -- file
     *
     * @throws Exception e
     */
    @Test
    void generateCommonWalletOnWalletPathTest() throws Exception {
        Web3jWalletUtils.CommonWallet commonWallet = web3jWalletUtils.generateCommonWallet("", COMMON_WALLET_PATH);
        log.debug("generateCommonWallet with path: " + JSON.toJSONString(commonWallet));
        // load from file
        Web3jWalletUtils.CommonWallet commonWallet1 = web3jWalletUtils.loadCommonWalletFromFile("", commonWallet.getPath());
        log.debug("load wallet from file: " + commonWallet1.getJson());
    }

    /**
     * generate bip39Wallet -- json
     *
     * @throws CipherException e
     */
    @Test
    void bip39Wallet2Test() throws CipherException {
        Web3jWalletUtils.Bip39Wallet2 bip39Wallet2 = web3jWalletUtils.generateBip39Wallet("");
        log.debug("generate bip39Wallet: " + JSON.toJSONString(bip39Wallet2));
        // 从json加载钱包
        Web3jWalletUtils.Bip39Wallet2 bip39Wallet21 = web3jWalletUtils.loadBip39WalletFromJson("", bip39Wallet2.getMnemonic(), bip39Wallet2.getJson());
        log.debug("load bip39Wallet from json and mnemonic: " + JSON.toJSONString(bip39Wallet21));
    }

    /**
     * generate bip39Wallet with path -- file
     *
     * @throws CipherException e
     * @throws IOException     e
     */
    @Test
    void bip39Wallet2OnWalletPathTest() throws CipherException, IOException {
        Web3jWalletUtils.Bip39Wallet2 bip39Wallet2 = web3jWalletUtils.generateBip39Wallet("", BIP39_WALLET_PATH);
        log.debug("generate bip39Wallet with path" + JSON.toJSONString(bip39Wallet2));
        Web3jWalletUtils.Bip39Wallet2 bip39Wallet21 = web3jWalletUtils.loadBip39WalletFromFile("", bip39Wallet2.getMnemonic(), bip39Wallet2.getPath());
        log.debug("load bip39Wallet from file" + JSON.toJSONString(bip39Wallet21));
    }

    /**
     * generate random password
     */
    @Test
    void generateRandomPasswordTest() {
        log.debug(web3jWalletUtils.generateRandomPassword());
        log.debug(web3jWalletUtils.generateRandomPassword(16));
    }

    /**
     * bip39Wallet signature and verify transaction
     */
    @Test
    void bip39WalletSignAndVerifyTransaction() throws Exception {
        // TODO: 2020/9/24 generate bip39Wallet with path
        Web3jWalletUtils.Bip39Wallet2 bip39Wallet2 = web3jWalletUtils.generateBip39Wallet("123456", BIP39_WALLET_PATH);
        log.debug("generate bip39Wallet with path" + JSON.toJSONString(bip39Wallet2));
        String password = bip39Wallet2.getPassword();
        String mnemonic = bip39Wallet2.getMnemonic();
        log.debug("wallet password: " + password);
        log.debug("wallet mnemonic: " + mnemonic);

        // TODO: 2020/9/24 set original data
        JSONObject data = new JSONObject();
        data.put("fromWalletAddress", bip39Wallet2.getAddress());
        data.put("toWalletAddress", "0xf7783fbbb1fda904f534ab5269d6bf95539aa56c");
        data.put("value", "99.4");
        data.put("chargeWalletAddress", "0xdd05e23c39eead942bcv63fd388ffa13a1a28307");
        data.put("chargeValue", "0.6");
        String rawData = data.toJSONString();
        log.debug("original dada : " + rawData);

        Credentials credentials = WalletUtils.loadBip39Credentials(password, mnemonic);
        // TODO: 2020/9/24 signature to original data
        String sign = web3jWalletUtils.signTransaction(rawData, credentials.getEcKeyPair());
        // TODO: 2020/9/24 verify signature data
        boolean flag = web3jWalletUtils.verifyTransaction(rawData, bip39Wallet2.getAddress(), sign);
        log.debug("verify result: " + flag);
    }

}