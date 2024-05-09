package org.wallet.wallet.utils;

import com.alibaba.fastjson.JSON;
import com.alibaba.fastjson.JSONObject;
import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.DeserializationFeature;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.SerializationFeature;
import lombok.Data;
import lombok.experimental.Accessors;
import org.apache.commons.lang3.ObjectUtils;
import org.apache.commons.lang3.StringUtils;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.web3j.crypto.*;
import org.web3j.utils.Numeric;

import java.io.File;
import java.io.IOException;
import java.math.BigInteger;
import java.security.InvalidAlgorithmParameterException;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.SecureRandom;
import java.util.Random;

public class Web3jWalletUtils {

    private Logger log = LoggerFactory.getLogger(this.getClass());

    private static final ObjectMapper OBJECT_MAPPER = new ObjectMapper();
    private static final SecureRandom SECURE_RANDOM = SecureRandomUtils.secureRandom();

    static {
        // 转换为格式化的json
        OBJECT_MAPPER.enable(SerializationFeature.INDENT_OUTPUT);
        // 如果json中有新增的字段并且是实体类类中不存在的，不报错
        OBJECT_MAPPER.configure(DeserializationFeature.FAIL_ON_UNKNOWN_PROPERTIES, false);
    }

    public Web3jWalletUtils() {

    }

    /**
     * generateCommonWallet
     *
     * @param password       wallet password
     * @param walletFilePath wallet file path
     * @return CommonWallet
     * @throws Exception e
     */
    public CommonWallet generateCommonWallet(String password, String walletFilePath) throws Exception {
        try {
            String walletFileName = WalletUtils.generateNewWalletFile(password, new File(walletFilePath), false);
            String path = StringUtils.isNotBlank(walletFilePath) && File.separator.equals(walletFilePath.substring(walletFilePath.length() - 1)) ? walletFilePath + walletFileName : walletFilePath + File.separator + walletFileName;
            Credentials credentials = WalletUtils.loadCredentials(password, path);
            String address = credentials.getAddress();
            BigInteger publicKey = credentials.getEcKeyPair().getPublicKey();
            BigInteger privateKey = credentials.getEcKeyPair().getPrivateKey();
            return new CommonWallet(address, password, privateKey, publicKey, path);
        } catch (NoSuchAlgorithmException | InvalidAlgorithmParameterException | NoSuchProviderException | CipherException | IOException e) {
            throw new Exception(e);
        }
    }

    /**
     * generateCommonWallet
     *
     * @param password password
     * @return CommonWallet
     * @throws Exception e
     */
    public CommonWallet generateCommonWallet(String password) throws Exception {
        try {
            ECKeyPair ecKeyPair = Keys.createEcKeyPair();
            WalletFile walletFile = generateWalletFile(password, ecKeyPair, false);
            BigInteger publicKey = ecKeyPair.getPublicKey();
            BigInteger privateKey = ecKeyPair.getPrivateKey();
            return new CommonWallet(walletFile.getAddress(), JSON.toJSONString(walletFile), password, privateKey, publicKey);
        } catch (NoSuchAlgorithmException | InvalidAlgorithmParameterException | NoSuchProviderException | CipherException e) {
            throw new Exception(e);
        }
    }

    /**
     * load wallet from json
     *
     * @param password wallet password
     * @param json     wallet json
     * @return CommonWallet
     * @throws JsonProcessingException jsonProcessingException
     * @throws CipherException         cipherException
     */
    public CommonWallet loadCommonWalletFromJson(String password, String json) throws JsonProcessingException, CipherException {
        WalletFile walletFile = OBJECT_MAPPER.readValue(json, WalletFile.class);
        log.debug("walletJson: " + JSON.toJSONString(walletFile));
        Credentials credentials = loadCredentials(password, walletFile);
        String address = credentials.getAddress();
        ECKeyPair ecKeyPair = credentials.getEcKeyPair();
        BigInteger privateKey = ecKeyPair.getPrivateKey();
        BigInteger publicKey = ecKeyPair.getPublicKey();
        return new CommonWallet(address, json, password, privateKey, publicKey);
    }

    /**
     * load wallet from file
     *
     * @param password       password
     * @param walletFilePath wallet file path
     * @return CommonWallet
     * @throws IOException     e
     * @throws CipherException e
     */
    public CommonWallet loadCommonWalletFromFile(String password, String walletFilePath) throws IOException, CipherException {
        Credentials credentials = WalletUtils.loadCredentials(password, walletFilePath);
        String address = credentials.getAddress();
        ECKeyPair ecKeyPair = credentials.getEcKeyPair();
        BigInteger privateKey = ecKeyPair.getPrivateKey();
        BigInteger publicKey = ecKeyPair.getPublicKey();
        return new CommonWallet(address, password, privateKey, publicKey, walletFilePath);
    }

    /**
     * generateBip39Wallet
     *
     * @param password wallet password
     * @return CommonWallet
     * @throws CipherException e
     */
    public Bip39Wallet2 generateBip39Wallet(String password) throws CipherException {
        byte[] initialEntropy = new byte[16];
        SECURE_RANDOM.nextBytes(initialEntropy);
        String mnemonic = MnemonicUtils.generateMnemonic(initialEntropy);
        byte[] seed = MnemonicUtils.generateSeed(mnemonic, password);
        ECKeyPair ecKeyPair = ECKeyPair.create(Hash.sha256(seed));
        WalletFile walletFile = generateWalletFile(password, ecKeyPair, false);
        return new Bip39Wallet2(walletFile.getAddress(), mnemonic, password, JSON.toJSONString(walletFile), ecKeyPair.getPrivateKey(), ecKeyPair.getPublicKey());
    }

    /**
     * loadBip39Wallet from json
     *
     * @param password password
     * @param mnemonic mnemonic
     * @param json     json
     * @return Bip39Wallet2
     */
    public Bip39Wallet2 loadBip39WalletFromJson(String password, String mnemonic, String json) {
        Credentials credentials = WalletUtils.loadBip39Credentials(password, mnemonic);
        return new Bip39Wallet2(credentials.getAddress(), json, mnemonic, password, credentials.getEcKeyPair().getPrivateKey(), credentials.getEcKeyPair().getPublicKey());
    }

    /**
     * loadBip39WalletFromFile
     *
     * @param password       password
     * @param mnemonic       mnemonic
     * @param walletFilePath wallet file path
     * @return Bip39Wallet2
     */
    public Bip39Wallet2 loadBip39WalletFromFile(String password, String mnemonic, String walletFilePath) {
        Credentials credentials = WalletUtils.loadBip39Credentials(password, mnemonic);
        return new Bip39Wallet2(credentials.getAddress(), mnemonic, password, credentials.getEcKeyPair().getPrivateKey(), credentials.getEcKeyPair().getPublicKey(), walletFilePath);
    }

    /**
     * generateBip39Wallet
     *
     * @param password       password
     * @param walletFilePath wallet file path
     * @return CommonWallet
     * @throws CipherException e
     */
    public Bip39Wallet2 generateBip39Wallet(String password, String walletFilePath) throws CipherException, IOException {
        Bip39Wallet bip39Wallet = WalletUtils.generateBip39Wallet(password, new File(walletFilePath));
        String mnemonic = bip39Wallet.getMnemonic();
        // wallet file name
        String filename = bip39Wallet.getFilename();
        Credentials credentials = WalletUtils.loadBip39Credentials(password, mnemonic);
        String address = credentials.getAddress();
        BigInteger publicKey = credentials.getEcKeyPair().getPublicKey();
        BigInteger privateKey = credentials.getEcKeyPair().getPrivateKey();
        String path = StringUtils.isNotBlank(walletFilePath) && File.separator.equals(walletFilePath.substring(walletFilePath.length() - 1)) ? walletFilePath + filename : walletFilePath + File.separator + filename;
        return new Bip39Wallet2(address, mnemonic, password, privateKey, publicKey, path);
    }

    public static Credentials loadCredentials(String password, WalletFile walletFile) throws CipherException {
        return Credentials.create(Wallet.decrypt(password, walletFile));
    }

    public static WalletFile generateWalletFile(String password, ECKeyPair ecKeyPair, boolean useFullScrypt) throws CipherException {
        WalletFile walletFile;
        if (useFullScrypt) {
            walletFile = Wallet.createStandard(password, ecKeyPair);
        } else {
            walletFile = Wallet.createLight(password, ecKeyPair);
        }
        return walletFile;
    }

    public String signTransaction(String json, ECKeyPair keyPair) {
        Sign.SignatureData signatureData = Sign.signMessage(json.getBytes(), keyPair);
        JSONObject signatureDataJson = new JSONObject();
        signatureDataJson.put("v", Numeric.toBigInt(signatureData.getV()));
        signatureDataJson.put("r", Numeric.toBigInt(signatureData.getR()));
        signatureDataJson.put("s", Numeric.toBigInt(signatureData.getS()));
        return signatureDataJson.toJSONString();
    }

    /**
     * verify data
     * get public key and get wallet address with sign
     *
     * @param data          data
     * @param walletAddress walletAddress
     * @param strSign       signature data
     * @return boolean
     * @throws Exception e
     */
    public boolean verifyTransaction(String data, String walletAddress, String strSign) throws Exception {
        try {
            if (StringUtils.isBlank(data)) {
                return false;
            }

            JSONObject jsonSign = JSONObject.parseObject(strSign);
            if (jsonSign == null) {
                return false;
            }

            byte v = jsonSign.getByte("v");
            byte[] r = Numeric.toBytesPadded(jsonSign.getBigInteger("r"), 32);
            byte[] s = Numeric.toBytesPadded(jsonSign.getBigInteger("s"), 32);

            Sign.SignatureData signatureData = new Sign.SignatureData(v, r, s);

            BigInteger publicKey = Sign.signedMessageToKey(data.getBytes(), signatureData);
            return StringUtils.equalsIgnoreCase("0x" + Keys.getAddress(publicKey), walletAddress);
        } catch (Exception e) {
            e.printStackTrace();
            throw new Exception(e);
        }
    }

    public String generateRandomPassword() {
        return generateRandomPassword(8);
    }

    public String generateRandomPassword(Integer count) {
        if (ObjectUtils.isEmpty(count)) {
            throw new RuntimeException("count must setting");
        }
        StringBuilder codeNum = new StringBuilder();
        int[] code = new int[3];
        Random random = new Random();
        for (int i = 0; i < count; i++) {
            int num = random.nextInt(10) + 48;
            int uppercase = random.nextInt(26) + 65;
            int lowercase = random.nextInt(26) + 97;
            code[0] = num;
            code[1] = uppercase;
            code[2] = lowercase;
            codeNum.append((char) code[random.nextInt(3)]);
        }
        return codeNum.toString();
    }

    @Data
    @Accessors(chain = true)
    public static class CommonWallet {
        private String address;
        private String json;
        private String password;
        private BigInteger privateKey;
        private String privateKeyHexStr;
        private BigInteger publicKey;
        private String publicKeyHexStr;
        private String path;

        public CommonWallet(String address, String json, String password, BigInteger privateKey, BigInteger publicKey) {
            this.address = address;
            this.json = json;
            this.password = password;
            this.privateKey = privateKey;
            this.publicKey = publicKey;
            this.path = "";
            this.setPrivateKeyHexStr(privateKey);
            this.setPublicKeyHexStr(publicKey);
        }

        public CommonWallet(String address, String password, BigInteger privateKey, BigInteger publicKey, String path) {
            this.address = address;
            this.json = "";
            this.password = password;
            this.privateKey = privateKey;
            this.publicKey = publicKey;
            this.path = path;
            this.setPrivateKeyHexStr(privateKey);
            this.setPublicKeyHexStr(publicKey);
        }

        public void setPrivateKeyHexStr(BigInteger privateKey) {
            this.privateKeyHexStr = Numeric.toHexStringWithPrefix(privateKey);
        }

        public void setPublicKeyHexStr(BigInteger publicKey) {
            this.publicKeyHexStr = Numeric.toHexStringWithPrefix(publicKey);
        }

    }

    @Data
    @Accessors(chain = true)
   public static class Bip39Wallet2 {
        private String address;
        private String password;
        private String json;
        private BigInteger privateKey;
        private String privateKeyHexStr;
        private BigInteger publicKey;
        private String publicKeyHexStr;
        private String mnemonic;
        private String path;

        public Bip39Wallet2(String address, String mnemonic, String password, String json, BigInteger privateKey, BigInteger publicKey) {
            this.address = address;
            this.password = password;
            this.json = json;
            this.privateKey = privateKey;
            this.publicKey = publicKey;
            this.mnemonic = mnemonic;
            this.path = "";
            this.setPrivateKeyHexStr(privateKey);
            this.setPublicKeyHexStr(publicKey);
        }

        public Bip39Wallet2(String address, String mnemonic, String password, BigInteger privateKey, BigInteger publicKey, String path) {
            this.address = address;
            this.password = password;
            this.json = "";
            this.privateKey = privateKey;
            this.publicKey = publicKey;
            this.mnemonic = mnemonic;
            this.path = path;
            this.setPrivateKeyHexStr(privateKey);
            this.setPublicKeyHexStr(publicKey);
        }


        public void setPrivateKeyHexStr(BigInteger privateKey) {
            this.privateKeyHexStr = Numeric.toHexStringWithPrefix(privateKey);
        }

        public void setPublicKeyHexStr(BigInteger publicKey) {
            this.publicKeyHexStr = Numeric.toHexStringWithPrefix(publicKey);
        }
    }
}