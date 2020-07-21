import io.eblock.eos4j.Ecc;
import org.bitcoinj.core.ECKey;
import org.bitcoinj.core.LegacyAddress;
import org.bitcoinj.core.NetworkParameters;
import org.bitcoinj.core.SegwitAddress;
import org.bitcoinj.crypto.*;
import org.bitcoinj.params.MainNetParams;
import org.bitcoinj.script.Script;
import org.bitcoinj.script.ScriptBuilder;
import org.bitcoinj.wallet.DeterministicSeed;
import org.bitcoinj.wallet.UnreadableWalletException;
import org.web3j.crypto.ECKeyPair;
import org.web3j.crypto.Keys;
import org.web3j.crypto.MnemonicUtils;
import org.web3j.utils.Numeric;

import java.security.InvalidAlgorithmParameterException;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.util.Arrays;
import java.util.List;

public class HDWallet {


    public static void main(String[] args) throws UnreadableWalletException, NoSuchAlgorithmException, InvalidAlgorithmParameterException, MnemonicException.MnemonicLengthException {
//随机生成12个助记词
        SecureRandom secureRandom = new SecureRandom();
        byte[] entropy = new byte[DeterministicSeed.DEFAULT_SEED_ENTROPY_BITS / 8];
        secureRandom.nextBytes(entropy);
        //生成12位助记词
        List<String>  mnemonic = MnemonicCode.INSTANCE.toMnemonic(entropy);
      //  System.out.println("mnemonic = " + mnemonic);
        String mnemonic0 = "unfair raccoon electric valve session fish catch near industry increase pipe nominee";
      //System.out.println("助记词 ： " + mnemonic.toString().replace(',', ' '));
        // 由助记词得到种子
        byte[] seed = MnemonicCode.toSeed(Arrays.asList(mnemonic0), "");
        System.out.println("种子 ：" + Numeric.toHexString(seed));
        NetworkParameters params = MainNetParams.get();

        // 生成根私钥 root private key
        DeterministicKey rootPrivateKey = HDKeyDerivation.createMasterPrivateKey(seed);
        System.out.println("BIP32 Root Key = " + rootPrivateKey.serializePrivB58(params));
        //生成 HD 钱包 , 由根私钥
        DeterministicHierarchy hd = new DeterministicHierarchy(rootPrivateKey);
        // 定义父路径
        List<ChildNumber> btcPath44 = HDUtils.parsePath("44H / 0H / 0H / 0 ");
        List<ChildNumber> btcPath49 = HDUtils.parsePath("49H / 0H / 0H / 0 ");
        List<ChildNumber> btcPath84 = HDUtils.parsePath("84H / 0H / 0H / 0 ");
        System.out.println(btcPath44);
        System.out.println(btcPath49);
        System.out.println(btcPath84);
        //定义子路径 m/44'/0'/0'/0/0
        DeterministicKey child44 = hd.deriveChild(btcPath44, true, true, new ChildNumber(0));
        //定义子路径 m/49'/0'/0'/0/0
        DeterministicKey child49 = hd.deriveChild(btcPath49, true, true, new ChildNumber(0));
        //定义子路径 m/84'/0'/0'/0/0
        DeterministicKey child84 = hd.deriveChild(btcPath84, true, true, new ChildNumber(0));
        //生成子秘钥
        ECKey ecKey44 = ECKey.fromPrivate(child44.getPrivKey());
        System.out.println("ecKey44 = " + ecKey44.getPublicKeyAsHex());
//        ECKey ecKey442 = ECKey.fromPrivate(child44.getPrivKey(),true);
//        System.out.println("ecKey44 = " + ecKey442.getPublicKeyAsHex());
        ECKey ecKey49 = ECKey.fromPrivate(child49.getPrivKey());
        ECKey ecKey84 = ECKey.fromPrivate(child84.getPrivKey());
        System.out.println("-----------------BTC----------------------");
        System.out.println("------------bip44------------");
        //子私钥
        System.out.println("BTC bip44私钥 = " + ecKey44.getPrivateKeyAsWiF(params));
        //子公钥
        System.out.println("BTC bip44公钥 = " + ecKey44.getPublicKeyAsHex());
        //生成子地址
        LegacyAddress address_1 = LegacyAddress.fromKey(params, ecKey44);
        System.out.println("1开头的P2PKH地址：" + address_1.toBase58());
        System.out.println("1开头的P2PKH地址：" + address_1.getOutputScriptType());
        System.out.println("1开头的P2PKH地址：" + address_1);
        //------------bip49------------
        System.out.println("------------bip49------------");
        //子私钥
        System.out.println("BTC bip49私钥 = " + ecKey49.getPrivateKeyAsWiF(params));
        //子公钥
        System.out.println("BTC bip49公钥 = " + ecKey49.getPublicKeyAsHex());
        //----------生成子地址----------
        //P2WPKH脚本
        Script scriptP2WPKH = ScriptBuilder.createP2WPKHOutputScript(ecKey49);
        //P2SH-P2WPKH脚本
        Script scriptP2SH_P2WPKH = ScriptBuilder.createP2SHOutputScript(scriptP2WPKH);
        LegacyAddress address_3 = LegacyAddress.fromScriptHash(params, scriptP2SH_P2WPKH.getPubKeyHash());
        System.out.println("3开头的P2SH地址：" + address_3.toBase58());
        System.out.println("3开头的P2SH地址：" + address_3.getOutputScriptType());
        //------------bip84------------
        System.out.println("------------bip84------------");
        //子私钥
        System.out.println("BTC bip84私钥 = " + ecKey84.getPrivateKeyAsWiF(params));
        //子公钥
        System.out.println("BTC bip84公钥 = " + ecKey84.getPublicKeyAsHex());
        //生成子地址
        SegwitAddress address_bc1 = SegwitAddress.fromKey(params, ecKey84);
        System.out.println("bc1开头的P2WPKH地址：" + address_bc1.toBech32());
        System.out.println("bc1开头的P2WPKH地址：" + address_bc1.getOutputScriptType());

        //-----------ETH---------
        System.out.println("-----------------ETH----------------------");
        System.out.println("------------bip44------------");
        List<ChildNumber> ethPath = HDUtils.parsePath("44H / 60H / 0H / 0 ");
        //定义子路径 m/44'/60'/0'/0/0
        DeterministicKey childETH = hd.deriveChild(ethPath, true, true, new ChildNumber(0));
        byte[] bytes = childETH.getPrivKeyBytes();
        ECKeyPair keyPair = ECKeyPair.create(bytes);
        //通过公钥生成钱包地址
        String address = Keys.getAddress(keyPair.getPublicKey());
        System.out.println("ETH bip44私钥：" + "0x"+keyPair.getPrivateKey().toString(16));
        System.out.println("ETH bip44公钥：" + keyPair.getPublicKey().toString(16));
        System.out.println("ETH地址：" + "0x"+address);

        System.out.println("-----------------EOS----------------------");
        System.out.println("------------bip44------------");
        List<ChildNumber> eosPath = HDUtils.parsePath("44H / 194H / 0H / 0 ");
        DeterministicKey eosChild = hd.deriveChild(eosPath, true, true, new ChildNumber(0));
        ECKey eosKey = ECKey.fromPrivate(eosChild.getPrivKey(),false);
        String privateKey = eosKey.getPrivateKeyAsWiF(params);
        System.out.println("eos bip44私钥 = " + privateKey);
        String publicKey = Ecc.privateToPublic(privateKey);
        System.out.println("eos bip44公钥 = " + publicKey);


    }

}
