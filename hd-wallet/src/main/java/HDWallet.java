import org.bitcoinj.core.ECKey;
import org.bitcoinj.core.LegacyAddress;
import org.bitcoinj.core.NetworkParameters;
import org.bitcoinj.core.SegwitAddress;
import org.bitcoinj.crypto.*;
import org.bitcoinj.params.MainNetParams;
import org.bitcoinj.script.Script;
import org.bitcoinj.script.ScriptBuilder;
import org.bitcoinj.wallet.UnreadableWalletException;
import org.web3j.crypto.MnemonicUtils;
import org.web3j.utils.Numeric;

import java.security.InvalidAlgorithmParameterException;
import java.security.NoSuchAlgorithmException;
import java.util.List;

public class HDWallet {


    public static void main(String[] args) throws UnreadableWalletException, NoSuchAlgorithmException, InvalidAlgorithmParameterException {
//随机生成12个助记词
//      String mnemonic = MnemonicUtils.generateMnemonic();
//      System.out.println("mnemonic = " + mnemonic);
        String mnemonic = "sentence script path test catch describe little miss item stage nut solution";
        System.out.println("助记词 ： " + mnemonic);
        // 由助记词得到种子
        byte[] seed = MnemonicUtils.generateSeed(mnemonic, "");
        System.out.println("种子 ：" + Numeric.toHexString(seed));
        NetworkParameters params = MainNetParams.get();

        // 生成根私钥 root private key
        DeterministicKey rootPrivateKey = HDKeyDerivation.createMasterPrivateKey(seed);
        System.out.println("BIP32 Root Key = " + rootPrivateKey.serializePrivB58(params));
        //生成 HD 钱包 , 由根私钥
        DeterministicHierarchy hd = new DeterministicHierarchy(rootPrivateKey);
        // 定义父路径
        List<ChildNumber> parentPath44 = HDUtils.parsePath("44H / 0H / 0H / 0 ");
        List<ChildNumber> parentPath49 = HDUtils.parsePath("49H / 0H / 0H / 0 ");
        List<ChildNumber> parentPath84 = HDUtils.parsePath("84H / 0H / 0H / 0 ");
        System.out.println(parentPath44);
        System.out.println(parentPath49);
        System.out.println(parentPath84);
        //定义子路径 m/44'/0'/0'/0/0
        DeterministicKey child44 = hd.deriveChild(parentPath44, true, true, new ChildNumber(0));
        //定义子路径 m/49'/0'/0'/0/0
        DeterministicKey child49 = hd.deriveChild(parentPath49, true, true, new ChildNumber(0));
        //定义子路径 m/84'/0'/0'/0/0
        DeterministicKey child84 = hd.deriveChild(parentPath84, true, true, new ChildNumber(0));
        //生成子秘钥
        ECKey ecKey44 = ECKey.fromPrivate(child44.getPrivKey());
        ECKey ecKey49 = ECKey.fromPrivate(child49.getPrivKey());
        ECKey ecKey84 = ECKey.fromPrivate(child84.getPrivKey());
        //------------bip44------------
        //子私钥
        System.out.println("子私钥（childPrivateKey） = " + ecKey44.getPrivateKeyAsWiF(params));
        //子公钥
        System.out.println("子公钥（childPublicKey） = " + ecKey44.getPublicKeyAsHex());
        //生成子地址
        LegacyAddress address_1 = LegacyAddress.fromKey(params, ecKey44);
        System.out.println("1开头的P2PKH地址：" + address_1.toBase58());
        //------------bip49------------
        //子私钥
        System.out.println("子私钥（childPrivateKey） = " + ecKey49.getPrivateKeyAsWiF(params));
        //子公钥
        System.out.println("子公钥（childPublicKey） = " + ecKey49.getPublicKeyAsHex());
        //----------生成子地址----------
        //P2WPKH脚本
        Script scriptP2WPKH = ScriptBuilder.createP2WPKHOutputScript(ecKey49);
        //P2SH-P2WPKH脚本
        Script scriptP2SH_P2WPKH = ScriptBuilder.createP2SHOutputScript(scriptP2WPKH);
        LegacyAddress address_3 = LegacyAddress.fromScriptHash(params, scriptP2SH_P2WPKH.getPubKeyHash());
        System.out.println("3开头的P2SH地址：" + address_3.toBase58());
        //------------bip84------------
        //子私钥
        System.out.println("子私钥（childPrivateKey） = " + ecKey84.getPrivateKeyAsWiF(params));
        //子公钥
        System.out.println("子公钥（childPublicKey） = " + ecKey84.getPublicKeyAsHex());
        //生成子地址
        SegwitAddress address_bc1 = SegwitAddress.fromKey(params, ecKey84);
        System.out.println("bc1开头的P2WPKH地址：" + address_bc1.toBech32());

    }

}
