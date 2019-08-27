package com.iri.utils.crypto.ellipticcurve;

import org.json.JSONObject;
import org.junit.Assert;
import org.junit.Test;

import java.io.IOException;
import java.security.NoSuchAlgorithmException;

public class EcdsaUtilsTest {
    @Test
    public void testVerifyMessage(){
        String address = "1vofXj4Vf2cgJDQrbbN2Zc6gG9qmRmk96";
        String message = "123456";
        String signature = "ILvxYFjP/tAA9ce/JDxB1RQf0Pgu5SqxATP+8EsGZ+EVaz9Z3BETmSbraem9waMksWBTPPcjTXZJvpsTGdcLIn4=";
        try {
            EcdsaUtils.ValidRes res = EcdsaUtils.verifyMessage(signature, message, address);
            System.out.println(JSONObject.valueToString(res));
            assert res.verifyResult();
        } catch (NoSuchAlgorithmException e) {
            e.printStackTrace();
        } catch (IOException e) {
            e.printStackTrace();
        }
    }

    @Test
    public void testSign() throws IOException, NoSuchAlgorithmException {
        String message = "123456";
        String pk = "KxPgZSiHf4QirYmX2AGjhQ8jXNErHQoUzcbttumtQ9wShaP1tSoX";
        String address = "1vofXj4Vf2cgJDQrbbN2Zc6gG9qmRmk96";

        System.out.println("privateKey :" + pk);
        System.out.println("address :" + address);
        String sign = EcdsaUtils.sign(message, pk, address);
        System.out.println("sign: "+sign);
        EcdsaUtils.ValidRes res = EcdsaUtils.verifyMessage(sign, message, address);
        Assert.assertTrue(res.errMessage(), res.verifyResult());
    }

    @Test
    public void testGenSkAddressPair(){
        EcdsaUtils.SecureInfo secureInfo = EcdsaUtils.generateSecureInfo();
        System.out.println("privateKey:" + secureInfo.getPrivateKey());
        System.out.println("address:" + secureInfo.getAddress());
    }

    @Test
    public void testGenAddress() throws NoSuchAlgorithmException, IOException {
        String base58 = "KxPgZSiHf4QirYmX2AGjhQ8jXNErHQoUzcbttumtQ9wShaP1tSoX";
        PrivateKey privateKey = PrivateKey.fromBase58(base58);
        System.out.println(privateKey.toPem());
        String address = EcdsaUtils.generateAddress(privateKey);
        System.out.println("address:"+address);
        //验证地址和密钥可以用来签名
        String message = "123456";
        String sign = EcdsaUtils.sign(address, base58, address);
        EcdsaUtils.verifyMessage(sign, message, address);
    }
}
