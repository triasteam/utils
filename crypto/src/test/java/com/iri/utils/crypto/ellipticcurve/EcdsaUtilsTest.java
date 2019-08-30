package com.iri.utils.crypto.ellipticcurve;

import com.iri.utils.crypto.ellipticcurve.utils.BinaryAscii;
import org.json.JSONObject;
import org.junit.Assert;
import org.junit.Test;

import java.io.IOException;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.Random;

public class EcdsaUtilsTest {
    @Test
    public void testVerifyMessage(){
//        String address = "1vofXj4Vf2cgJDQrbbN2Zc6gG9qmRmk96";
//        String message = "123456";
//        String signature = "ILvxYFjP/tAA9ce/JDxB1RQf0Pgu5SqxATP+8EsGZ+EVaz9Z3BETmSbraem9waMksWBTPPcjTXZJvpsTGdcLIn4=";
        String message = "14dc7dd0ca5ff7cf4fad6fcd09b7919f606daab262d7a7ace87b78522eb89520";
        String signature = "IBUVX6m3MB8QfJmeIzKBgsPvH3RoT4Srbbm6Xe55cUKpSlYi4jw53sj8SVlzsEjP64DRwrut58uMADIolhk+J5Y=";
        String address = "1NZbawYVWRBnqBuVqbb8Z7CVpwsokNUSZ9";
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
        String base58 = "KxSgY5kZnTYQfVc2eXnkqPuLwVyY221N3uSsQtRJx5kf2o2Eyde4";
        PrivateKey privateKey = PrivateKey.fromBase58(base58);
        System.out.println(privateKey.toPem());
        String address = EcdsaUtils.generateAddress(privateKey);
        System.out.println("address:"+address);
        //17ZkxK119QCeQ7YJ6UgDLfdPqxJX1AiwdK
//        13KQh492C4V7ZeaVHkqoPxRS1fRpMrhqQB
//
//        -----BEGIN EC PRIVATE KEY-----
//        MHUCAQEEIU3wZ4xSeV6EV1m0AaQ/xsFRE2O60lS0WTFbKn0wDtFW3qAHBgUrgQQA
//        CqFEA0IABOPneeLx+8RFF/Gr8NTrPGvZLu5LC+6qGDcoNsluxZbL1yFJOAR2DlrU
//        YvyYPyWkxeqEOI+rfQecau+PcepYeLY=
//                -----END EC PRIVATE KEY-----

//        String message = "123456";
//        String sign = EcdsaUtils.sign(address, base58, address);
        // from python cli
//        sign = "IECCntPLBtCBeGhUQDmhzW1h4CFpDDqI+JLs0T5nCv9AmhbVolQkcfK2DexF89ewdCSD1eT5/rmpzGqJAY/Whls=";
//        EcdsaUtils.verifyMessage(sign, message, address);
    }

    @Test
    public void testReadData() throws NoSuchAlgorithmException, IOException {
        String json = "{\"address\": \"1vofXj4Vf2cgJDQrbbN2Zc6gG9qmRmk96\", \"attestee\": \"10.0.0.2\", \"attester\": \"10.0.0.1\", \"nonce\": \"1\", \"score\": \"1\", \"time\": \"2213223190\"}";
        MessageDigest digest = MessageDigest.getInstance("SHA-256");
        digest.update(json.getBytes());
        String message = BinaryAscii.hexFromBinary(digest.digest());
        String address = "1vofXj4Vf2cgJDQrbbN2Zc6gG9qmRmk96";
        String sign = "H3bfDz12p0vxvqrx68Fx0Y49yyoAvC2fapuvbZTiF4KEhc1Kv25vhRPYbg9QvQltcvP9+U5D+yMC3ChOUusYqbQ=";
        EcdsaUtils.ValidRes res = EcdsaUtils.verifyMessage(sign, message, address);
        System.out.println(res);
    }

    @Test
    public void testRandom(){
        Random random = new Random();


        for (int j=0; j<100; j++){
//            System.out.println(random.nextInt(9999));
            int rand;
            for (; (rand = random.nextInt(9999)) < 1000 ;);

            System.out.println(rand);

//            System.out.println(random.nextInt());
//            System.out.println(7>>1);
        }
    }
}