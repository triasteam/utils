package com.iri.utils.crypto.ellipticcurve;

import com.iri.utils.crypto.ellipticcurve.utils.BinaryAscii;
import com.iri.utils.crypto.ellipticcurve.utils.ByteString;
import com.iri.utils.crypto.ellipticcurve.utils.Der;
import com.iri.utils.crypto.ellipticcurve.utils.RandomInteger;
import io.ipfs.multibase.Base58;
import org.junit.Assert;

import java.math.BigInteger;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.Arrays;


public class PrivateKey {


     Curve curve;
    public BigInteger secret;

    public PrivateKey() {
        this(Curve.secp256k1, null);
        secret = RandomInteger.between(BigInteger.ONE, curve.N);
    }

    public PrivateKey(Curve curve, BigInteger secret) {
        this.curve = curve;
        this.secret = secret;
    }

    public PublicKey publicKey() {
        Curve curve = this.curve;
        Point publicPoint = Math.multiply(curve.G, this.secret, curve.N, curve.A, curve.P);
        return new PublicKey(publicPoint, curve);
    }

    public ByteString toByteString() {
        return BinaryAscii.stringFromNumber(this.secret, this.curve.length());
    }

    public ByteString toDer() {
        ByteString encodedPublicKey = this.publicKey().toByteString(true);
        return Der.encodeSequence(
                Der.encodeInteger(BigInteger.valueOf(1)),
                Der.encodeOctetString(this.toByteString()),
                Der.encodeConstructed(0, Der.encodeOid(this.curve.oid)),
                Der.encodeConstructed(1, Der.encodeBitString(encodedPublicKey)));
    }

    public String toPem() {
        return Der.toPem(this.toDer(), "EC PRIVATE KEY");
    }


    public static PrivateKey fromPem(String string) {
        String privkeyPem = string.substring(string.indexOf("-----BEGIN EC PRIVATE KEY-----"));
        return PrivateKey.fromDer(Der.fromPem(privkeyPem));
    }

    public static PrivateKey fromDer(String string) {
        return fromDer(new ByteString(string.getBytes()));
    }

    public static PrivateKey fromDer(ByteString string) {
        ByteString[] str = Der.removeSequence(string);
        ByteString s = str[0];
        ByteString empty = str[1];
        if (!empty.isEmpty()) {
            throw new RuntimeException(String.format("trailing junk after DER privkey: %s", BinaryAscii.hexFromBinary(empty)));
        }

        Object[] o = Der.removeInteger(s);
        long one = Long.valueOf(o[0].toString());
        s = (ByteString) o[1];
        if (one != 1) {
            throw new RuntimeException(String.format("expected '1' at start of DER privkey, got %d", one));
        }

        str = Der.removeOctetString(s);
        ByteString privkeyStr = str[0];
        s = str[1];
        Object[] t = Der.removeConstructed(s);
        long tag = Long.valueOf(t[0].toString());
        ByteString curveOidStr = (ByteString) t[1];
        s = (ByteString) t[2];
        if (tag != 0) {
            throw new RuntimeException(String.format("expected tag 0 in DER privkey, got %d", tag));
        }

        o = Der.removeObject(curveOidStr);
        long[] oidCurve = (long[]) o[0];
        empty = (ByteString) o[1];
        if (!"".equals(empty.toString())) {
            throw new RuntimeException(String.format("trailing junk after DER privkey curve_oid: %s", BinaryAscii.hexFromBinary(empty)));
        }
        Curve curve = (Curve) Curve.curvesByOid.get(Arrays.hashCode(oidCurve));
        if (curve == null) {
            throw new RuntimeException(String.format("Unknown curve with oid %s. I only know about these: %s", Arrays.toString(oidCurve), Arrays.toString(Curve.supportedCurves.toArray())));
        }

        if (privkeyStr.length() < curve.length()) {
            int l = curve.length() - privkeyStr.length();
            byte[] bytes = new byte[l + privkeyStr.length()];
            for (int i = 0; i < curve.length() - privkeyStr.length(); i++) {
                bytes[i] = 0;
            }
            byte[] privateKey = privkeyStr.getBytes();
            System.arraycopy(privateKey, 0, bytes, l, bytes.length - l);
            privkeyStr = new ByteString(bytes);
        }

        return PrivateKey.fromString(privkeyStr, curve);
    }

    public static PrivateKey fromString(ByteString string, Curve curve) {
        return new PrivateKey(curve, BinaryAscii.numberFromString(string.getBytes()));
    }

    public static PrivateKey fromString(String string) {
        return fromString(new ByteString(string.getBytes()));
    }

    public static PrivateKey fromString(ByteString string) {
        return PrivateKey.fromString(string, Curve.secp256k1);
    }

    public static PrivateKey fromBase58(String base58PrivateKey){
        char tip = base58PrivateKey.charAt(0);
        boolean compressed;
        if (tip == 'L' || tip == 'K'){
            compressed = true;
        }
        else if(tip == '5'){
            compressed = false;
        }
        else{
            throw new RuntimeException("error: private must start with 5 if uncompressed or L/K for compressed, but actural:" + base58PrivateKey);
        }
        byte[] encodedPrivKey = Base58.decode(base58PrivateKey);
        String hexPrivKey = BinaryAscii.hexFromBinary(encodedPrivKey);

        checkLength(hexPrivKey, compressed);

        String secretString;
        if (compressed){
            secretString = hexPrivKey.substring(2, hexPrivKey.length() - 8);
        }
        else{
            secretString = hexPrivKey.substring(2,hexPrivKey.length() - 10);
        }

        BigInteger secret = new BigInteger(secretString, 16);
        try {
            checkSum(encodedPrivKey, hexPrivKey);
        } catch (NoSuchAlgorithmException e) {
            e.printStackTrace();
        }

        return new PrivateKey(Curve.secp256k1, secret);
    }

    private static void checkSum(byte[] encodedPrivKey, String hexPrivKey) throws NoSuchAlgorithmException {
        byte[] checkPrivKey = new byte[encodedPrivKey.length - 4];
        System.arraycopy(encodedPrivKey, 0, checkPrivKey, 0, encodedPrivKey.length - 4);
        byte[] afterHash = doubleHash(checkPrivKey, MessageDigest.getInstance("SHA-256"));
        byte[] checkSum = new byte[4];
        System.arraycopy(afterHash, 0, checkSum, 0, 4);
        String hexCheckSum = BinaryAscii.hexFromBinary(checkSum);

        Assert.assertTrue("error: checksum error.", hexCheckSum.equals(hexPrivKey.substring(hexPrivKey.length() - 8)));
    }

    private static void checkLength(String hexPrivKey, boolean compressed) {
        if (compressed){
            Assert.assertTrue("error: length of uncompressed hex private key is not 76",hexPrivKey.length() == 76);
        }else{
            Assert.assertTrue("error: length of uncompressed hex private key is not 74",hexPrivKey.length() == 74);
        }
    }

    private static byte[] doubleHash(byte[] h, MessageDigest hashFunc){
        return hashFunc.digest(hashFunc.digest(h));
    }
}
