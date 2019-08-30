package com.iri.utils.crypto.ellipticcurve;

import com.iri.utils.crypto.ellipticcurve.utils.Base64;
import com.iri.utils.crypto.ellipticcurve.utils.BinaryAscii;
import com.iri.utils.crypto.ellipticcurve.utils.ByteString;
import com.iri.utils.crypto.ellipticcurve.utils.Ripemd160;
import io.ipfs.multibase.Base58;
import org.apache.log4j.Logger;
import org.json.JSONException;
import org.json.JSONObject;

import java.io.IOException;
import java.io.StringWriter;
import java.io.Writer;
import java.math.BigInteger;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
import java.util.Map;

/**
 * utils for crypto
 * <pre>
 *     <li>method <code>generateSecureInfo</code>: generate security key including private key and address</li>
 *     <li>method <code>sign</code>: sign message using private key string encoded by base58</li>
 *     <li>method <code>verifyMessage</code>: verify message</li>
 * </pre>
 */
public class EcdsaUtils {
    private static final Logger logger = Logger.getLogger(EcdsaUtils.class);

    /**
     * generate private key and address.
     * @return
     */
    public static SecureInfo generateSecureInfo(){
        PrivateKey privateKey = new PrivateKey();
        try {
            String base58 = convert2Base58(privateKey, MessageDigest.getInstance("SHA-256"));
            String address = generateAddress(PrivateKey.fromBase58(base58));
            return new SecureInfo(base58, address);
        } catch (NoSuchAlgorithmException e) {
            throw new RuntimeException("generate private key and address error. ", e);
        }
    }

    private static String convert2Base58(PrivateKey privateKey, MessageDigest func) {
        String hex = BinaryAscii.hexFromBinary(privateKey.toByteString());

        String with80 = "80" + hex;

        byte[] bs2 = BinaryAscii.binaryFromHex(with80);

        byte[] hash256 = func.digest(bs2);

        byte[] hash256twice = func.digest(hash256);

        byte[] first4byte = new byte[4];

        System.arraycopy(hash256twice, 0, first4byte, 0, 4);

        String hexFirst4Byte = BinaryAscii.hexFromBinary(first4byte);

        with80 = with80 + hexFirst4Byte;

        byte[] bs3 = BinaryAscii.binaryFromHex(with80);

        return Base58.encode(bs3);
    }

    public static String generateAddress(PrivateKey privateKey) throws NoSuchAlgorithmException {
        return EcdsaUtils.generateAddress(privateKey.publicKey(), true);
    }

    /**
     * sign message
     * @param message
     * @param base58PrivateKey
     * @param address
     * @return
     */
    public static String sign(String message, String base58PrivateKey, String address){
        PrivateKey privateKey = PrivateKey.fromBase58(base58PrivateKey);
        Signature signature = Ecdsa.sign(EcdsaUtils.wrap(message), privateKey);
        int nv;
        for(int i=0; i<4; i++){
            nv = 27 + i + 4;
            String sig = org.apache.xerces.impl.dv.util.Base64.encode(concatByteArray(BigInteger.valueOf(nv).toByteArray(), BinaryAscii.stringFromNumber(signature.r, signature.r.bitLength()).getBytes(), BinaryAscii.stringFromNumber(signature.s, signature.s.bitLength()).getBytes()));
            try {
                if (EcdsaUtils.verifyMessage(sig,message, address).verifyResult()){
                    return sig;
                }
            } catch (NoSuchAlgorithmException e) {
                e.printStackTrace();
            } catch (IOException e) {
                e.printStackTrace();
            }
        }
        throw new RuntimeException("error: can not sig message.");
    }

    private static byte[] concatByteArray(byte[] array1, byte[] ... array2){
        int size = 0;
        for (byte[] a : array2){
            size += a.length;
        }
        byte[] dest = new byte[array1.length + size];
        System.arraycopy(array1, 0, dest, 0, array1.length);
        int index = array1.length;
        for(byte[] array22 : array2) {
            System.arraycopy(array22, 0, dest, index, array22.length);
            index += array22.length;
        }
        return dest;
    }

    /**
     *  1. validate signature
     *  2. validate address
     *
     * @param signature signature string encoded by base64
     * @param message ori message, for example "hello world"
     * @param address just as btcoin address
     * @return ValidRes includes verify result (true/false) and verify message
     * @throws NoSuchAlgorithmException
     */
    public static ValidRes verifyMessage(String signature, String message, String address) throws NoSuchAlgorithmException, IOException {
        byte[] sig = Base64.decode(signature);
        if (sig.length != 65){
            throw new RuntimeException("Wrong encoding");
        }

        int nV = sig[0];
        boolean isCompressed;
        if (nV < 27 || nV >= 35){
            throw new RuntimeException("sig failed");
        }
        if (nV >= 31){
            isCompressed = true;
            nV -= 4;
        }else{
            isCompressed = false;
        }

        Curve curve = Curve.secp256k1;
        int len = curve.length();
        byte[] r = new byte[len];
        System.arraycopy(sig, 1, r, 0, len);
        byte[] s = new byte[sig.length - 1 - len];
        System.arraycopy(sig, sig.length - len, s, 0, sig.length - 1 - len);

        PublicKey publicKey = recoverFrom(wrap(message), r, s, nV, curve);
        Signature signature1 = new Signature(BinaryAscii.numberFromString(r), BinaryAscii.numberFromString(s));

        if (!Ecdsa.verify(wrap(message), signature1, publicKey, MessageDigest.getInstance("SHA-256"))){
            String error = String.format("verify signature failed, expect:%s, actural :%s", signature, signature1.toBase64());
            return new ValidRes(false, error);
        }

        String generateAddress = generateAddress(publicKey, isCompressed);
        if (!generateAddress.equals(address)){
            String error = String.format("valid address failed, expect:%s, actural :%s", address, generateAddress);
            return new ValidRes(false, error);
        }
        return new ValidRes(true, "success");
    }

    /* internal method  */
    private static String wrap(String message){
        String msg = (char)0x18 + "Bitcoin Signed Message:" + (char)'\n' + (char)message.length() + message;
        return msg;
    }

    private static PublicKey recoverFrom(String message, byte[] rByte, byte[] sByte, int nV, Curve curve) throws NoSuchAlgorithmException {
        int recId = nV - 27;
        BigInteger x = BinaryAscii.numberFromString(rByte).add(BigInteger.valueOf(recId).divide(BigInteger.valueOf(2)).multiply(curve.N));
        BigInteger alpha = (x.multiply(x).multiply(x).add(curve.A.multiply(x)).add(curve.B)).mod(curve.P);
        BigInteger beta = modularSqrt(alpha, curve.P);
        BigInteger y = beta.subtract(BigInteger.valueOf(recId)).mod(BigInteger.valueOf(2)).intValue() == 0 ? beta : curve.P.subtract(beta);
        BigInteger s = new BigInteger(BinaryAscii.hexFromBinary(sByte), 16);
        Point rR = new Point(x, y, curve.B);
        MessageDigest hashFunc = MessageDigest.getInstance("SHA-256");
        byte[] h = hashFunc.digest(hashFunc.digest(message.getBytes()));
        BigInteger e = new BigInteger(BinaryAscii.hexFromBinary(h), 16);
        BigInteger minuxE = e.multiply(BigInteger.valueOf(-1)).mod(curve.N);
        BigInteger invR = Math.inv(new BigInteger(BinaryAscii.hexFromBinary(rByte), 16), curve.N);

        Point qQ1 = Math.multiply(rR, s, curve.N, curve.A, curve.P);
        Point qQ2 = Math.multiply(curve.G, minuxE, curve.N, curve.A, curve.P);
        Point qQ = Math.multiply(Math.add(qQ1, qQ2, curve.A, curve.P),invR, curve.N, curve.A, curve.P);
        ByteString xStr = BinaryAscii.stringFromNumber(qQ.x, qQ.x.bitLength());
        ByteString yStr = BinaryAscii.stringFromNumber(qQ.y, qQ.y.bitLength());
        byte[] point = new byte[xStr.length() + yStr.length()];
        System.arraycopy(xStr.getBytes(), 0, point, 0, xStr.length());
        System.arraycopy(yStr.getBytes(), 0, point, xStr.length(), yStr.length());

        PublicKey publicKey = PublicKey.fromString(new ByteString(point), curve);
        return publicKey;
    }

    /* replaced with generateSecureInfo for public */
    private static String generateAddress(PublicKey publicKey, Boolean isCompressed) throws NoSuchAlgorithmException {
        Point point = publicKey.point;
        ByteString xStr = BinaryAscii.stringFromNumber(point.x, Curve.secp256k1.length());
        ByteString yStr = BinaryAscii.stringFromNumber(point.y, Curve.secp256k1.length());
        String encodePoint;
        if(isCompressed){
            ByteString hex = BinaryAscii.stringFromNumber(point.y,point.y.bitLength());
            Integer prefix = 2 + (hex.getBytes()[hex.length() - 1] & 0x01);
            encodePoint = BinaryAscii.hexFromBinary(new byte[]{prefix.byteValue()}) + BinaryAscii.hexFromBinary(xStr);
        }else{
            encodePoint = BinaryAscii.hexFromBinary(new byte[]{4}) + BinaryAscii.hexFromBinary(xStr)+ BinaryAscii.hexFromBinary(yStr);
        }
        MessageDigest hashFunc = MessageDigest.getInstance("SHA-256");
        byte[] firstHash256 = hashFunc.digest(BinaryAscii.binaryFromHex(encodePoint));
        byte[] secHashMd160 = Ripemd160.getHash(firstHash256);
        byte[] vh160 = new byte[secHashMd160.length+1];
        System.arraycopy(secHashMd160, 0, vh160, 1, secHashMd160.length);
        byte[] hh = hashFunc.digest(hashFunc.digest(vh160));
        byte[] addr = new byte[vh160.length + 4];
        System.arraycopy(vh160, 0, addr, 0, vh160.length);
        System.arraycopy(hh, 0, addr, vh160.length, 4);
        return Base58.encode(addr);
    }

    /* not for public */
    private static BigInteger modularSqrt(BigInteger a, BigInteger p){
        if (legendreSymbol(a,p).intValue() != 1){
            return BigInteger.valueOf(0);
        }
        else if(a.intValue() == 0){
            return BigInteger.valueOf(0);
        }
        else if(p.intValue() == 2){
            return p;
        }
        else if(p.mod(BigInteger.valueOf(4)).intValue() == 3){
            return a.modPow(p.add(BigInteger.valueOf(1)).divide(BigInteger.valueOf(4)), p);
        }

        BigInteger s = p.subtract(BigInteger.valueOf(1));
        BigInteger e = BigInteger.ZERO;
        while (s.mod(BigInteger.valueOf(2)).intValue() == 2){
            s = s.divide(BigInteger.valueOf(2));
            e = e.add(BigInteger.ONE);
        }

        BigInteger n = BigInteger.valueOf(2);
        while(legendreSymbol(n,p).intValue() != -1){
            n = n.add(BigInteger.ONE);
        }

        BigInteger x = a.modPow(s.add(BigInteger.ONE).divide(BigInteger.valueOf(2)), p);
        BigInteger b = a.modPow(s, p);
        BigInteger g = n.modPow(s, p);
        BigInteger r = e;

        while (true){
            BigInteger t = b;
            BigInteger m = BigInteger.ZERO;
            for (; m.compareTo(r) < 0 ; m = m.add(BigInteger.ONE)){
                if (t.intValue() == 1){
                    break;
                }
                t = t.modPow(BigInteger.valueOf(2), p);
            }

            if (m.intValue() == 0){
                return x;
            }

            BigInteger gs = g.modPow(BigInteger.valueOf(2).pow(r.subtract(m).subtract(BigInteger.ONE).intValue()), p);
            g = gs.modPow(gs, p);
            x = x.modPow(gs, p);
            b = b.modPow(g, p);
            r = m;
        }
    }

    /* not for public */
    private static BigInteger legendreSymbol(BigInteger a, BigInteger p){
        BigInteger ls = a.modPow(p.subtract(BigInteger.valueOf(1)).divide(BigInteger.valueOf(2)), p);
        return ls.equals(p) ? p.subtract(BigInteger.valueOf(1)) : ls;
    }

    public static class ValidRes{
        Boolean aBoolean;
        String message;
        public ValidRes(Boolean aBoolean, String message){
            this.aBoolean = aBoolean;
            this.message = message;
        }

        public Boolean verifyResult(){
            return aBoolean;
        }

        public String errMessage(){
            return message;
        }

        @Override
        public String toString(){
            return aBoolean + ":" + message;
        }
    }

    /**
     *  format simple java bean
     *  <b>please do not use this method for complicate object</b>
     * @param json
     * @return
     */
    public static String getSortedStringFrom(JSONObject json){
        StringWriter w = new StringWriter();
        synchronized (w.getBuffer()){
            write(w, json);
        }
        return w.toString();
    }

    static Writer write(Writer writer, JSONObject json)
            throws JSONException {
        try {
            boolean commanate = false;
            final int length = json.length();
            writer.write('{');

            if (length == 1) {
                final Map.Entry<String,?> entry = json.toMap().entrySet().iterator().next();
                writeValue(writer, entry.getKey(), entry.getValue());
            } else if (length != 0) {
                //按字符排序
                List<String> keys = new ArrayList(json.toMap().keySet());
                Collections.sort(keys);
                for (final String key : keys) {
                    if (commanate) {
                        writer.write(',');
                    }
                    writeValue(writer, key, json.get(key));
                    commanate = true;
                }
            }
            writer.write('}');
            return writer;
        } catch (IOException exception) {
            throw new JSONException(exception);
        }
    }

    static void writeValue(Writer writer, String key, Object value) throws IOException {
        writer.write(JSONObject.quote(key));
        writer.write(':');
        if (value == null || value.equals(null)){
            writer.write("null");
        }
        else if(value instanceof Number){
            writer.write(JSONObject.numberToString((Number) value));
        }
        else if(value instanceof String){
            JSONObject.quote(value.toString(), writer);
        }
        else{
            throw new RuntimeException("unknown transaction field type:" + value.getClass());
        }
    }

    public static class SecureInfo{
        private String privateKey;
        private String address;

        public SecureInfo(String privateKey, String address){
            this.privateKey = privateKey;
            this.address = address;
        }

        public String getPrivateKey() {
            return privateKey;
        }

        public String getAddress() {
            return address;
        }

        /**
         * only return address.
         * @return
         */
        public String toString(){
            return "privateKey: ****, address: "+address;
        }
    }
}
