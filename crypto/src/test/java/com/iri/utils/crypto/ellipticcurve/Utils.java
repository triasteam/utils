package com.iri.utils.crypto.ellipticcurve;
import com.iri.utils.crypto.ellipticcurve.utils.ByteString;

import java.io.FileNotFoundException;
import java.io.IOException;
import java.io.RandomAccessFile;
import java.io.UnsupportedEncodingException;
import java.net.URISyntaxException;


class Utils {

    static String readFileAsString(String path) throws URISyntaxException, IOException {
        return new String(readFileAsBytes(path), "ASCII");
    }

    static byte[] readFileAsBytes(String path) throws URISyntaxException {
        return read(ClassLoader.getSystemClassLoader().getResource(path).toURI().getPath());
    }

    private static byte[] read(String path) {
        try {
            RandomAccessFile f = new RandomAccessFile(path, "r");
            if (f.length() > Integer.MAX_VALUE)
                throw new RuntimeException("File is too large");
            byte[] b = new byte[(int) f.length()];
            f.readFully(b);
            if (f.getFilePointer() != f.length())
                throw new RuntimeException("File length changed while reading");
            return b;
        } catch (IOException e) {
            throw new RuntimeException("Could not read file");
        }
    }

    public static void writeFileAsByteString(ByteString content, String path){
        try {
            write(content.getBytes(), ClassLoader.getSystemClassLoader().getResource(path).toURI().getPath());
        } catch (URISyntaxException e) {
            e.printStackTrace();
        }
    }

    private static void write(byte[] bytes, String path){
        RandomAccessFile f = null;
        try {
            System.out.println(path);
            f = new RandomAccessFile(path, "r");
            f.write(bytes);
        } catch (FileNotFoundException e) {
            e.printStackTrace();
        } catch (IOException e) {
            e.printStackTrace();
        }
    }
}
