package com.picocel.secure_notepad.util;

import org.json.JSONException;
import org.json.JSONObject;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;

import javax.crypto.Cipher;
import javax.crypto.spec.SecretKeySpec;

public class NoteContent {
    String title;
    String content;
    String cipherContent;
    String password= "";
    boolean isLocked = false;
    public boolean isLockMode = false;

    public NoteContent(String newTitle,String newContent){
        title = newTitle;
        content = newContent;
    }

    public NoteContent(String newContent){
        String[] lines = newContent.split("\\r?\\n");
        title = lines[0];
        content = newContent;
    }

    public NoteContent(NoteContent org){
        title = org.title;
        content = org.content;
        cipherContent = org.cipherContent;
        password = org.password;
        isLockMode = org.isLockMode;
        isLocked = org.isLocked;
    }

    public String toString(){
        if(isLocked) {
            return "[locked]";
        }else {
            return content;
        }
    }

    public String getPassword(){
        return password;
    }

    public int length(){
        return content.length();
    }

    public void setTitle(String newTitle){
        title = newTitle;
    }

    public boolean isEmpty(){
        if(title.equals("") && content.equals("")){
            return true;
        }else{
            return false;
        }
    }

    public void setContent(String newContent){
        if(title.equals("")){
            String[] lines = newContent.split("\\r?\\n");
            title = lines[0];
        }
        content = newContent;
    }

    public byte[] toBytes(){
        String rdata;
        if(!isLockMode){
            rdata = content;
        }else if(!isLocked){
            rdata = cipherContent;
        }else{
            setLock();
            rdata = cipherContent;
        }
        return rdata.getBytes(StandardCharsets.UTF_8);
    }

    public String makeJson(){
        JSONObject json = new JSONObject();
        try {
            json.put("title", title);
            if (isLockMode) {
                String cipher;
                boolean success = false;
                JSONObject contPack = new JSONObject();
                contPack.put("result","success");
                contPack.put("content",content);
                String contPackString = contPack.toString();
                try{
                    cipher = encrypt(contPackString);
                    success = true;
                }catch(Exception e){
                    cipher = content;
                }
                if(success){
                    json.put("lockmode", "locked");
                }else{
                    json.put("lockmode", "plain");
                }
                json.put("content",cipher);
            } else {
                json.put("lockmode", "plain");
                json.put("content",content);
            }

        }catch(JSONException e){
            return "JSON Exception";
        }
        return json.toString();
    }

    public boolean parseJson(String jsonStr){
        ;
        try {
            JSONObject json = new JSONObject(jsonStr);
            String newTitle = json.getString("title");
            String newContent = json.getString("content");
            String lockMode = json.getString("lockmode");
            if(lockMode.equals("locked")){
                title = newTitle;
                content = "";
                cipherContent = newContent;
                isLocked = true;
                isLockMode = true;
            }else{
                title = newTitle;
                content = newContent;
                cipherContent = "";
                isLocked = false;
                isLockMode = false;
            }
        }catch(JSONException e){
            return false;
        }
        return true;
    }

    public boolean createLock(String newPassword){
        if(isLockMode){
            return false;
        }
        isLockMode = true;
        isLocked = false;
        password = newPassword;
        return true;
    }

    public boolean setLock(){
        if(isLockMode) {
            try{
                cipherContent = encrypt(content);
            }catch(Exception e){
                return false;
            }
            isLocked = true;
            return true;
        }else{
            return false;
        }
    }

    public boolean setUnLock(String newPassword){
        if(!isLockMode){
            return false;
        }else if(!isLocked){
            return false;
        }else{
            String rev;
            try{
                rev = decrypt(cipherContent,newPassword);
            }catch(Exception e){
                return false;
            }
            JSONObject json;
            try{
                json = new JSONObject(rev);
                String result = json.getString("result");
                String newContent = json.getString("conent");
                if(result.equals("success")){
                    content = newContent;
                    password = newPassword;
                    isLocked = false;
                }else{
                    return false;
                }
            }catch(JSONException e){
                return false;
            }
        }
        return true;
    }

    public boolean clearLock(String newPassword){
        if(!isLockMode){
            return false;
        }else if(!isLocked){
            if(newPassword.equals(password)){
                isLockMode = false;
                return true;
            }
            return false;
        }else{
            if(setUnLock(newPassword)){
                isLockMode = false;
                cipherContent = "";
                return true;
            }
            return false;
        }
    }

    private final static char[] hexArray = "0123456789ABCDEF".toCharArray();
    public static String bytesToHex(byte[] bytes) {
        char[] hexChars = new char[bytes.length * 2];
        for ( int j = 0; j < bytes.length; j++ ) {
            int v = bytes[j] & 0xFF;
            hexChars[j * 2] = hexArray[v >>> 4];
            hexChars[j * 2 + 1] = hexArray[v & 0x0F];
        }
        return new String(hexChars);
    }
    public static byte[] hexToBytes(String str){
        int len = str.length();
        byte[] data = new byte[len / 2];
        for (int i = 0; i < len; i += 2) {
            data[i / 2] = (byte) ((Character.digit(str.charAt(i), 16) << 4)
                    + Character.digit(str.charAt(i+1), 16));
        }
        return data;
    }
    private String encrypt(String inStr) throws Exception {
        return encrypt(inStr,password);
    }

    private String encrypt(String inStr, String pass) throws Exception{
        MessageDigest md = MessageDigest.getInstance("MD5");
        byte[] theDigest = md.digest(pass.getBytes(StandardCharsets.UTF_8));
        SecretKeySpec skc = new SecretKeySpec(theDigest,"AES");

        byte[] input = inStr.getBytes(StandardCharsets.UTF_8);
        Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
        cipher.init(Cipher.ENCRYPT_MODE,skc);

        byte[] cipherText = new byte[cipher.getOutputSize(input.length)];
        int ctLength = cipher.update(input,0,input.length,cipherText,0);
        ctLength += cipher.doFinal(cipherText,ctLength);

        return bytesToHex(cipherText);
    }

    public class PasswordFailure extends Exception {
        public PasswordFailure(String errorMessage) {
            super(errorMessage);
        }
    }

    private String decrypt(String inStr) throws Exception{
        return decrypt(inStr,password);
    }
    private String decrypt(String inStr,String pass) throws Exception{
        MessageDigest md = MessageDigest.getInstance("MD5");
        byte[] theDigest = md.digest(pass.getBytes(StandardCharsets.UTF_8));
        SecretKeySpec skc = new SecretKeySpec(theDigest,"AES");

        Cipher dcipher = Cipher.getInstance("AES");
        dcipher.init(Cipher.DECRYPT_MODE,skc);
        byte[] clearByte = dcipher.doFinal(hexToBytes(inStr));

        return new String(clearByte,StandardCharsets.UTF_8);
    }

}
