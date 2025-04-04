import javax.crypto.Cipher;
import javax.crypto.CipherOutputStream;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.io.*;
import java.lang.reflect.Array;
import java.net.HttpURLConnection;
import java.net.URI;
import java.net.URL;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.*;

/**
 * 获取并解密 ijrsoftware 数据库数据
 *
 * @author Dr (dr@der.kim)
 * @date 2025/4/4 10:38
 */
public class AllDataJson {
    private enum DownLoadType {
        CPU("com.ijsoft.cpul", "https://www.ijrsoftware.com/json/db_cpus.json"),
        GPU("com.ijsoft.gpul", "https://www.ijrsoftware.com/json/db_gpus.json"),
        SOC("com.ijsoft.socl", "https://www.ijrsoftware.com/json/db_socs.json");

        final byte[] passwd;
        final byte[] iv;
        final String url;

        DownLoadType(String passwd, String url) {
            byte[] bytes = md5(passwd).getBytes();
            // HEX TO 16Bytes IV
            byte[] bArr = new byte[16];
            int i7 = 0;
            while (i7 < bytes.length) {
                bArr[i7 / 2] = bytes[31 - i7];
                i7 += 2;
            }
            this.passwd = bytes;
            this.iv = bArr;
            this.url = url;
        }

        private static String md5(String md5) {
            //byte[] bytes = context.getPackageName().getBytes();
            byte[] bytes = md5.getBytes();
            try {
                MessageDigest messageDigest = MessageDigest.getInstance("MD5");
                messageDigest.update(bytes);
                byte[] digest = messageDigest.digest();
                StringBuilder sb = new StringBuilder();
                for (byte b7 : digest) {
                    StringBuilder hexString = new StringBuilder(Integer.toHexString(b7 & 255));
                    while (hexString.length() < 2) {
                        hexString.insert(0, "0");
                    }
                    sb.append(hexString);
                }
                return sb.toString();
            } catch (NoSuchAlgorithmException unused) {
                return "";
            }
        }
    }
    public static void main(String[] args) throws Exception {
        for (DownLoadType data : DownLoadType.values()) {
            creatFile(data);
        }
    }

    private static void creatFile(DownLoadType downLoadType) throws Exception {
        System.out.println(downLoadType + " : Start");
        IvParameterSpec ivParameterSpec = new IvParameterSpec(downLoadType.iv);
        SecretKeySpec secretKeySpec = new SecretKeySpec(downLoadType.passwd, "AES");
        Cipher cipher = Cipher.getInstance("AES/CFB8/NoPadding");
        cipher.init(Cipher.DECRYPT_MODE, secretKeySpec, ivParameterSpec);

        ByteArrayOutputStream out = new ByteArrayOutputStream();

        try (CipherOutputStream cipherOut = new CipherOutputStream(out, cipher)) {
            // 这个 URL 来自 : https://www.ijrsoftware.com/json/db_cpus.json
            String str = new String(doGetRequestForFile(downLoadType.url));
            if (str.isEmpty()) {
                throw new Exception(downLoadType + " is empty");
            }
            @SuppressWarnings("unchecked")
            LinkedHashMap<String, Object> json = (LinkedHashMap<String, Object>) JSONSerializer.deserialize(str);
            System.out.println(downLoadType + " : Data Release " + json.get("release"));
            System.out.println(downLoadType + " : Data version " + json.get("version"));
            System.out.println(downLoadType + " : Data URL " + json.get("url"));
            cipherOut.write(doGetRequestForFile(json.get("url").toString()));
        }

        File file = File.createTempFile(String.valueOf(downLoadType), ".zip");
        try (FileOutputStream outFile = new FileOutputStream(file)) {
            outFile.write(out.toByteArray());
        }

        System.out.println(downLoadType + " : Download OK, Json(ZIP) File: "+ file.getAbsolutePath());
    }

    public static byte[] doGetRequestForFile(String urlStr) {
        InputStream is = null;
        ByteArrayOutputStream os = null;
        byte[] buff = new byte[1024];
        int len;
        try {
            URL url = URI.create(urlStr).toURL();
            HttpURLConnection conn = (HttpURLConnection) url.openConnection();
            conn.setRequestProperty("Content-Type", "plain/text;charset=UTF-8");
            conn.setRequestProperty("charset", "UTF-8");
            conn.setDoInput(true);
            conn.setDoOutput(true);
            conn.setRequestMethod("GET");
            conn.setReadTimeout(5000);
            conn.connect();
            is = conn.getInputStream();
            os = new ByteArrayOutputStream();
            while ((len = is.read(buff)) != -1) {
                os.write(buff, 0, len);
            }
            return os.toByteArray();
        } catch (IOException e) {
            return null;
        } finally {
            if (is != null) {
                try {
                    is.close();
                } catch (IOException ignored) {
                }
            }
            if (os != null) {
                try {
                    os.close();
                } catch (IOException ignored) {
                }
            }
        }
    }

    /**
     * @author Fan Wen Jie
     * @version 2015-03-05
     */
    private static class JSONSerializer {

        /**
         * Serializing a data object combined by values which types are Number Bollean Map Collection Array null to Json
         *
         * @param object object which will be serialized
         * @return Json string made from object
         * @throws IllegalArgumentException the node object of the data object whose type is not one of Number Bollean Map Collection Array null
         */

        public static String serialize(Object object) throws IllegalArgumentException {
            if (object == null)
                return "null";
            if (object instanceof String)
                return '\"' + ((String) object).replace("\b", "\\b")
                        .replace("\t", "\\t").replace("\r", "\\r")
                        .replace("\f", "\\f").replace("\n", "\\n") + '\"';
            if (object instanceof Number || object instanceof Boolean)
                return object.toString();
            if (object instanceof Map) {
                StringBuilder sb = new StringBuilder();
                sb.append('{');
                Map map = (Map) object;
                for (Object key : map.keySet()) {
                    Object value = map.get(key);
                    sb.append(serialize(key)).append(':').append(serialize(value)).append(',');
                }
                int last = sb.length() - 1;
                if (sb.charAt(last) == ',') sb.deleteCharAt(last);
                sb.append('}');
                return sb.toString();
            }
            if (object instanceof Collection) {
                return serialize(((Collection) object).toArray());
            }
            if (object.getClass().isArray()) {
                StringBuilder sb = new StringBuilder();
                sb.append('[');
                int last = Array.getLength(object) - 1;
                for (int i = 0; i <= last; ++i) {
                    Object value = Array.get(object, i);
                    sb.append(serialize(value)).append(',');
                }
                last = sb.length() - 1;
                if (sb.charAt(last) == ',') sb.deleteCharAt(last);
                sb.append(']');
                return sb.toString();
            }
            throw new IllegalArgumentException(object.toString());
        }

        /**
         * Deserializing a json string to data object
         *
         * @param json the json string which will be deserialized
         * @return the data object made from json
         * @throws ParseException thrown when parsing a illegal json text
         */
        public static Object deserialize(String json) throws ParseException {
            return new JSONSerializer(json).nextValue();
        }


        private int position;
        private final char[] buffer;

        private JSONSerializer(String string) {
            this.buffer = string.toCharArray();
            this.position = -1;
        }

        private Object nextValue() throws ParseException {
            try {
                char c = this.nextToken();
                switch (c) {
                    case '{':
                        try {
                            LinkedHashMap<String, Object> map = new LinkedHashMap<>();
                            if (nextToken() != '}') {
                                --position;
                                while (true) {
                                    String key = nextValue().toString();
                                    if (nextToken() != ':') {
                                        throw new ParseException(new String(this.buffer), this.position, "Expected a ':' after a key");
                                    }
                                    map.put(key, nextValue());
                                    switch (nextToken()) {
                                        case ';':
                                        case ',':
                                            if (nextToken() == '}') {
                                                return map;
                                            }
                                            --position;
                                            break;
                                        case '}':
                                            return map;
                                        default:
                                            throw new ParseException(new String(this.buffer), this.position, "Expected a ',' or '}'");
                                    }
                                }
                            } else return map;
                        } catch (ArrayIndexOutOfBoundsException ignore) {
                            throw new ParseException(new String(this.buffer), this.position, "Expected a ',' or '}'");
                        }


                    case '[':
                        try {
                            ArrayList<Object> list = new ArrayList<Object>();
                            if (nextToken() != ']') {
                                --position;
                                while (true) {
                                    if (nextToken() == ',') {
                                        --position;
                                        list.add(null);
                                    } else {
                                        --position;
                                        list.add(nextValue());
                                    }
                                    switch (nextToken()) {
                                        case ',':
                                            if (nextToken() == ']') {
                                                return list;
                                            }
                                            --position;
                                            break;
                                        case ']':
                                            return list;
                                        default:
                                            throw new ParseException(new String(this.buffer), this.position, "Expected a ',' or ']'");
                                    }
                                }
                            } else return list;
                        } catch (ArrayIndexOutOfBoundsException ignore) {
                            throw new ParseException(new String(this.buffer), this.position, "Expected a ',' or ']'");
                        }


                    case '"':
                    case '\'':
                        StringBuilder sb = new StringBuilder();
                        while (true) {
                            char ch = this.buffer[++position];
                            switch (ch) {
                                case '\n':
                                case '\r':
                                    throw new ParseException(new String(this.buffer), this.position, "Unterminated string");
                                case '\\':
                                    ch = this.buffer[++position];
                                    switch (ch) {
                                        case 'b':
                                            sb.append('\b');
                                            break;
                                        case 't':
                                            sb.append('\t');
                                            break;
                                        case 'n':
                                            sb.append('\n');
                                            break;
                                        case 'f':
                                            sb.append('\f');
                                            break;
                                        case 'r':
                                            sb.append('\r');
                                            break;
                                        case 'u':
                                            int num = 0;
                                            for (int i = 3; i >= 0; --i) {
                                                int tmp = buffer[++position];
                                                if (tmp <= '9' && tmp >= '0')
                                                    tmp = tmp - '0';
                                                else if (tmp <= 'F' && tmp >= 'A')
                                                    tmp = tmp - ('A' - 10);
                                                else if (tmp <= 'f' && tmp >= 'a')
                                                    tmp = tmp - ('a' - 10);
                                                else
                                                    throw new ParseException(new String(this.buffer), this.position, "Illegal hex code");
                                                num += tmp << (i * 4);
                                            }
                                            sb.append((char) num);
                                            break;
                                        case '"':
                                        case '\'':
                                        case '\\':
                                        case '/':
                                            sb.append(ch);
                                            break;
                                        default:
                                            throw new ParseException(new String(this.buffer), this.position, "Illegal escape.");
                                    }
                                    break;
                                default:
                                    if (ch == c) {
                                        return sb.toString();
                                    }
                                    sb.append(ch);
                            }
                        }
                }

                int startPosition = this.position;
                while (c >= ' ' && ",:]}/\\\"[{;=#".indexOf(c) < 0)
                    c = this.buffer[++position];
                String substr = new String(buffer, startPosition, position-- - startPosition);
                if (substr.equalsIgnoreCase("true")) {
                    return Boolean.TRUE;
                }
                if (substr.equalsIgnoreCase("false")) {
                    return Boolean.FALSE;
                }
                if (substr.equalsIgnoreCase("null")) {
                    return null;
                }

                char b = "-+".indexOf(substr.charAt(0)) < 0 ? substr.charAt(0) : substr.charAt(1);
                if (b >= '0' && b <= '9') {
                    try {
                        long l = Long.parseLong(substr);
                        if ((int) l == l)
                            return (int) l;
                        return l;
                    } catch (NumberFormatException exInt) {
                        try {
                            return Double.valueOf(substr);
                        } catch (NumberFormatException ignore) {
                        }
                    }
                }
                return substr;
            } catch (ArrayIndexOutOfBoundsException ignore) {
                throw new ParseException(new String(this.buffer), this.position, "Unexpected end");
            }
        }


        private char nextToken() throws ArrayIndexOutOfBoundsException {
            while (this.buffer[++position] <= ' ') ;
            return this.buffer[position];
        }
    }

    /**
     * The JSONException is thrown when deserialize a illegal json.
     *
     * @author Fan Wen Jie
     * @version 2015-03-05
     */
    private static class ParseException extends RuntimeException {
        @Serial
        private static final long serialVersionUID = 3674125742687171239L;
        private final int position;
        private final String json;

        /**
         * Constructs a new json exception with the specified detail message.
         *
         * @param json     the json text which cause JSONParseException
         * @param position the position of illegal escape char at json text;
         * @param message  the detail message. The detail message is saved for
         *                 later retrieval by the {@link #getMessage()} method.
         */
        public ParseException(String json, int position, String message) {
            super(message);
            this.json = json;
            this.position = position;
        }

        /**
         * Get message about error when parsing illegal json
         *
         * @return error message
         */
        @Override
        public String getMessage() {
            final int maxTipLength = 10;
            int end = position + 1;
            int start = end - maxTipLength;
            if (start < 0) start = 0;
            if (end > json.length()) end = json.length();
            return String.format("%s  (%d):%s", json.substring(start, end), position, super.getMessage());
        }

        public String getJson() {
            return this.json;
        }

        public int getPosition() {
            return this.position;
        }

    }
}
