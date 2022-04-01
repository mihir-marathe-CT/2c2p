import com.nimbusds.jwt.EncryptedJWT;
import com.nimbusds.jwt.JWTClaimsSet;
import java.io.BufferedReader;
import java.io.DataInputStream;
import java.io.DataOutputStream;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileReader;
import java.io.IOException;
import java.io.InputStreamReader;
import java.net.URL;
import java.nio.charset.Charset;
import java.nio.file.Files;
import java.security.NoSuchAlgorithmException;
import java.security.cert.CertificateException;
import java.security.spec.InvalidKeySpecException;

import java.text.ParseException;
import java.util.Date;
import java.util.UUID;
import javax.net.ssl.HttpsURLConnection;
import java.security.KeyFactory;
import java.security.Security;
import javax.crypto.*;
import java.security.interfaces.*;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.cert.X509Certificate;
import java.security.cert.CertificateFactory;

import com.nimbusds.jose.*;
import com.nimbusds.jose.crypto.*;
import com.nimbusds.jose.crypto.bc.BouncyCastleProviderSingleton;
import com.nimbusds.jose.jwk.RSAKey;
import org.bouncycastle.util.encoders.Base64;
import org.bouncycastle.util.io.pem.PemObject;
import org.bouncycastle.util.io.pem.PemReader;
import org.json.simple.JSONObject;

public class Capture {

    public static void main(String[] args)
        throws IOException, CertificateException, JOSEException, NoSuchAlgorithmException, InvalidKeySpecException, ParseException {

        Security.addProvider(BouncyCastleProviderSingleton.getInstance());
        Security.setProperty("crypto.policy", "unlimited");

        String paymentRequest = "<PaymentProcessRequest><version>3.8</version><merchantID>702702000001875</merchantID>"
            + "<processType>S</processType><invoiceNo>pay1</invoiceNo></PaymentProcessRequest>";

        FileInputStream is  = new FileInputStream("/Users/mihirvmarathe/IdeaProjects/2c2p/demo2/demo2.crt"); ////2c2p public cert key

        JWEAlgorithm alg = JWEAlgorithm.RSA_OAEP;
        EncryptionMethod enc = EncryptionMethod.A256GCM;

        CertificateFactory certFactory  = CertificateFactory.getInstance("X509");
        X509Certificate jwePubKey = (X509Certificate) certFactory.generateCertificate(is);

        RSAKey rsaJWE = RSAKey.parse(jwePubKey);
        RSAPublicKey jweRsaPubKey = rsaJWE.toRSAPublicKey();

        File file = new File("/Users/mihirvmarathe/IdeaProjects/2c2p/self/decrypted_private.key");
//        FileInputStream fis = new FileInputStream(file);
//        DataInputStream dis = new DataInputStream(fis);
//
//        byte[] keyBytes = new byte[(int) file.length()];
//        dis.readFully(keyBytes);
//        dis.close();


        String key = Files.readString(file.toPath(), Charset.defaultCharset());

        String privateKeyPEM = key
           .replace("-----BEGIN RSA PRIVATE KEY-----", "")
            .replaceAll(System.lineSeparator(), "")
           .replace("-----END RSA PRIVATE KEY-----", "");

        byte[] encoded =  Base64.decode(privateKeyPEM);
            //Base64.decodeBase64(privateKeyPEM);


        PKCS8EncodedKeySpec spec = new PKCS8EncodedKeySpec(encoded);
        KeyFactory kf = KeyFactory.getInstance("RSA");
        RSAPrivateKey jwsPrivateKey = (RSAPrivateKey) kf
            .generatePrivate(spec);


//        RSAPrivateKey privateKey = null;
//        KeyFactory factory = KeyFactory.getInstance("RSA");
//
//        try (FileReader keyReader = new FileReader(file);
//            PemReader pemReader = new PemReader(keyReader)) {
//
//            PemObject pemObject = pemReader.readPemObject();
//            byte[] content = pemObject.getContent();
//            PKCS8EncodedKeySpec privKeySpec = new PKCS8EncodedKeySpec(content);
//            privateKey = (RSAPrivateKey) factory.generatePrivate(privKeySpec);
//        }

            KeyGenerator keyGenerator = KeyGenerator.getInstance("AES");
        keyGenerator.init(enc.cekBitLength());
        SecretKey cek = keyGenerator.generateKey();

        JWEObject jwe = new JWEObject(new JWEHeader(alg, enc), new Payload(paymentRequest));
        jwe.encrypt(new RSAEncrypter(jweRsaPubKey, cek));
        String jwePayload = jwe.serialize();


        RSASSASigner signer = new RSASSASigner(jwsPrivateKey);
        JWSHeader headerc = new JWSHeader(JWSAlgorithm.PS256);
        JWSObject jwsObject = new JWSObject(headerc, new Payload(jwePayload));
        jwsObject.sign(signer);
        String jwsPayload = jwsObject.serialize();

        JSONObject requestData = new JSONObject();
        requestData.put("payload", jwsPayload);

        try
        {
            String endpoint = "https://demo2.2c2p.com/2C2PFrontend/PaymentAction/2.0/action";
            URL obj = new URL(endpoint);
            HttpsURLConnection con = (HttpsURLConnection) obj.openConnection();

            con.setRequestMethod("POST");
            con.setRequestProperty("Content-Type", "application/*+json");
            con.setRequestProperty("Accept", "text/plain");

            con.setDoOutput(true);
            DataOutputStream wr = new DataOutputStream(con.getOutputStream());
            wr.writeBytes(requestData.toJSONString());
            wr.flush();
            wr.close();
            System.out.println(requestData.toJSONString());

            BufferedReader in = new BufferedReader(new InputStreamReader(con.getInputStream()));
            String inputLine;
            StringBuffer response = new StringBuffer();

            while ((inputLine = in.readLine()) != null) {
                response.append(inputLine);
            }
            in.close();
        }catch(Exception e){
            e.printStackTrace();
        }
    }
}
