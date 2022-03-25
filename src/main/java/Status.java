import java.io.BufferedReader;
import java.io.DataInputStream;
import java.io.DataOutputStream;
import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;
import java.io.InputStreamReader;
import java.net.URL;
import java.nio.charset.Charset;
import java.nio.file.Files;
import java.security.NoSuchAlgorithmException;
import java.security.cert.CertificateException;
import java.security.spec.InvalidKeySpecException;
import java.util.Base64;
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

public class Status {

    public static void main(String[] args)
        throws IOException, CertificateException, JOSEException, NoSuchAlgorithmException, InvalidKeySpecException {

        String paymentRequest = "<PaymentProcessRequest><version>3.8</version><timeStamp>151020142801</timeStamp><merchantID>JT01</merchantID><invoiceNo>1mihir1523953661</invoiceNo><processType>I</processType></PaymentProcessRequest>";

        FileInputStream is  = new FileInputStream("/Users/mihirvmarathe/IdeaProjects/2c2p/demo2/demo2.crt"); ////2c2p public cert key

        JWEAlgorithm alg = JWEAlgorithm.RSA_OAEP;
        EncryptionMethod enc = EncryptionMethod.A256GCM;

        CertificateFactory certFactory  = CertificateFactory.getInstance("X509");
        X509Certificate jwePubKey = (X509Certificate) certFactory.generateCertificate(is);

        RSAKey rsaJWE = RSAKey.parse(jwePubKey);
        RSAPublicKey jweRsaPubKey = rsaJWE.toRSAPublicKey();


        File file = new File("/Users/mihirvmarathe/IdeaProjects/2c2p/demo2/demo2.pem");
        String key = Files.readString(file.toPath(), Charset.defaultCharset());

        byte[] encoded = Base64.getDecoder().decode(key);


        PKCS8EncodedKeySpec spec = new PKCS8EncodedKeySpec(encoded);
        KeyFactory kf = KeyFactory.getInstance("RSA");
        RSAPrivateKey jwsPrivateKey = (RSAPrivateKey) kf
            .generatePrivate(spec);


        KeyGenerator keyGenerator = KeyGenerator.getInstance("AES");
        keyGenerator.init(enc.cekBitLength());
        SecretKey cek = keyGenerator.generateKey();

        JWEObject jwe = new JWEObject(new JWEHeader(alg, enc), new Payload(paymentRequest));
        jwe.encrypt(new RSAEncrypter(jweRsaPubKey, cek));
        String jwePayload = jwe.serialize();

        Security.addProvider(BouncyCastleProviderSingleton.getInstance());
        RSASSASigner signer = new RSASSASigner(jwsPrivateKey);
        JWSHeader header = new JWSHeader(JWSAlgorithm.PS256);
        JWSObject jwsObject = new JWSObject(header, new Payload(jwePayload));
        jwsObject.sign(signer);
        String jwsPayload = jwsObject.serialize();

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
            wr.writeBytes(jwsPayload);
            wr.flush();
            wr.close();


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
