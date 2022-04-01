import com.nimbusds.jwt.EncryptedJWT;
import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;
import java.nio.charset.Charset;
import java.nio.file.Files;
import java.security.NoSuchAlgorithmException;
import java.security.cert.CertificateException;
import java.security.spec.InvalidKeySpecException;

import java.text.ParseException;
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

public class AllWithCAPkeys {

    public static void main(String[] args)
        throws IOException, CertificateException, JOSEException, NoSuchAlgorithmException, InvalidKeySpecException, ParseException {

        Security.addProvider(BouncyCastleProviderSingleton.getInstance());
        //Security.setProperty("crypto.policy", "unlimited");

        String paymentRequest = "<PaymentProcessRequest><version>3.8</version><merchantID>702702000001875</merchantID>"
            + "<processType>S</processType><invoiceNo>7mmihir1523953</invoiceNo></PaymentProcessRequest>";

        FileInputStream is  = new FileInputStream("/Users/mihirvmarathe/IdeaProjects/2c2p/self/domain.crt"); ////2c2p public cert key

        JWEAlgorithm alg = JWEAlgorithm.RSA_OAEP;
        EncryptionMethod enc = EncryptionMethod.A256GCM;

        CertificateFactory certFactory  = CertificateFactory.getInstance("X509");
        X509Certificate jwePubKey = (X509Certificate) certFactory.generateCertificate(is);

        RSAKey rsaJWE = RSAKey.parse(jwePubKey);
        RSAPublicKey jweRsaPubKey = rsaJWE.toRSAPublicKey();

        File file = new File("/Users/mihirvmarathe/IdeaProjects/2c2p/self/decrypted_private.key");
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

        JWSObject jwsObjectD = JWSObject.parse(jwsPayload);

        boolean verified = jwsObject.verify(new RSASSAVerifier(jweRsaPubKey));

        if(verified == true){

            JWEObject jweD = EncryptedJWT.parse(jwsObject.getPayload().toString());
            jweD.decrypt(new RSADecrypter(jwsPrivateKey));
            String responsePayload = jwe.getPayload().toString();
        }
    }
}