//public class V {
//
//}
//import java.security.KeyFactory;
//    import java.security.Security;
//    import javax.crypto.*;
//    import java.security.interfaces.*;
//    import java.security.spec.PKCS8EncodedKeySpec;
//    import java.security.cert.X509Certificate;
//    import java.security.cert.CertificateFactory;
//
//    import com.nimbusds.jose.*;
//    import com.nimbusds.jose.crypto.*;
//    import com.nimbusds.jose.crypto.bc.BouncyCastleProviderSingleton;
//    import com.nimbusds.jose.jwk.RSAKey;
//    import com.nimbusds.jwt.EncryptedJWT;
//
//    String jwsResponse = "eyJhbGciOiJQUzI1NiIsInR5cCI6IkpXVCJ9.ZXlKaGJHY2lPaUpTVTBFdFQwRkZVQ0lzSW1WdVl5STZJa0V5TlRaSFEwMGlmUS5rcXNGWFhQcFJwQWhkMEloUnNWYmN6QU52NV84aEhYN1hrdkxsSTItWGs4S2xyeWwtU1RmMDZUWHZKdWpDazNndG1GMGpYQXNPUGJSNXFTUEZOU0RkclJVeERmN0ZHZldjZmpKWXR1WlFjVC15cndOeHdtQl9XS0ViWVZmTlFDLThFTVZ5bXMza2wxNUZvd3Z4bV96Wl9WVFFMSTZmRDhHRG05OEFRSXprUksybWsydGlORTVPc2EzNlRVT2xQaFhEd3ZQX1p1eWJPd09LUzlNSXE4MXoyTVhGMEVZclJLUnJnTEQtUC02Vm5TWDJOdWNtcEZIUVROeVBtX1BQWTJlVWhaVmM4ZXlLN2lQWmFUaFpIV1c5VS0xSVZIaDlmeHBSMFZBU0RwWWVWU2VEVV9DekZ0MTdqdGY1eE1sa2hGZk1KLWgzRVlHVVlUTGtCVG5kOXdWSEE0NXAtZzAyM1N2RzhoOUxIai04SF9rZ0JvVXFUd0tQTDg4bjNabGVsVHQ2dGtmTEFrZnpDUFY0TnhacVV4SUhlRTFkWTl2YUg5dUx1dU9QTEpYOTFNTVRnYS1ZbkJvcmk1TWJrOVU0bmxkdkZsSzJ5ZlhMdVVVMExPa0hndk14ZkdXclRDWERoNHdmcG1sVWprZHFaakZxQU14ZmxxTHVMckI4VEo2NlhzRlNPck1Yb0J3US1ocjAzTm5OM3Nmb3c1T1Q5WGdQZ1h5WW1vMVoxMV9SR2tWMnVaVzhaZHFtalUzdUloZ2FiVXg1M0doRWNhdTc5UjczR0EyNXA1cDY1Tl9nX1dXZWhXazRmUnVGcTF3QkJTRVlYZGw0R1JENm1QVzVmbzZ5UGJ2MDR4MDRTOHpsRHFZVmpnMUt6M3VvYW1IYjdTeUlCT2E5Wmx6aEV3MUxYWS5IYmhFSm5uTEh0a2NpaEgxLkVJX2EwLXkwa284aDE4Q3RtQjNicTdKOFREV3cyd21xc3hyQXRzUVZzQzFnV1pmRlNxc3hNd1lhQVpmTHJxRm91Z1RHNlBxN3pKbGJwWlk4TU16R2EtanlCQ0JZUWpSamZvSmlDendQc3hLQkEwZ2NwZmx2cnVIQTk0VkpfT3lLQXg4aVhWektSb2l1QzZZN2dLbzRxS1JnZjdXZ2NoVl9ZVFBBeng1WmJkVUloQWM0ZWd3LXppVkZBU2xJQlU0c0hPRU1LQkViazhONkRtS3ZNZW93SV9zOU1fbmZwSElmTHRqaWxpWHR1TXYxSU5SMjdyajQzTnBsWGVWcEl0S000ZmxncTJwRXhUSGVfS2JDejd2eWNiYk5tcTY2ajFhUU5nNUdwaEdxWkx1czZQZ3p2QXdHd3EzQ054cGEwcVFzVV8zNTJ2Mk5zeDVWUWhQUWx0SkNSWk5kSEZ4YUpXLWhZUEFFM0JPMzlVNG45Vzc4bUZSMENkNDZtVVlrNXl5RnpqSk91bTNSWU9MNDJ2T2dSdy5VUnpGMXdkQjVpRFVUQl9hOVVvbjNR.czac5DA6fsAF_cmFgN6S0J5XNM9melgwWfYXNRDru0OaQpMzh9r9sdtt8mO7jjw_z0tJg6tsk3Rv4EnuKUww9i4wJazQ5L3oLx2DHBt-8pQ5RbajaQhqZCLb-czRtp6DiDULxOVJKShBlR3hx8DcyCt16KH3ThG9yC5v0ARjwZu6-cByspvvpyWq1raS5dxldPbbbns5VeMpBXRl3sgzTyiv591GTzfdftzHNZZzBqDeCf3-ZjGtFWBEVixWwO8ryFBq7CwGGOnOih15WQFb6mDVeuYzxLTb0toEOJYmuiB4-lOfRmOg7909uF-F51Rk7xgizZOfLdMnGbKN2HVCdg";
//    JWSObject jwsObject = JWSObject.parse(jwsResponse);
//    FileInputStream is  = new FileInputStream("C:\\cert\\sandbox-jwt-2c2p.demo.2.1(public).cer"); //2c2p public cert key
//
//    JWEAlgorithm alg = JWEAlgorithm.RSA_OAEP;
//    EncryptionMethod enc = EncryptionMethod.A256GCM;
//
//    CertificateFactory certFactory  = CertificateFactory.getInstance("X509");
//    X509Certificate jwePubKey = (X509Certificate) certFactory.generateCertificate(is);
//
//    File file = new File("C:\\cert\\Merchant12345.der");
//    FileInputStream fis = new FileInputStream(file);
//    DataInputStream dis = new DataInputStream(fis);
//
//    byte[] keyBytes = new byte[(int) file.length()];
//    dis.readFully(keyBytes);
//    dis.close();
//
//    PKCS8EncodedKeySpec spec = new PKCS8EncodedKeySpec(keyBytes);
//    KeyFactory kf = KeyFactory.getInstance("RSA");
//    java.security.interfaces.RSAPrivateKey jwsPrivateKey = (java.security.interfaces.RSAPrivateKey) kf
//    .generatePrivate(spec);
//
//    RSAKey rsaJWE = RSAKey.parse(jwePubKey);
//    RSAPublicKey jweRsaPubKey = rsaJWE.toRSAPublicKey();
//
//    boolean verified = jwsObject.verify(new RSASSAVerifier(jweRsaPubKey)); //return true represent valid JWS, else invalid.
//
//    if(verified == true){
//    PKCS8EncodedKeySpec spec = new PKCS8EncodedKeySpec(keyBytes);
//    KeyFactory kf = KeyFactory.getInstance("RSA");
//    java.security.interfaces.RSAPrivateKey jwsPrivateKey = (java.security.interfaces.RSAPrivateKey) kf
//    .generatePrivate(spec);
//
//    JWEObject jwe = EncryptedJWT.parse(jwsObject.getPayload().toString());
//    jwe.decrypt(new RSADecrypter(jwsPrivateKey));
//    String responsePayload = jwe.getPayload().toString();
//    }
//    else{
//    //Invalid Signature
//    }