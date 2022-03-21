import com.auth0.jwt.JWT;
import com.auth0.jwt.algorithms.Algorithm;
import com.auth0.jwt.exceptions.JWTCreationException;
import java.io.BufferedReader;
import java.io.DataOutputStream;
import java.io.InputStreamReader;
import java.net.URL;
import java.util.HashMap;
import javax.net.ssl.HttpsURLConnection;
import org.json.simple.JSONObject;

public class Main {

    public static void main(String[] args) {

        String token="";
        String secretKey = "ECC4E54DBA738857B84A7EBC6B5DC7187B8DA68750E88AB53AAA41F548D6F2D9";

        HashMap<String, Object> payload = new HashMap<>();
        
        payload.put("merchantID","JT01");
        payload.put("invoiceNo","1mihir1523953661");
        payload.put("description","item 1");
        payload.put("amount",1000.00);
        payload.put("cuencyCode","SGD");

        try {
            Algorithm algorithm = Algorithm.HMAC256(secretKey);

            token = JWT.create()
                .withPayload(payload).sign(algorithm);

        } catch (JWTCreationException | IllegalArgumentException e){
            //Invalid Signing configuration / Couldn't convert Claims.
            e.printStackTrace();
        }

        JSONObject requestData = new JSONObject();
        requestData.put("payload", token);

        try
        {
            String endpoint = "https://sandbox-pgw.2c2p.com/payment/4.1/PaymentToken";
            URL obj = new URL(endpoint);
            HttpsURLConnection con = (HttpsURLConnection) obj.openConnection();

            con.setRequestMethod("POST");
            con.setRequestProperty("Content-Type", "application/*+json");
            con.setRequestProperty("Accept", "text/plain");

            con.setDoOutput(true);
            DataOutputStream wr = new DataOutputStream(con.getOutputStream());
            wr.writeBytes(requestData.toString());
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
