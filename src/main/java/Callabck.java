import com.auth0.jwt.JWT;
import com.auth0.jwt.algorithms.Algorithm;
import com.auth0.jwt.interfaces.Claim;
import com.auth0.jwt.interfaces.DecodedJWT;
import com.auth0.jwt.interfaces.JWTVerifier;
import java.util.Map;

public class Callabck {

    public static void main(String[] args) {

        String secretKey = "33949FCDF8791E4DC33E186BA30C93232870F093CCC2D4CCC4CE215B819B6550";
        Algorithm algorithm = Algorithm.HMAC256(secretKey);

        String responseToken = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJjYXJkTm8iOiI0MTExMTFYWFhYWFgxMTExIiwiY2FyZFRva2VuIjoiIiwibWVyY2hhbnRJRCI6IjcwMjcwMjAwMDAwMTg3NSIsImludm9pY2VObyI6InBheTEiLCJhbW91bnQiOjEwMDAuMCwibW9udGhseVBheW1lbnQiOm51bGwsInVzZXJEZWZpbmVkMSI6IiIsInVzZXJEZWZpbmVkMiI6IiIsInVzZXJEZWZpbmVkMyI6IiIsInVzZXJEZWZpbmVkNCI6IiIsInVzZXJEZWZpbmVkNSI6IiIsImN1cnJlbmN5Q29kZSI6IlNHRCIsInJlY3VycmluZ1VuaXF1ZUlEIjoiIiwidHJhblJlZiI6IjQ3OTAxODUiLCJyZWZlcmVuY2VObyI6IjQ0NDgzNDkiLCJhcHByb3ZhbENvZGUiOiIxMTEwNjIiLCJlY2kiOiIwNSIsInRyYW5zYWN0aW9uRGF0ZVRpbWUiOiIyMDIyMDQwMTEzNTM1OSIsImFnZW50Q29kZSI6IlRCQU5LIiwiY2hhbm5lbENvZGUiOiJWSSIsImlzc3VlckNvdW50cnkiOiJVUyIsImlzc3VlckJhbmsiOiJCQU5LIiwiaW5zdGFsbG1lbnRNZXJjaGFudEFic29yYlJhdGUiOm51bGwsImNhcmRUeXBlIjoiQ1JFRElUIiwiaWRlbXBvdGVuY3lJRCI6IiIsInBheW1lbnRTY2hlbWUiOiJWSSIsInJlc3BDb2RlIjoiMDAwMCIsInJlc3BEZXNjIjoiU3VjY2VzcyJ9.TNYayNL8lxbDdYFVbKfR0YhWul4xF3DOvgu9kIBXYZM";


            JWTVerifier verifier = JWT.require(algorithm).build();
        verifier.verify(responseToken);   //verify signature
        DecodedJWT jwt = JWT.decode(responseToken); //decode encoded payload
        Map<String, Claim> responseData = jwt.getClaims();
        String paymentToken = responseData.get("paymentToken").asString();
    }
}
