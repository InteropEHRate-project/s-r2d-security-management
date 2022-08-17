package eu.interopehrate.sr2dsm;

import java.io.IOException;
import java.security.KeyFactory;
import java.security.NoSuchAlgorithmException;
import java.security.PublicKey;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.X509EncodedKeySpec;

import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jwts;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import sun.misc.BASE64Decoder;

class JwtUtil {
    private static final Logger logger = LoggerFactory.getLogger(JwtUtil.class);

    protected static Claims decode(String jwt, String key) throws InvalidKeySpecException {
        PublicKey publicKey = null;
        try {
            //Remove extra Strings
            key = key.replaceAll("\r", "");
            key = key.replace("-----BEGIN PUBLIC KEY-----\n","");
            key = key.replace("-----END PUBLIC KEY-----", "");

            //Decode the public key and convert it to bytes
            BASE64Decoder base64Decoder = new BASE64Decoder();
            byte[] publicKeyBytes = base64Decoder.decodeBuffer(key);

            // create a key object from the bytes
            X509EncodedKeySpec keySpec = new X509EncodedKeySpec(publicKeyBytes);
            KeyFactory keyFactory = KeyFactory.getInstance("RSA");
            publicKey = keyFactory.generatePublic(keySpec);
        } catch (NoSuchAlgorithmException | IOException e) {
            logger.error("jwt decode {}", e.getMessage());
        }

        return Jwts.parser()
                .setSigningKey(publicKey)
                .parseClaimsJws(jwt).getBody();
    }
}
