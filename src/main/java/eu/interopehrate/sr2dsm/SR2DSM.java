package eu.interopehrate.sr2dsm;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.core.type.TypeReference;
import com.fasterxml.jackson.databind.ObjectMapper;

import java.io.*;
import java.security.spec.InvalidKeySpecException;
import java.util.List;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

import eu.interopehrate.sr2dsm.model.EidasResponse;
import eu.interopehrate.sr2dsm.model.ResponseDetails;
import eu.interopehrate.sr2dsm.model.ResponseAttibute;
import eu.interopehrate.sr2dsm.model.SubStatusCode;
import eu.interopehrate.sr2dsm.model.UserDetails;
import io.jsonwebtoken.Claims;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

public class SR2DSM {

    private static final Logger logger = LoggerFactory.getLogger(SR2DSM.class);

    public static ResponseDetails decode(final String jwt) throws InvalidKeySpecException {

        String key = "";
        try {
            key = LoadData("private.pub");
        } catch (IOException e) {
            logger.error("Failed to load private.pub :{}", e.getMessage());
        }
        logger.debug("key {}", key);
        Claims jwtClaims = JwtUtil.decode(jwt, key);

        ResponseDetails res = new ResponseDetails();

        res.setAssertion(jwtClaims.get("assertion").toString());
        String encryptedData = jwtClaims.get("attributes").toString();
        String data = JwtUtil.decode(encryptedData, key).get("data3").toString();
        data = data.replaceAll("\n","");
        data = data.replaceAll("\r","");

        //Extract only the response part with REGEX
        Pattern pattern = Pattern.compile("(?<=\"response\" : )(.*)(?=\\}</textarea)");
        Matcher matcher = pattern.matcher(data);
        if (matcher.find()) data = matcher.group(1);

        //Map JSON to JAVA object
        EidasResponse response = null;
        UserDetails user = null;
        try {
            response = new ObjectMapper().readValue(data, EidasResponse.class);
            List<ResponseAttibute> attributes = new ObjectMapper()
                    .readValue(response.getAttribute_list().toString(),
                            new TypeReference<List<ResponseAttibute>>(){});

            user = UserDetails.create(attributes);
        } catch (JsonProcessingException e) {
            logger.error("Failed to map json to object: {}",e.getMessage());
        }

        if (response.getStatus().getSub_status_code() != null) {
            logger.debug("Successful Response with id: " + response.getId() +
                    "\n and status " + response.getStatus().getSub_status_code() +
                    "\n and issuer:" + response.getIssuer());
        }
        else {
            logger.debug("Successful Response with id " + response.getId() +
                    " \n with status " + response.getStatus().getStatus_code() +
                    " \n and with attributes " + response.getAttribute_list());
        }
        res.setEidasResponse(response);
        res.setUserDetails(user);

        //Check if the user was authenticated
        boolean authenticated = false;
        if (response.getStatus().getSub_status_code() != null &&
                response.getStatus().getSub_status_code().equals(SubStatusCode.AuthnSuccess)) authenticated = true;
        if (response.getStatus().getSub_status_code() == null &&
                response.getStatus().getStatus_code().equals("success")) authenticated = true;

        res.setAuthenticated(authenticated);

        //Only display the extraJwt if the Authentication process was successful
        if (authenticated) {
            logger.debug("The assertion is: "+ res.getAssertion());
        }

        return res;
    }

    private static String LoadData(String filePath) throws IOException {
        BufferedReader reader = null;
        StringBuilder builder = new StringBuilder();
        try {
            InputStream stream = SR2DSM.class.getClassLoader().getResourceAsStream(filePath);
            reader = new BufferedReader(
                    new InputStreamReader(stream, "UTF-8"));

            int c;
            while ((c = reader.read()) != -1) {
                builder.append((char)c);
            }
        } catch (IOException e) {
            throw e;
        } finally {
            if (reader != null) {
                try {
                    reader.close();
                } catch (IOException e) {
                    logger.error("Failed to close stream " + e.getMessage());
                }
            }
        }
        return builder.toString();
    }

}
