package com.baeldung.resource;

import io.restassured.RestAssured;
import io.restassured.response.Response;
import org.junit.Test;

import java.util.HashMap;
import java.util.Map;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNotNull;

//Before running this live test make sure both authorization server and resource server are running   

public class PreferredUserNameValidatorLiveTest {

	private final static String AUTH_SERVER = "http://localhost:8083/auth/realms/baeldung/protocol/openid-connect";
	private final static String RESOURCE_SERVER = "http://localhost:8081/resource-server";
	private final static String CLIENT_ID = "newClient";
	private final static String CLIENT_SECRET = "newClientSecret";
	private final static String VALID_USER_NAME = "john@test.com";
	private final static String VALID_USER_PASSWORD = "123";

	private final static String INVALID_USER_NAME = "mike@other.com";
	private final static String INVALID_USER_PASSWORD = "pass";

	@Test
	public void givenUser_whenUseFooClient_thenOkForFooResourceOnly() {
		final String accessToken = obtainAccessToken(CLIENT_ID, VALID_USER_NAME, VALID_USER_PASSWORD);

		final Response fooResponse = RestAssured.given().header("Authorization", "Bearer " + accessToken)
				.get(RESOURCE_SERVER + "/api/foos/1");
		assertEquals(200, fooResponse.getStatusCode());
		assertNotNull(fooResponse.jsonPath().get("name"));
	}

	@Test
	public void givenUser_whenUseFooClient_thenUnAuthorizeForFooResourceOnly() {
		final String accessToken = obtainAccessToken(CLIENT_ID, INVALID_USER_NAME, INVALID_USER_PASSWORD);

		final Response fooResponse = RestAssured.given().header("Authorization", "Bearer " + accessToken)
				.get(RESOURCE_SERVER + "/api/foos/1");
		assertEquals(401, fooResponse.getStatusCode());
	}

	private String obtainAccessToken(String clientId, String username, String password) {
		final Map<String, String> params = new HashMap<String, String>();
		params.put("grant_type", "password");
		params.put("client_id", clientId);
		params.put("username", username);
		params.put("password", password);
		params.put("scope", "read write");
		final Response response = RestAssured.given().auth().preemptive().basic(clientId, CLIENT_SECRET).and()
				.with().params(params).when().post(AUTH_SERVER + "/token");
		return response.jsonPath().getString("access_token");
	}

}
