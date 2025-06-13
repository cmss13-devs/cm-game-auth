use base64::{prelude::BASE64_STANDARD, Engine};
use rand::{distr::Alphanumeric, Rng};
use rocket::{response::Redirect, State};
use rocket_db_pools::Connection;
use serde::Deserialize;
use sqlx::query;

use crate::{Cmdb, Config};

#[get("/authenticate?<token>")]
pub async fn authenticate(token: &str, config: &State<Config>) -> Redirect {
    let oauth_config = config.oauth.as_ref().unwrap();

    let nonce: String = rand::rng()
        .sample_iter(&Alphanumeric)
        .take(14)
        .map(char::from)
        .collect();

    Redirect::found(format!("{}?scope=openid%20profile&response_type=code&client_id={}&redirect_uri={}/forums/callback&nonce={}&state={}", &oauth_config.auth_endpoint, &oauth_config.client_id, &config.base_url, &nonce, token))
}

#[derive(Deserialize)]
#[allow(dead_code)]
struct OauthResponse {
    access_token: String,
    expires_in: i32,
    id_token: String,
    scope: String,
    token_type: String,
}

#[derive(Deserialize, Debug)]
#[allow(dead_code)]
struct Oauthuser {
    at_hash: String,
    aud: Vec<String>,
    auth_time: i32,
    email: String,
    email_verified: bool,
    exp: i32,
    groups: Vec<String>,
    iat: i32,
    iss: String,
    jti: String,
    name: String,
    nonce: String,
    picture: String,
    rat: i32,
    sub: String,
}

#[get("/callback?<code>&<scope>&<state>")]
#[allow(unused_variables)]
pub async fn callback(
    mut db: Connection<Cmdb>,
    code: &str,
    scope: &str,
    state: &str,
    config: &State<Config>,
) -> String {
    let oauth_config = config.oauth.as_ref().unwrap();

    if !state.chars().all(char::is_alphanumeric) {
        return String::from("Invalid token.");
    };

    let http_client = reqwest::Client::new();

    let result = http_client
        .post(&oauth_config.token_endpoint)
        .form(&[
            ("client_id", &oauth_config.client_id),
            ("client_secret", &oauth_config.client_secret),
            ("grant_type", &String::from("authorization_code")),
            ("code", &code.to_string()),
            (
                "redirect_uri",
                &format!("{}/forums/callback", &config.base_url),
            ),
        ])
        .send()
        .await;

    let Ok(response) = result else {
        return String::from("No response provided from authentication server.");
    };

    let Ok(json) = response.json::<OauthResponse>().await else {
        return String::from("Unable to parse response");
    };

    let Some(user) = json.id_token.split('.').nth(1) else {
        return String::from("Could not retrieve user from response.");
    };

    let Ok(decoded_user) = BASE64_STANDARD.decode(user) else {
        return String::from("Could not decode user from response.");
    };

    let Ok(parsed_user) = String::from_utf8(decoded_user) else {
        return String::from("An error occured");
    };

    let Ok(json_user) = serde_json::from_str::<Oauthuser>(&parsed_user) else {
        return String::from("Unable to parse user from response.");
    };

    let Ok(query) = query("UPDATE authentication_requests SET approved = 1, external_username = ? WHERE access_code = ?").bind(json_user.sub).bind(state).execute(&mut **db).await else {
        return String::from("An error occured interfacing with the database.")
    };

    if query.rows_affected() == 0 {
        return String::from("Your authentication request could not be found. Please try again.");
    };

    String::from("Your authentication request has been approved. You can now return to the game.")
}
