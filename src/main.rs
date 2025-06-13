#![forbid(unsafe_code)]

use rocket::fairing::{Fairing, Info, Kind};
use rocket::figment::value::Value;
use rocket::http::Header;
use rocket::{
    fairing::AdHoc,
    figment::{
        providers::{Format, Serialized, Toml},
        Figment,
    },
};
use rocket::{Request, Response};
use rocket_db_pools::{sqlx::MySqlPool, Database};
use serde::{Deserialize, Serialize};

#[macro_use]
extern crate rocket;

pub struct CORS;

mod auth;

#[rocket::async_trait]
impl Fairing for CORS {
    fn info(&self) -> Info {
        Info {
            name: "Add CORS headers to responses",
            kind: Kind::Response,
        }
    }

    async fn on_response<'r>(&self, _request: &'r Request<'_>, response: &mut Response<'r>) {
        response.set_header(Header::new("Access-Control-Allow-Origin", "*"));
        response.set_header(Header::new(
            "Access-Control-Allow-Methods",
            "POST, GET, PATCH, OPTIONS",
        ));
        response.set_header(Header::new("Access-Control-Allow-Headers", "*"));
        response.set_header(Header::new("Access-Control-Allow-Credentials", "true"));
    }
}

#[derive(Debug, Deserialize, Serialize)]
struct OAuthConfig {
    auth_endpoint: String,
    token_endpoint: String,
    client_id: String,
    client_secret: String,
}

#[derive(Debug, Deserialize, Serialize)]
#[serde(crate = "rocket::serde")]
#[derive(Default)]
struct Config {
    oauth: Option<OAuthConfig>,
    base_url: String
}

#[derive(Database)]
#[database("cmdb")]
pub struct Cmdb(MySqlPool);

#[launch]
fn rocket() -> _ {
    let figment = Figment::from(rocket::Config::default())
        .merge(Serialized::defaults(Config::default()))
        .merge(Toml::file("Rocket.toml").nested())
        .merge(Toml::file("Api.toml"));

    let base_url: String = match figment.find_value("host.base_url") {
        Ok(value) => match value {
            Value::String(_, val) => val,
            _ => panic!("base_url must be a string."),
        },
        Err(_) => "/".to_string(),
    };

    rocket::custom(figment)
        .attach(Cmdb::init())
        .attach(AdHoc::config::<Config>())
        .attach(CORS)
        .mount(
            format!("{}/forums", base_url),
            routes![auth::authenticate, auth::callback],
        )
}
