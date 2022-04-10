use aws_sigv4::http_request::{sign, SignableRequest, SigningParams, SigningSettings};
use clap::Parser;
use http::{HeaderMap, HeaderValue};
use nix::unistd::{chdir, execve, setgid, setuid, Group, User};
use serde::de::Error;
use std::collections::HashMap;
use std::error;
use std::ffi::CString;
use std::time::SystemTime;
use uuid::Uuid;

/// Simple program to greet a person
#[derive(clap::Parser, Debug)]
#[clap(author, version, about, long_about = None, )]
struct Args {
    #[clap(long, env, default_value = "us-east-1")]
    aws_region: String,

    #[clap(long, env)]
    aws_access_key_id: String,

    #[clap(long, env)]
    aws_secret_access_key: String,

    #[clap(long, env)]
    vault_token: Option<String>,

    #[clap(long, env)]
    vault_addr: String,

    #[clap(long, env)]
    vault_cacert: Option<String>,

    #[clap(long, env)]
    vault_capath: Option<String>,

    #[clap(long, env)]
    vault_security_header: String,

    #[clap()]
    user_spec: String,

    #[clap()]
    command: String,

    #[clap()]
    args: Vec<String>,
}

fn convert(headers: &HeaderMap<HeaderValue>) -> HashMap<String, Vec<String>> {
    let mut header_hashmap = HashMap::new();
    for (k, v) in headers {
        let k = k.as_str().to_owned();
        let v = String::from_utf8_lossy(v.as_bytes()).into_owned();
        header_hashmap.entry(k).or_insert_with(Vec::new).push(v)
    }
    header_hashmap
}

#[tokio::main]
async fn auth_vault(
    aws_region: &str,
    aws_access_key_id: &str,
    aws_secret_access_key: &str,
    vault_security_header: &str,
    vault_addr: &str,
) -> Result<String, Box<dyn error::Error>> {
    let signing_settings = SigningSettings::default();
    let signing_params = SigningParams::builder()
        .region(aws_region)
        .access_key(aws_access_key_id)
        .secret_key(aws_secret_access_key)
        .service_name("sts")
        .time(SystemTime::now())
        .settings(signing_settings)
        .build()
        .unwrap();

    let request_method = "POST";
    let request_body = b"Action=GetCallerIdentity&Version=2011-06-15";

    let mut request = http::Request::builder()
        .method(request_method)
        .uri("https://sts.amazonaws.com")
        .header(
            "Content-Type",
            "application/x-www-form-urlencoded;charset=utf-8",
        )
        .header("X-Vault-AWS-IAM-Server-ID", vault_security_header)
        .body(request_body)
        .unwrap();

    let signable_request = SignableRequest::from(&request);

    let (signing_instructions, _signature) = sign(signable_request, &signing_params)
        .unwrap()
        .into_parts();

    signing_instructions.apply_to_request(&mut request);

    let nonce = Uuid::new_v4().hyphenated().to_string();
    let iam_request_url = base64::encode(b"https://sts.amazonaws.com").to_string();
    let iam_request_headers =
        base64::encode(serde_json::to_string(&convert(request.headers())).unwrap()).to_string();
    let iam_request_body = base64::encode(request_body).to_string();

    let login_data = HashMap::from([
        ("role", "jenkins-vault-writer"),
        ("nonce", &nonce),
        ("iam_http_request_method", request_method),
        ("iam_request_url", &iam_request_url),
        ("iam_request_headers", &iam_request_headers),
        ("iam_request_body", &iam_request_body),
    ]);

    let request = reqwest::Client::builder()
        .danger_accept_invalid_certs(true)
        .build()
        .unwrap()
        .post(format!("{}/v1/auth/aws/login", vault_addr))
        .header("X-Vault-AWS-IAM-Server-ID", vault_security_header)
        .json(&login_data);

    let text = request.send().await?.text().await?;

    match serde_json::from_str::<serde_json::Value>(&text) {
        Ok(data) => Ok(String::from(data["auth"]["client_token"].as_str().unwrap())),
        Err(e) => Err(Box::new(e) as Box<dyn error::Error>),
    }
}

#[tokio::main]
async fn vault_kv_get(
    url: &str,
    token: &str,
    engine: &str,
    path: &str,
    key: &str,
) -> Result<String, Box<dyn error::Error>> {
    let request = reqwest::Client::builder()
        .danger_accept_invalid_certs(true)
        .build()
        .unwrap()
        .get(format!("{url}/v1/{engine}/data/{path}"))
        .header("X-Vault-Token", token);

    let text = request.send().await?.text().await?;

    serde_json::from_str::<serde_json::Value>(&text)
        .or_else(|e| Err(Box::new(e) as Box<dyn error::Error>))
        .and_then(|v| {
            v["data"]["data"][key]
                .as_str()
                .ok_or(Box::new(serde_json::Error::custom("No key found")) as Box<dyn error::Error>)
                .map(String::from)
        })
}

fn process_env(args: &Args) -> Result<Vec<CString>, Box<dyn error::Error>> {
    let token = match auth_vault(
        &args.aws_region,
        &args.aws_access_key_id,
        &args.aws_secret_access_key,
        &args.vault_security_header,
        &args.vault_addr,
    ) {
        Ok(token) => token,
        Err(_) => String::from(""),
    };

    Ok(std::env::vars()
        .map(|(key, value)| {
            (
                key,
                if value.starts_with("vault:") {
                    let fields: Vec<&str> = value.split(":").collect();
                    let (_, engine, path, key) = (fields[0], fields[1], fields[2], fields[3]);

                    match vault_kv_get(&args.vault_addr, &token, &engine, &path, &key) {
                        Ok(v) => v,
                        Err(_) => value,
                    }
                } else {
                    value
                },
            )
        })
        .map(|(key, value)| CString::new([key, value].join("=")).unwrap())
        .collect())
}

fn switch_user(user_spec: &String) {
    let user_spec: Vec<&str> = user_spec.split(":").collect();
    let (user, group) = match user_spec.len() {
        2 => (user_spec[0], user_spec[1]),
        _ => (user_spec[0], user_spec[0]),
    };

    let user = User::from_name(&user)
        .expect("User lookup failed")
        .expect("User not found");

    let group = Group::from_name(&group)
        .expect("Group lookup failed")
        .expect("Group not found");

    chdir(&user.dir).expect("chdir failed");
    setgid(group.gid).expect("setgid failed");
    setuid(user.uid).expect("setuid failed");
}

fn exec(command: String, args: &Vec<String>, env: &Vec<CString>) {
    let cmd = CString::new(command.clone()).unwrap();

    let cmd_args: Vec<CString> = [command]
        .iter()
        .chain(args.iter())
        .map(|string| CString::new(string.as_str()).unwrap())
        .collect();

    execve(cmd.as_c_str(), &cmd_args, env).expect("exec failed");
}

fn main() {
    let args = Args::parse();

    switch_user(&args.user_spec);

    let env = process_env(&args).unwrap();

    exec(args.command, &args.args, &env);
}
