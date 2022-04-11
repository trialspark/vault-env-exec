#[macro_use]
extern crate slog;

use aws_sigv4::http_request::{sign, SignableRequest, SigningParams, SigningSettings};
use clap::Parser;
use http::{HeaderMap, HeaderValue};
use nix::unistd::{chdir, execve, setgid, setuid, Group, User};
use serde::de::Error;
use slog::Drain;
use std::collections::HashMap;
use std::error;
use std::ffi::CString;
use std::sync::Mutex;
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

struct Context {
    logger: slog::Logger,
}

fn decode_certificate(path: &Option<String>) -> Option<reqwest::Certificate> {
    if let Some(vault_cacert) = path {
        std::fs::File::open(vault_cacert)
            .map(|fh| std::io::BufReader::new(fh))
            .map(|buffer| std::io::BufRead::lines(buffer))
            .map(|lines| lines.filter_map(|line| line.ok().filter(|line| !line.contains("-"))))
            .map(std::iter::Iterator::collect::<Vec<String>>)
            .map(|lines| lines.join(""))
            .map_err(|e| Box::new(e) as Box<dyn error::Error>)
            .and_then(|cert| base64::decode(cert).map_err(|e| Box::new(e) as Box<dyn error::Error>))
            .and_then(|der| {
                reqwest::Certificate::from_der(&der)
                    .map_err(|e| Box::new(e) as Box<dyn error::Error>)
            })
            .ok()
    } else {
        None
    }
}

fn vault_https_client(
    _ctx: &Context,
    vault_cacert: &Option<String>,
) -> Result<reqwest::Client, reqwest::Error> {
    let builder = reqwest::Client::builder();

    if let Some(cert) = decode_certificate(vault_cacert) {
        builder.add_root_certificate(cert).build()
    } else {
        builder.build()
    }
}

fn convert(headers: &HeaderMap<HeaderValue>) -> HashMap<String, Vec<String>> {
    headers
        .into_iter()
        .fold(HashMap::new(), |mut hash, (key, val)| {
            hash.entry(key.as_str().to_owned())
                .or_insert_with(Vec::new)
                .push(String::from_utf8_lossy(val.as_bytes()).into_owned());
            hash
        })
}

#[tokio::main]
async fn auth_vault(
    ctx: &Context,
    aws_region: &str,
    aws_access_key_id: &str,
    aws_secret_access_key: &str,
    vault_security_header: &str,
    vault_addr: &str,
    vault_cacert: &Option<String>,
) -> Result<String, Box<dyn error::Error>> {
    info!(ctx.logger, "Setting up mock sts:GetCallerIdentity request");
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

    info!(ctx.logger, "Setting up request signing parameters");
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

    info!(ctx.logger, "Sign mock sts:GetCallerIdentity request");
    let signable_request = SignableRequest::from(&request);
    let (signing_instructions, _signature) = sign(signable_request, &signing_params)
        .unwrap()
        .into_parts();
    signing_instructions.apply_to_request(&mut request);

    info!(ctx.logger, "Building Vault auth request body");
    let nonce = Uuid::new_v4().hyphenated().to_string();
    let iam_request_url = base64::encode(b"https://sts.amazonaws.com");
    let iam_request_headers = serde_json::to_string(&convert(request.headers()))
        .map(base64::encode)
        .unwrap();
    let iam_request_body = base64::encode(request_body);

    let login_data = HashMap::from([
        ("role", "jenkins-vault-writer"),
        ("nonce", &nonce),
        ("iam_http_request_method", request_method),
        ("iam_request_url", &iam_request_url),
        ("iam_request_headers", &iam_request_headers),
        ("iam_request_body", &iam_request_body),
    ]);

    info!(ctx.logger, "Build Vault auth request");
    let request = vault_https_client(ctx, vault_cacert)
        .unwrap()
        .post(format!("{vault_addr}/v1/auth/aws/login"))
        .header("X-Vault-AWS-IAM-Server-ID", vault_security_header)
        .json(&login_data);

    info!(ctx.logger, "Send Vault auth reqest");
    let text = request.send().await?.text().await?;

    info!(ctx.logger, "Parsing Vault response json body");
    serde_json::from_str::<serde_json::Value>(&text)
        .or_else(|e| Err(Box::new(e) as Box<dyn error::Error>))
        .and_then(|json| {
            json["auth"]["client_token"]
                .as_str()
                .map(String::from)
                .ok_or_else(|| {
                    warn!(ctx.logger, "No client token found in auth json");
                    Box::new(serde_json::Error::custom("No client token found"))
                        as Box<dyn error::Error>
                })
        })
}

#[tokio::main]
async fn vault_kv_get(
    ctx: &Context,
    vault_cacert: &Option<String>,
    url: &str,
    token: &str,
    engine: &str,
    path: &str,
    key: &str,
) -> Result<String, Box<dyn error::Error>> {
    info!(
        ctx.logger,
        "Building Vault lookup request for {engine}/{path}/{key}"
    );
    let request = vault_https_client(ctx, vault_cacert)
        .unwrap()
        .get(format!("{url}/v1/{engine}/data/{path}"))
        .header("X-Vault-Token", token);

    info!(ctx.logger, "Sending Vault lookup request");
    let text = request.send().await?.text().await?;

    info!(ctx.logger, "Parsing Vault lookup json body");
    serde_json::from_str::<serde_json::Value>(&text)
        .or_else(|e| Err(Box::new(e) as Box<dyn error::Error>))
        .and_then(|json| {
            json["data"]["data"][key]
                .as_str()
                .map(String::from)
                .ok_or_else(|| {
                    warn!(
                        ctx.logger,
                        "No secret value found for vault:{engine}:{path}:{key}"
                    );
                    Box::new(serde_json::Error::custom("No key found")) as Box<dyn error::Error>
                })
        })
}

fn process_env(ctx: &Context, args: &Args) -> Result<Vec<CString>, Box<dyn error::Error>> {
    let token = auth_vault(
        ctx,
        &args.aws_region,
        &args.aws_access_key_id,
        &args.aws_secret_access_key,
        &args.vault_security_header,
        &args.vault_addr,
        &args.vault_cacert,
    )
    .unwrap();

    Ok(std::env::vars()
        .map(|(key, value)| {
            (
                key,
                if value.starts_with("vault:") {
                    let fields: Vec<&str> = value.split(":").collect();
                    let (_, engine, path, key) = (fields[0], fields[1], fields[2], fields[3]);

                    match vault_kv_get(
                        ctx,
                        &args.vault_cacert,
                        &args.vault_addr,
                        &token,
                        &engine,
                        &path,
                        &key,
                    ) {
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

fn switch_user(ctx: &Context, user_spec: &String) {
    trace!(ctx.logger, "Entering switch_user");

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

    #[cfg(debug_assertions)]
    let logger = {
        let decorator = slog_term::TermDecorator::new().build();
        let drain = slog_term::CompactFormat::new(decorator).build();
        Mutex::new(drain)
    };

    #[cfg(not(debug_assertions))]
    let logger = Mutex::new(slog_json::Json::default(std::io::stderr()));

    let ctx = Context {
        logger: slog::Logger::root(
            logger.map(slog::Fuse),
            o!(
                "version" => env!("CARGO_PKG_VERSION"),
                "app" => env!("CARGO_PKG_NAME")
            ),
        ),
    };

    switch_user(&ctx, &args.user_spec);

    let env = process_env(&ctx, &args).unwrap();

    exec(args.command, &args.args, &env);
}
