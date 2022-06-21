#[macro_use]
extern crate slog;

use aws_sigv4::http_request::{sign, SignableRequest, SigningParams, SigningSettings};
use clap::Error as ClapError;
use clap::ErrorKind;
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

/// Shim for switching uid / gid, and loading HashiCorp Vault values into then
/// ENV of an executing program.
#[derive(clap::Parser, Debug)]
#[clap(author, version, about, long_about = None, )]
struct Args {
    /// AWS Region for for Vault RBAC auth
    #[clap(long, env, default_value = "us-east-1")]
    aws_region: String,

    /// AWS credentials URI for Vault RBAC auth
    #[clap(long, env)]
    aws_container_credentials_relative_uri: Option<String>,

    /// AWS access key for Vault RBAC auth
    #[clap(long, env)]
    aws_access_key_id: Option<String>,

    /// AWS secret key for Vault RBAC auth
    #[clap(long, env)]
    aws_secret_access_key: Option<String>,

    /// AWS session token for Vault RPAB auth
    #[clap(long, env)]
    aws_session_token: Option<String>,

    /// Fully qualified domain of the Vault server
    #[clap(long, env)]
    vault_addr: String,

    /// Path to vault certificate identitiy
    #[clap(long, env)]
    vault_cacert: Option<String>,

    /// X-Vault-AWS-IAM-Server-ID value
    #[clap(long, env)]
    vault_security_header: String,

    /// Vault role to authenticate as
    #[clap(long, env)]
    vault_role: String,

    /// username:group for command execution
    #[clap()]
    user_spec: String,

    /// Program to be exec'ed into
    #[clap()]
    command: String,

    /// Arguments to pass to command
    #[clap()]
    args: Vec<String>,
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

struct VaultClient {
    logger: slog::Logger,
    aws_region: String,
    aws_access_key_id: String,
    aws_secret_access_key: String,
    aws_session_token: Option<String>,
    addr: String,
    cacert: Option<String>,
    security_header: Option<String>,
    role: String,
    token: Option<String>,
}

impl VaultClient {
    fn new(
        logger: slog::Logger,
        addr: String,
        cacert: Option<String>,
        security_header: Option<String>,
        role: String,
        aws_region: String,
        aws_access_key_id: String,
        aws_secret_access_key: String,
        aws_session_token: Option<String>,
    ) -> VaultClient {
        VaultClient {
            logger: logger,
            addr: addr,
            cacert: cacert,
            security_header: security_header,
            role: role,
            token: None,
            aws_region: aws_region,
            aws_access_key_id: aws_access_key_id,
            aws_secret_access_key: aws_secret_access_key,
            aws_session_token: aws_session_token,
        }
    }

    fn https_client(&self) -> Result<reqwest::Client, reqwest::Error> {
        let builder = reqwest::Client::builder();

        match decode_certificate(&self.logger, &self.cacert) {
            Some(cert) => builder.add_root_certificate(cert),
            None => builder,
        }
        .build()
    }

    #[tokio::main]
    async fn vault_request(
        &self,
        request: reqwest::RequestBuilder,
    ) -> Result<serde_json::Value, Box<dyn error::Error>> {
        let request = request
            .header(
                "X-Vault-AWS-IAM-Server-ID",
                self.security_header.as_ref().unwrap_or(&String::from("")),
            )
            .header(
                "X-Vault-Token",
                self.token.as_ref().unwrap_or(&String::from("")),
            );

        trace!(self.logger, "Sending vault request - {:?}", request);
        let response = request.send().await.or_else(|e| {
            error!(self.logger, "Failed to send request to Vault - {e}");
            Err(Box::new(e) as Box<dyn error::Error>)
        })?;

        let text = response.text().await.or_else(|e| {
            error!(self.logger, "Failed to read response body from Vault - {e}");
            Err(Box::new(e) as Box<dyn error::Error>)
        })?;

        trace!(self.logger, "Parsing vault response");
        serde_json::from_str::<serde_json::Value>(&text)
            .or_else(|e| Err(Box::new(e) as Box<dyn error::Error>))
    }

    fn authenticate(mut self) -> Result<VaultClient, Box<dyn error::Error>> {
        info!(self.logger, "Setting up mock sts:GetCallerIdentity request");
        let request_method = "POST";
        let request_body = b"Action=GetCallerIdentity&Version=2011-06-15";

        let request_builder = http::Request::builder()
            .method(request_method)
            .uri("https://sts.amazonaws.com")
            .header(
                "Content-Type",
                "application/x-www-form-urlencoded;charset=utf-8",
            )
            .header(
                "X-Vault-AWS-IAM-Server-ID",
                self.security_header.as_ref().unwrap_or(&String::from("")),
            )
            .body(request_body);

        let mut request = request_builder.or_else(|e| {
            error!(self.logger, "Error building vault auth request - {e}");
            Err(Box::new(e) as Box<dyn error::Error>)
        })?;

        info!(self.logger, "Setting up request signing parameters");
        let signing_settings = SigningSettings::default();
        let mut signing_params_builder = SigningParams::builder()
            .region(&self.aws_region)
            .access_key(&self.aws_access_key_id)
            .secret_key(&self.aws_secret_access_key)
            .service_name("sts")
            .time(SystemTime::now())
            .settings(signing_settings);

        if let Some(ref session_token) = self.aws_session_token {
            signing_params_builder = signing_params_builder.security_token(session_token);
        }

        let signing_params = signing_params_builder.build()?;

        info!(self.logger, "Sign mock sts:GetCallerIdentity request");
        let signable_request = SignableRequest::from(&request);
        let (signing_instructions, _signature) = sign(signable_request, &signing_params)
            .unwrap()
            .into_parts();
        signing_instructions.apply_to_request(&mut request);

        info!(self.logger, "Building Vault auth request body");
        let nonce = Uuid::new_v4().hyphenated().to_string();
        let iam_request_url = base64::encode(b"https://sts.amazonaws.com");
        let iam_request_headers =
            serde_json::to_string(&convert(request.headers())).map(base64::encode)?;
        let iam_request_body = base64::encode(request_body);

        let owned_request_method = String::from(request_method);

        let login_data = HashMap::from([
            ("role", &self.role),
            ("nonce", &nonce),
            ("iam_http_request_method", &owned_request_method),
            ("iam_request_url", &iam_request_url),
            ("iam_request_headers", &iam_request_headers),
            ("iam_request_body", &iam_request_body),
        ]);

        let request = self
            .https_client()?
            .post(format!("{}/v1/auth/aws/login", self.addr))
            .json(&login_data);

        self.token = Some(self.vault_request(request).and_then(|json| {
            json["auth"]["client_token"]
                .as_str()
                .map(String::from)
                .ok_or_else(|| {
                    error!(self.logger, "No client auth token found");
                    Box::new(serde_json::Error::custom("No client auth token"))
                        as Box<dyn error::Error>
                })
        })?);

        Ok(self)
    }

    fn read(&self, engine: &str, path: &str, key: &str) -> Result<String, Box<dyn error::Error>> {
        let request = self
            .https_client()?
            .get(format!("{}/v1/{engine}/data/{path}", self.addr));

        self.vault_request(request).and_then(|json| {
            json["data"]["data"][key]
                .as_str()
                .map(String::from)
                .ok_or_else(|| {
                    warn!(
                        self.logger,
                        "No secret value found for vault:{engine}:{path}:{key}"
                    );
                    Box::new(serde_json::Error::custom("No key found")) as Box<dyn error::Error>
                })
        })
    }
}

fn decode_certificate(
    logger: &slog::Logger,
    path: &Option<String>,
) -> Option<reqwest::Certificate> {
    if let Some(vault_cacert) = path {
        let reader = std::fs::File::open(vault_cacert)
            .and_then(|fh| Ok(std::io::BufReader::new(fh)))
            .or_else(|e| {
                error!(logger, "Failed to read cert {vault_cacert} - {e}");
                Err(e)
            })
            .ok()?;

        let cert_body = std::io::BufRead::lines(reader)
            .filter_map(|line| line.ok().filter(|line| !line.contains("-")))
            .collect::<Vec<String>>()
            .join("");

        let decoded_cert = base64::decode(cert_body)
            .or_else(|e| {
                error!(logger, "Failed to decode certificate - {e}");
                Err(Box::new(e) as Box<dyn error::Error>)
            })
            .ok()?;

        reqwest::Certificate::from_der(&decoded_cert)
            .or_else(|e| {
                error!(logger, "Failed to create Certificate - {e}");
                Err(Box::new(e) as Box<dyn error::Error>)
            })
            .ok()
    } else {
        None
    }
}

fn build_environment(vault_client: &VaultClient) -> Vec<CString> {
    std::env::vars()
        .map(|(key, value)| {
            (
                key,
                if value.starts_with("vault:") {
                    let fields: Vec<&str> = value.split(":").collect();
                    let (_, engine, path, key) = (fields[0], fields[1], fields[2], fields[3]);

                    vault_client.read(&engine, &path, &key).unwrap_or(value)
                } else {
                    value
                },
            )
        })
        .map(|(key, value)| CString::new([key, value].join("=")).unwrap())
        .collect()
}

fn switch_user(ctx: &VaultClient, user_spec: &String) -> Result<(), Box<dyn error::Error>> {
    let user_spec: Vec<&str> = user_spec.split(":").collect();

    if let Some(group_name) = user_spec.get(1) {
        let group = Group::from_name(&group_name).or_else(|e| {
            error!(
                ctx.logger,
                "Failed to lookup group name: {group_name} - {e}"
            );
            Err(Box::new(e) as Box<dyn error::Error>)
        })?;

        if let Some(group) = group {
            setgid(group.gid).or_else(|e| {
                error!(ctx.logger, "Failed to set GID to {} - {e}", group.gid);
                Err(Box::new(e) as Box<dyn error::Error>)
            })?;
        } else {
            warn!(
                ctx.logger,
                "No group named {group_name} found - Not setting GID"
            );
        }
    }

    if let Some(user_name) = user_spec.get(0) {
        let user = User::from_name(&user_name).or_else(|e| {
            error!(ctx.logger, "Failed to lookup user name: {user_name} - {e}");
            Err(Box::new(e) as Box<dyn error::Error>)
        })?;

        if let Some(user) = user {
            chdir(&user.dir).or_else(|e| {
                error!(
                    ctx.logger,
                    "Failed to change directory {:?} - {e}", user.dir
                );
                Err(Box::new(e) as Box<dyn error::Error>)
            })?;

            setuid(user.uid).or_else(|e| {
                error!(ctx.logger, "Failed to set UID to {} - {e}", user.uid);
                Err(Box::new(e) as Box<dyn error::Error>)
            })?;
        } else {
            warn!(
                ctx.logger,
                "No user named {user_name} found - Not setting UID"
            );
        }
    }
    Ok(())
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

#[derive(serde::Deserialize)]
#[serde(rename_all(deserialize = "PascalCase"))]
struct AwsCredentials {
    access_key_id: String,
    expiration: String,
    role_arn: String,
    secret_access_key: String,
    token: String,
}

#[tokio::main]
async fn fetch_aws_credentials(
    relative_uri: &String,
    logger: &slog::Logger,
) -> Result<(String, String, Option<String>), Box<dyn error::Error>> {
    let aws_container_credentials_uri = format!("http://169.254.170.2{}", relative_uri);
    let request = reqwest::Client::new().get(&aws_container_credentials_uri);

    let response = request.send().await.or_else(|e| {
        error!(logger, "Failed to send request to aws - {aws_container_credentials_uri}");
        error!(logger, "Failed to send request to aws - {e}");
        Err(Box::new(e) as Box<dyn error::Error>)
    })?;

    let text = response.text().await.or_else(|e| {
        error!(logger, "Failed to read response body from Vault - {e}");
        Err(Box::new(e) as Box<dyn error::Error>)
    })?;

    info!(logger, "Parsing vault response");

    let result = serde_json::from_str::<AwsCredentials>(&text)
        .or_else(|e| Err(Box::new(e) as Box<dyn error::Error>))?;

    Ok((
        result.access_key_id,
        result.secret_access_key,
        Some(result.token),
    ))
}

fn main() -> Result<(), Box<dyn error::Error>> {
    let args = Args::parse();

    #[cfg(debug_assertions)]
    let logger = {
        let decorator = slog_term::TermDecorator::new().build();
        let drain = slog_term::CompactFormat::new(decorator).build();
        Mutex::new(drain)
    };

    #[cfg(not(debug_assertions))]
    let logger = Mutex::new(slog_json::Json::default(std::io::stderr()));
    let main_logger = slog::Logger::root(
        logger.map(slog::Fuse),
        o!(
            "version" => env!("CARGO_PKG_VERSION"),
            "app" => env!("CARGO_PKG_NAME")
        ),
    );

    let (aws_access_key_id, aws_secret_access_key, aws_session_token) = match args {
        Args { aws_access_key_id: Some(access_key_id), aws_secret_access_key: Some(secret_access_key), .. } => (
            access_key_id,
            secret_access_key,
            args.aws_session_token,
        ),
        Args { aws_container_credentials_relative_uri: Some(uri), .. } => {
            fetch_aws_credentials(&uri, &main_logger)?
        },
        _ => return Err(Box::new(ClapError::raw(
            ErrorKind::MissingRequiredArgument,
            "Missing aws credentials. Please provide aws_access_key_id and aws_secret_access_key or aws_container_credentials_relative_uri",
        ))),
    };

    let vault_client = VaultClient::new(
        main_logger,
        args.vault_addr,
        args.vault_cacert,
        Some(args.vault_security_header),
        args.vault_role,
        args.aws_region,
        aws_access_key_id,
        aws_secret_access_key,
        aws_session_token,
    )
    .authenticate()?;

    switch_user(&vault_client, &args.user_spec)?;

    let env = build_environment(&vault_client);

    exec(args.command, &args.args, &env);

    Ok(())
}
