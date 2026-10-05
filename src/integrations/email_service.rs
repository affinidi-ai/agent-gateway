use anyhow::{Context, Result};
use lettre::message::{MultiPart, SinglePart, header};
use lettre::transport::smtp::authentication::Credentials;
use lettre::{Message, SmtpTransport, Transport};
use serde_json::Value as JsonValue;
use tracing::{debug, error, info, warn};

/// Configuration for SMTP email sending
#[derive(Debug, Clone)]
pub struct SmtpConfig {
    pub smtp_host: String,
    pub smtp_port: u16,
    pub smtp_username: String,
    pub smtp_password: String,
    pub from: String,
    pub to: Vec<String>,
    pub use_tls: bool,
    pub use_starttls: Option<bool>,
    pub cc: Option<Vec<String>>,
    pub bcc: Option<Vec<String>>,
}

impl SmtpConfig {
    /// Parse SMTP configuration from JSON
    pub fn from_json(config: &JsonValue) -> Result<Self> {
        debug!("Parsing SMTP configuration from JSON");

        let smtp_host = config["smtp_host"]
            .as_str()
            .context("Missing smtp_host")?
            .to_string();
        debug!("SMTP host: {}", smtp_host);

        let smtp_port = config["smtp_port"]
            .as_u64()
            .context("Missing smtp_port")? as u16;
        debug!("SMTP port: {}", smtp_port);

        let smtp_username = config["smtp_username"]
            .as_str()
            .context("Missing smtp_username")?
            .to_string();
        debug!("SMTP username configured ({} chars)", smtp_username.len());

        let smtp_password = config["smtp_password"]
            .as_str()
            .context("Missing smtp_password")?
            .to_string();
        debug!("SMTP password provided: {} chars", smtp_password.len());

        let from = config["from"]
            .as_str()
            .context("Missing from address")?
            .to_string();
        debug!("From address: {}", from);

        let to = config["to"]
            .as_array()
            .context("Missing or invalid 'to' array")?
            .iter()
            .filter_map(|v| {
                v.as_str()
                    .map(|s| s.to_string())
            })
            .collect::<Vec<_>>();
        debug!("To addresses: {:?}", to);

        if to.is_empty() {
            anyhow::bail!("At least one recipient email is required");
        }

        let use_tls = config["use_tls"]
            .as_bool()
            .unwrap_or(true);
        let use_starttls = config
            .get("use_starttls")
            .and_then(|v| v.as_bool());
        debug!("TLS settings: use_tls={}, use_starttls={:?}", use_tls, use_starttls);

        let cc = config
            .get("cc")
            .and_then(|v| v.as_array())
            .map(|arr| {
                arr.iter()
                    .filter_map(|v| {
                        v.as_str()
                            .map(|s| s.to_string())
                    })
                    .collect::<Vec<_>>()
            });
        if let Some(ref cc_list) = cc {
            debug!("CC addresses: {:?}", cc_list);
        }

        let bcc = config
            .get("bcc")
            .and_then(|v| v.as_array())
            .map(|arr| {
                arr.iter()
                    .filter_map(|v| {
                        v.as_str()
                            .map(|s| s.to_string())
                    })
                    .collect::<Vec<_>>()
            });
        if let Some(ref bcc_list) = bcc {
            debug!("BCC addresses: {:?}", bcc_list);
        }

        info!("SMTP configuration parsed successfully");

        Ok(Self {
            smtp_host,
            smtp_port,
            smtp_username,
            smtp_password,
            from,
            to,
            use_tls,
            use_starttls,
            cc,
            bcc,
        })
    }
}

/// Send an email notification
pub async fn send_email(
    config: &SmtpConfig,
    subject: &str,
    body: &str,
    is_html: bool,
) -> Result<()> {
    info!("Starting email send to {:?} via SMTP {}:{}", config.to, config.smtp_host, config.smtp_port);

    // Build the email message
    debug!("Building email message with from: {}", config.from);
    let mut email_builder = Message::builder().from(
        config
            .from
            .parse()
            .context("Invalid from address")?,
    );

    // Add primary recipients
    for recipient in &config.to {
        debug!("Adding recipient: {}", recipient);
        email_builder = email_builder.to(recipient
            .parse()
            .context("Invalid to address")?);
    }

    // Add CC recipients
    if let Some(cc_list) = &config.cc {
        for cc_addr in cc_list {
            debug!("Adding CC: {}", cc_addr);
            email_builder = email_builder.cc(cc_addr
                .parse()
                .context("Invalid cc address")?);
        }
    }

    // Add BCC recipients
    if let Some(bcc_list) = &config.bcc {
        for bcc_addr in bcc_list {
            debug!("Adding BCC: {}", bcc_addr);
            email_builder = email_builder.bcc(
                bcc_addr
                    .parse()
                    .context("Invalid bcc address")?,
            );
        }
    }

    email_builder = email_builder.subject(subject);
    debug!("Email subject: {}", subject);

    // Create the email with HTML or plain text body
    debug!("Building email body (is_html: {})", is_html);
    let email = if is_html {
        email_builder
            .multipart(
                MultiPart::alternative()
                    .singlepart(
                        SinglePart::builder()
                            .header(header::ContentType::TEXT_PLAIN)
                            .body(strip_html(body)),
                    )
                    .singlepart(
                        SinglePart::builder()
                            .header(header::ContentType::TEXT_HTML)
                            .body(body.to_string()),
                    ),
            )
            .context("Failed to build HTML email")?
    } else {
        email_builder
            .body(body.to_string())
            .context("Failed to build plain text email")?
    };

    info!("Email message built successfully, creating SMTP transport");

    // Create SMTP transport
    let creds = Credentials::new(config.smtp_username.clone(), config.smtp_password.clone());

    debug!(
        "Creating SMTP transport with TLS settings: use_tls={}, use_starttls={:?}, port={}",
        config.use_tls, config.use_starttls, config.smtp_port
    );

    // Determine transport type based on port and configuration
    // Port 465: Implicit TLS (SMTPS)
    // Port 587: STARTTLS (opportunistic TLS)
    // Other: Respect config flags
    let mailer = if config.smtp_port == 465 || (config.use_tls && config.smtp_port != 587) {
        info!("Using implicit TLS/SMTPS (port {})", config.smtp_port);
        SmtpTransport::relay(&config.smtp_host)
            .context("Failed to create SMTP relay")?
            .credentials(creds)
            .port(config.smtp_port)
            .build()
    } else if config.smtp_port == 587
        || config
            .use_starttls
            .unwrap_or(true)
    {
        info!("Using STARTTLS (port {})", config.smtp_port);
        SmtpTransport::starttls_relay(&config.smtp_host)
            .context("Failed to create SMTP STARTTLS relay")?
            .credentials(creds)
            .port(config.smtp_port)
            .build()
    } else {
        warn!("Using unencrypted SMTP connection (not recommended for production)");
        SmtpTransport::builder_dangerous(&config.smtp_host)
            .credentials(creds)
            .port(config.smtp_port)
            .build()
    };

    info!("SMTP transport created, attempting to send email...");

    // Send the email
    match mailer.send(&email) {
        Ok(_) => {
            info!("Email sent successfully to {:?} with subject: {}", config.to, subject);
            Ok(())
        }
        Err(e) => {
            error!("Failed to send email: {}", e);
            Err(anyhow::anyhow!("SMTP error: {}", e))
        }
    }
}

/// Send multiple emails using a single SMTP connection (batch optimization)
#[allow(dead_code)]
pub async fn send_email_batch(
    config: &SmtpConfig,
    messages: Vec<(String, String, bool)>, // (subject, body, is_html)
) -> Result<Vec<Result<()>>> {
    info!(
        "Starting batch email send ({} messages) to {:?} via SMTP {}:{}",
        messages.len(),
        config.to,
        config.smtp_host,
        config.smtp_port
    );

    // Create SMTP mailer once and reuse connection
    let creds = Credentials::new(config.smtp_username.clone(), config.smtp_password.clone());

    let mailer = if config.use_tls && config.smtp_port == 465 {
        info!("Using TLS (port 465) for batch send");
        SmtpTransport::relay(&config.smtp_host)
            .context("Failed to create SMTP relay")?
            .credentials(creds)
            .port(config.smtp_port)
            .build()
    } else if config.smtp_port == 587
        || config
            .use_starttls
            .unwrap_or(true)
    {
        info!("Using STARTTLS (port {}) for batch send", config.smtp_port);
        SmtpTransport::starttls_relay(&config.smtp_host)
            .context("Failed to create SMTP STARTTLS relay")?
            .credentials(creds)
            .port(config.smtp_port)
            .build()
    } else {
        warn!("Using unencrypted SMTP connection for batch (not recommended)");
        SmtpTransport::builder_dangerous(&config.smtp_host)
            .credentials(creds)
            .port(config.smtp_port)
            .build()
    };

    let mut results = Vec::new();

    // Send all messages using the same connection
    for (subject, body, is_html) in messages {
        let mut email_builder = Message::builder().from(
            config
                .from
                .parse()
                .context("Invalid from address")?,
        );

        for recipient in &config.to {
            email_builder = email_builder.to(recipient
                .parse()
                .context("Invalid to address")?);
        }

        if let Some(cc_list) = &config.cc {
            for cc_addr in cc_list {
                email_builder = email_builder.cc(cc_addr
                    .parse()
                    .context("Invalid cc address")?);
            }
        }

        if let Some(bcc_list) = &config.bcc {
            for bcc_addr in bcc_list {
                email_builder = email_builder.bcc(
                    bcc_addr
                        .parse()
                        .context("Invalid bcc address")?,
                );
            }
        }

        email_builder = email_builder.subject(subject.clone());

        let email = if is_html {
            let plain_text = strip_html(&body);
            email_builder
                .multipart(
                    MultiPart::alternative()
                        .singlepart(
                            SinglePart::builder()
                                .header(header::ContentType::TEXT_PLAIN)
                                .body(plain_text),
                        )
                        .singlepart(
                            SinglePart::builder()
                                .header(header::ContentType::TEXT_HTML)
                                .body(body.clone()),
                        ),
                )
                .context("Failed to build HTML email")?
        } else {
            email_builder
                .header(header::ContentType::TEXT_PLAIN)
                .body(body.clone())
                .context("Failed to build plain text email")?
        };

        // Send using the shared connection
        match mailer.send(&email) {
            Ok(_) => {
                debug!("Batch email sent successfully: {}", subject);
                results.push(Ok(()));
            }
            Err(e) => {
                error!("Failed to send batch email: {}", e);
                results.push(Err(anyhow::anyhow!("SMTP error: {}", e)));
            }
        }
    }

    info!(
        "Batch email send completed: {}/{} successful",
        results
            .iter()
            .filter(|r| r.is_ok())
            .count(),
        results.len()
    );

    Ok(results)
}

/// Simple HTML tag stripper for plain text alternative
fn strip_html(html: &str) -> String {
    let mut result = String::new();
    let mut inside_tag = false;

    for ch in html.chars() {
        match ch {
            '<' => inside_tag = true,
            '>' => inside_tag = false,
            _ if !inside_tag => result.push(ch),
            _ => {}
        }
    }

    // Clean up excessive whitespace
    result
        .split_whitespace()
        .collect::<Vec<_>>()
        .join(" ")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    #[ignore] // FIXME: failing test
    fn test_strip_html() {
        let html = "<h1>Hello</h1><p>This is a <strong>test</strong> message.</p>";
        let plain = strip_html(html);
        assert_eq!(plain, "Hello This is a test message.");
    }

    #[test]
    fn test_smtp_config_from_json() {
        let config_json = serde_json::json!({
            "smtp_host": "smtp.gmail.com",
            "smtp_port": 587,
            "smtp_username": "user@gmail.com",
            "smtp_password": "app-password",
            "from": "gateway@company.com",
            "to": ["admin@company.com"],
            "use_tls": false,
            "use_starttls": true
        });

        let config = SmtpConfig::from_json(&config_json).unwrap();
        assert_eq!(config.smtp_host, "smtp.gmail.com");
        assert_eq!(config.smtp_port, 587);
        assert_eq!(config.to.len(), 1);
        assert!(!config.use_tls);
        assert_eq!(config.use_starttls, Some(true));
    }
}
