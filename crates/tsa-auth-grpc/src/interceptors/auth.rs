use tonic::{Request, Status};

#[derive(Debug, Clone)]
pub struct AuthToken(pub String);

pub fn extract_token<T>(request: &Request<T>) -> Result<String, Status> {
    let token = request
        .metadata()
        .get("authorization")
        .and_then(|v| v.to_str().ok())
        .and_then(|v| v.strip_prefix("Bearer "))
        .ok_or_else(|| Status::unauthenticated("Missing or invalid authorization header"))?;

    Ok(token.to_string())
}

#[derive(Debug, Clone)]
pub struct ClientInfo {
    pub ip_address: Option<String>,
    pub user_agent: Option<String>,
}

pub fn extract_client_info<T>(request: &Request<T>) -> ClientInfo {
    let ip_address = request
        .metadata()
        .get("x-forwarded-for")
        .and_then(|v| v.to_str().ok())
        .map(|s| s.to_string());

    let user_agent = request
        .metadata()
        .get("user-agent")
        .and_then(|v| v.to_str().ok())
        .map(|s| s.to_string());

    ClientInfo {
        ip_address,
        user_agent,
    }
}
