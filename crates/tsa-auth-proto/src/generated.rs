use prost::Message;
use prost_types::Timestamp;

#[derive(Clone, PartialEq, Message)]
pub struct User {
    #[prost(string, tag = "1")]
    pub id: String,
    #[prost(string, tag = "2")]
    pub email: String,
    #[prost(bool, tag = "3")]
    pub email_verified: bool,
    #[prost(string, optional, tag = "4")]
    pub phone: Option<String>,
    #[prost(bool, tag = "5")]
    pub phone_verified: bool,
    #[prost(string, optional, tag = "6")]
    pub name: Option<String>,
    #[prost(string, optional, tag = "7")]
    pub image: Option<String>,
    #[prost(message, optional, tag = "8")]
    pub created_at: Option<Timestamp>,
    #[prost(message, optional, tag = "9")]
    pub updated_at: Option<Timestamp>,
}

#[derive(Clone, PartialEq, Message)]
pub struct Session {
    #[prost(string, tag = "1")]
    pub id: String,
    #[prost(string, tag = "2")]
    pub user_id: String,
    #[prost(message, optional, tag = "3")]
    pub expires_at: Option<Timestamp>,
    #[prost(message, optional, tag = "4")]
    pub created_at: Option<Timestamp>,
    #[prost(string, optional, tag = "5")]
    pub ip_address: Option<String>,
    #[prost(string, optional, tag = "6")]
    pub user_agent: Option<String>,
}

#[derive(Clone, PartialEq, Message)]
pub struct Organization {
    #[prost(string, tag = "1")]
    pub id: String,
    #[prost(string, tag = "2")]
    pub name: String,
    #[prost(string, tag = "3")]
    pub slug: String,
    #[prost(string, optional, tag = "4")]
    pub logo: Option<String>,
    #[prost(string, optional, tag = "5")]
    pub role: Option<String>,
    #[prost(message, optional, tag = "6")]
    pub created_at: Option<Timestamp>,
    #[prost(message, optional, tag = "7")]
    pub updated_at: Option<Timestamp>,
}

#[derive(Clone, PartialEq, Message)]
pub struct Member {
    #[prost(string, tag = "1")]
    pub id: String,
    #[prost(string, tag = "2")]
    pub organization_id: String,
    #[prost(string, tag = "3")]
    pub user_id: String,
    #[prost(string, tag = "4")]
    pub role: String,
    #[prost(message, optional, tag = "5")]
    pub user: Option<User>,
    #[prost(message, optional, tag = "6")]
    pub created_at: Option<Timestamp>,
    #[prost(message, optional, tag = "7")]
    pub updated_at: Option<Timestamp>,
}

#[derive(Clone, PartialEq, Message)]
pub struct ApiKey {
    #[prost(string, tag = "1")]
    pub id: String,
    #[prost(string, tag = "2")]
    pub user_id: String,
    #[prost(string, optional, tag = "3")]
    pub organization_id: Option<String>,
    #[prost(string, tag = "4")]
    pub name: String,
    #[prost(string, tag = "5")]
    pub prefix: String,
    #[prost(string, repeated, tag = "6")]
    pub scopes: Vec<String>,
    #[prost(message, optional, tag = "7")]
    pub expires_at: Option<Timestamp>,
    #[prost(message, optional, tag = "8")]
    pub last_used_at: Option<Timestamp>,
    #[prost(message, optional, tag = "9")]
    pub created_at: Option<Timestamp>,
}

#[derive(Clone, PartialEq, Message)]
pub struct MessageResponse {
    #[prost(string, tag = "1")]
    pub message: String,
}

#[derive(Clone, PartialEq, Message)]
pub struct SignupRequest {
    #[prost(string, tag = "1")]
    pub email: String,
    #[prost(string, tag = "2")]
    pub password: String,
    #[prost(string, optional, tag = "3")]
    pub name: Option<String>,
    #[prost(string, optional, tag = "4")]
    pub ip_address: Option<String>,
    #[prost(string, optional, tag = "5")]
    pub user_agent: Option<String>,
}

#[derive(Clone, PartialEq, Message)]
pub struct SigninRequest {
    #[prost(string, tag = "1")]
    pub email: String,
    #[prost(string, tag = "2")]
    pub password: String,
    #[prost(string, optional, tag = "3")]
    pub ip_address: Option<String>,
    #[prost(string, optional, tag = "4")]
    pub user_agent: Option<String>,
}

#[derive(Clone, PartialEq, Message)]
pub struct SignoutRequest {}

#[derive(Clone, PartialEq, Message)]
pub struct RefreshSessionRequest {}

#[derive(Clone, PartialEq, Message)]
pub struct Setup2faRequest {}

#[derive(Clone, PartialEq, Message)]
pub struct Verify2faRequest {
    #[prost(string, tag = "1")]
    pub code: String,
}

#[derive(Clone, PartialEq, Message)]
pub struct Disable2faRequest {
    #[prost(string, tag = "1")]
    pub code: String,
}

#[derive(Clone, PartialEq, Message)]
pub struct ChangePasswordRequest {
    #[prost(string, tag = "1")]
    pub current_password: String,
    #[prost(string, tag = "2")]
    pub new_password: String,
    #[prost(bool, tag = "3")]
    pub revoke_other_sessions: bool,
}

#[derive(Clone, PartialEq, Message)]
pub struct AuthResponse {
    #[prost(message, optional, tag = "1")]
    pub user: Option<User>,
    #[prost(message, optional, tag = "2")]
    pub session: Option<Session>,
    #[prost(string, tag = "3")]
    pub token: String,
}

#[derive(Clone, PartialEq, Message)]
pub struct RefreshSessionResponse {
    #[prost(message, optional, tag = "1")]
    pub session: Option<Session>,
    #[prost(string, tag = "2")]
    pub token: String,
}

#[derive(Clone, PartialEq, Message)]
pub struct TwoFactorSetupResponse {
    #[prost(string, tag = "1")]
    pub secret: String,
    #[prost(string, tag = "2")]
    pub otpauth_url: String,
    #[prost(string, repeated, tag = "3")]
    pub backup_codes: Vec<String>,
}

#[derive(Clone, PartialEq, Message)]
pub struct GetCurrentUserRequest {}

#[derive(Clone, PartialEq, Message)]
pub struct UpdateCurrentUserRequest {
    #[prost(string, optional, tag = "1")]
    pub name: Option<String>,
    #[prost(string, optional, tag = "2")]
    pub phone: Option<String>,
}

#[derive(Clone, PartialEq, Message)]
pub struct UserResponse {
    #[prost(message, optional, tag = "1")]
    pub user: Option<User>,
}

#[derive(Clone, PartialEq, Message)]
pub struct ListSessionsRequest {}

#[derive(Clone, PartialEq, Message)]
pub struct ListSessionsResponse {
    #[prost(message, repeated, tag = "1")]
    pub sessions: Vec<Session>,
}

#[derive(Clone, PartialEq, Message)]
pub struct RevokeSessionRequest {
    #[prost(string, tag = "1")]
    pub session_id: String,
}

#[derive(Clone, PartialEq, Message)]
pub struct RevokeAllSessionsRequest {}

#[derive(Clone, PartialEq, Message)]
pub struct ListOrganizationsRequest {}

#[derive(Clone, PartialEq, Message)]
pub struct ListOrganizationsResponse {
    #[prost(message, repeated, tag = "1")]
    pub organizations: Vec<Organization>,
}

#[derive(Clone, PartialEq, Message)]
pub struct CreateOrganizationRequest {
    #[prost(string, tag = "1")]
    pub name: String,
    #[prost(string, tag = "2")]
    pub slug: String,
}

#[derive(Clone, PartialEq, Message)]
pub struct GetOrganizationRequest {
    #[prost(string, tag = "1")]
    pub slug: String,
}

#[derive(Clone, PartialEq, Message)]
pub struct UpdateOrganizationRequest {
    #[prost(string, tag = "1")]
    pub id: String,
    #[prost(string, optional, tag = "2")]
    pub name: Option<String>,
    #[prost(string, optional, tag = "3")]
    pub logo: Option<String>,
}

#[derive(Clone, PartialEq, Message)]
pub struct DeleteOrganizationRequest {
    #[prost(string, tag = "1")]
    pub id: String,
}

#[derive(Clone, PartialEq, Message)]
pub struct OrganizationResponse {
    #[prost(message, optional, tag = "1")]
    pub organization: Option<Organization>,
}

#[derive(Clone, PartialEq, Message)]
pub struct ListMembersRequest {
    #[prost(string, tag = "1")]
    pub organization_id: String,
}

#[derive(Clone, PartialEq, Message)]
pub struct ListMembersResponse {
    #[prost(message, repeated, tag = "1")]
    pub members: Vec<Member>,
}

#[derive(Clone, PartialEq, Message)]
pub struct AddMemberRequest {
    #[prost(string, tag = "1")]
    pub organization_id: String,
    #[prost(string, tag = "2")]
    pub user_id: String,
    #[prost(string, tag = "3")]
    pub role: String,
}

#[derive(Clone, PartialEq, Message)]
pub struct UpdateMemberRequest {
    #[prost(string, tag = "1")]
    pub organization_id: String,
    #[prost(string, tag = "2")]
    pub user_id: String,
    #[prost(string, tag = "3")]
    pub role: String,
}

#[derive(Clone, PartialEq, Message)]
pub struct RemoveMemberRequest {
    #[prost(string, tag = "1")]
    pub organization_id: String,
    #[prost(string, tag = "2")]
    pub user_id: String,
}

#[derive(Clone, PartialEq, Message)]
pub struct MemberResponse {
    #[prost(message, optional, tag = "1")]
    pub member: Option<Member>,
}

#[derive(Clone, PartialEq, Message)]
pub struct ListApiKeysRequest {}

#[derive(Clone, PartialEq, Message)]
pub struct ListApiKeysResponse {
    #[prost(message, repeated, tag = "1")]
    pub api_keys: Vec<ApiKey>,
}

#[derive(Clone, PartialEq, Message)]
pub struct CreateApiKeyRequest {
    #[prost(string, tag = "1")]
    pub name: String,
    #[prost(string, repeated, tag = "2")]
    pub scopes: Vec<String>,
    #[prost(int64, optional, tag = "3")]
    pub expires_in_days: Option<i64>,
}

#[derive(Clone, PartialEq, Message)]
pub struct CreateApiKeyResponse {
    #[prost(message, optional, tag = "1")]
    pub api_key: Option<ApiKey>,
    #[prost(string, tag = "2")]
    pub secret: String,
}

#[derive(Clone, PartialEq, Message)]
pub struct UpdateApiKeyRequest {
    #[prost(string, tag = "1")]
    pub id: String,
    #[prost(string, optional, tag = "2")]
    pub name: Option<String>,
    #[prost(string, repeated, tag = "3")]
    pub scopes: Vec<String>,
}

#[derive(Clone, PartialEq, Message)]
pub struct DeleteApiKeyRequest {
    #[prost(string, tag = "1")]
    pub id: String,
}

#[derive(Clone, PartialEq, Message)]
pub struct ApiKeyResponse {
    #[prost(message, optional, tag = "1")]
    pub api_key: Option<ApiKey>,
}

#[derive(Clone, PartialEq, Message)]
pub struct HealthCheckRequest {}

#[derive(Clone, PartialEq, Message)]
pub struct HealthCheckResponse {
    #[prost(string, tag = "1")]
    pub status: String,
    #[prost(string, tag = "2")]
    pub version: String,
}

pub mod auth_service_server {
    use super::*;
    use tonic::{Request, Response, Status};

    #[tonic::async_trait]
    pub trait AuthService: Send + Sync + 'static {
        async fn signup(
            &self,
            request: Request<SignupRequest>,
        ) -> Result<Response<AuthResponse>, Status>;
        async fn signin(
            &self,
            request: Request<SigninRequest>,
        ) -> Result<Response<AuthResponse>, Status>;
        async fn signout(
            &self,
            request: Request<SignoutRequest>,
        ) -> Result<Response<MessageResponse>, Status>;
        async fn refresh_session(
            &self,
            request: Request<RefreshSessionRequest>,
        ) -> Result<Response<RefreshSessionResponse>, Status>;
        async fn setup2fa(
            &self,
            request: Request<Setup2faRequest>,
        ) -> Result<Response<TwoFactorSetupResponse>, Status>;
        async fn verify2fa(
            &self,
            request: Request<Verify2faRequest>,
        ) -> Result<Response<MessageResponse>, Status>;
        async fn disable2fa(
            &self,
            request: Request<Disable2faRequest>,
        ) -> Result<Response<MessageResponse>, Status>;
        async fn change_password(
            &self,
            request: Request<ChangePasswordRequest>,
        ) -> Result<Response<MessageResponse>, Status>;
    }

    pub struct AuthServiceServer<T: AuthService> {
        inner: std::sync::Arc<T>,
    }

    impl<T: AuthService> AuthServiceServer<T> {
        pub fn new(inner: T) -> Self {
            Self {
                inner: std::sync::Arc::new(inner),
            }
        }

        pub fn inner(&self) -> &T {
            &self.inner
        }
    }

    impl<T: AuthService> Clone for AuthServiceServer<T> {
        fn clone(&self) -> Self {
            Self {
                inner: self.inner.clone(),
            }
        }
    }

    impl<T: AuthService> tonic::server::NamedService for AuthServiceServer<T> {
        const NAME: &'static str = "tsa.v1.AuthService";
    }

    impl<T, B> tower_service::Service<http::Request<B>> for AuthServiceServer<T>
    where
        T: AuthService,
        B: http_body::Body + Send + 'static,
        B::Error: Into<Box<dyn std::error::Error + Send + Sync>> + Send + 'static,
    {
        type Response = http::Response<tonic::body::Body>;
        type Error = std::convert::Infallible;
        type Future = std::pin::Pin<
            Box<
                dyn std::future::Future<Output = Result<Self::Response, Self::Error>>
                    + Send
                    + 'static,
            >,
        >;

        fn poll_ready(
            &mut self,
            _cx: &mut std::task::Context<'_>,
        ) -> std::task::Poll<Result<(), Self::Error>> {
            std::task::Poll::Ready(Ok(()))
        }

        fn call(&mut self, req: http::Request<B>) -> Self::Future {
            let inner = self.inner.clone();
            match req.uri().path() {
                "/tsa.v1.AuthService/Signup" => {
                    let inner = inner.clone();
                    Box::pin(async move {
                        let mut grpc = tonic::server::Grpc::new(tonic_prost::ProstCodec::default());
                        let res = grpc.unary(SignupSvc(inner), req).await;
                        Ok(res)
                    })
                }
                "/tsa.v1.AuthService/Signin" => {
                    let inner = inner.clone();
                    Box::pin(async move {
                        let mut grpc = tonic::server::Grpc::new(tonic_prost::ProstCodec::default());
                        let res = grpc.unary(SigninSvc(inner), req).await;
                        Ok(res)
                    })
                }
                "/tsa.v1.AuthService/Signout" => {
                    let inner = inner.clone();
                    Box::pin(async move {
                        let mut grpc = tonic::server::Grpc::new(tonic_prost::ProstCodec::default());
                        let res = grpc.unary(SignoutSvc(inner), req).await;
                        Ok(res)
                    })
                }
                "/tsa.v1.AuthService/RefreshSession" => {
                    let inner = inner.clone();
                    Box::pin(async move {
                        let mut grpc = tonic::server::Grpc::new(tonic_prost::ProstCodec::default());
                        let res = grpc.unary(RefreshSessionSvc(inner), req).await;
                        Ok(res)
                    })
                }
                "/tsa.v1.AuthService/Setup2fa" => {
                    let inner = inner.clone();
                    Box::pin(async move {
                        let mut grpc = tonic::server::Grpc::new(tonic_prost::ProstCodec::default());
                        let res = grpc.unary(Setup2faSvc(inner), req).await;
                        Ok(res)
                    })
                }
                "/tsa.v1.AuthService/Verify2fa" => {
                    let inner = inner.clone();
                    Box::pin(async move {
                        let mut grpc = tonic::server::Grpc::new(tonic_prost::ProstCodec::default());
                        let res = grpc.unary(Verify2faSvc(inner), req).await;
                        Ok(res)
                    })
                }
                "/tsa.v1.AuthService/Disable2fa" => {
                    let inner = inner.clone();
                    Box::pin(async move {
                        let mut grpc = tonic::server::Grpc::new(tonic_prost::ProstCodec::default());
                        let res = grpc.unary(Disable2faSvc(inner), req).await;
                        Ok(res)
                    })
                }
                "/tsa.v1.AuthService/ChangePassword" => {
                    let inner = inner.clone();
                    Box::pin(async move {
                        let mut grpc = tonic::server::Grpc::new(tonic_prost::ProstCodec::default());
                        let res = grpc.unary(ChangePasswordSvc(inner), req).await;
                        Ok(res)
                    })
                }
                _ => Box::pin(async move {
                    let mut res = http::Response::new(tonic::body::Body::empty());
                    *res.status_mut() = http::StatusCode::OK;
                    res.headers_mut().insert(
                        http::header::CONTENT_TYPE,
                        http::HeaderValue::from_static("application/grpc"),
                    );
                    res.headers_mut()
                        .insert("grpc-status", http::HeaderValue::from_static("12"));
                    res.headers_mut().insert(
                        "grpc-message",
                        http::HeaderValue::from_static("Unimplemented"),
                    );
                    Ok(res)
                }),
            }
        }
    }

    struct SignupSvc<T>(std::sync::Arc<T>);
    impl<T: AuthService> tonic::server::UnaryService<SignupRequest> for SignupSvc<T> {
        type Response = AuthResponse;
        type Future = std::pin::Pin<
            Box<
                dyn std::future::Future<
                        Output = Result<tonic::Response<Self::Response>, tonic::Status>,
                    > + Send
                    + 'static,
            >,
        >;
        fn call(&mut self, request: tonic::Request<SignupRequest>) -> Self::Future {
            let inner = self.0.clone();
            Box::pin(async move { inner.signup(request).await })
        }
    }

    struct SigninSvc<T>(std::sync::Arc<T>);
    impl<T: AuthService> tonic::server::UnaryService<SigninRequest> for SigninSvc<T> {
        type Response = AuthResponse;
        type Future = std::pin::Pin<
            Box<
                dyn std::future::Future<
                        Output = Result<tonic::Response<Self::Response>, tonic::Status>,
                    > + Send
                    + 'static,
            >,
        >;
        fn call(&mut self, request: tonic::Request<SigninRequest>) -> Self::Future {
            let inner = self.0.clone();
            Box::pin(async move { inner.signin(request).await })
        }
    }

    struct SignoutSvc<T>(std::sync::Arc<T>);
    impl<T: AuthService> tonic::server::UnaryService<SignoutRequest> for SignoutSvc<T> {
        type Response = MessageResponse;
        type Future = std::pin::Pin<
            Box<
                dyn std::future::Future<
                        Output = Result<tonic::Response<Self::Response>, tonic::Status>,
                    > + Send
                    + 'static,
            >,
        >;
        fn call(&mut self, request: tonic::Request<SignoutRequest>) -> Self::Future {
            let inner = self.0.clone();
            Box::pin(async move { inner.signout(request).await })
        }
    }

    struct RefreshSessionSvc<T>(std::sync::Arc<T>);
    impl<T: AuthService> tonic::server::UnaryService<RefreshSessionRequest> for RefreshSessionSvc<T> {
        type Response = RefreshSessionResponse;
        type Future = std::pin::Pin<
            Box<
                dyn std::future::Future<
                        Output = Result<tonic::Response<Self::Response>, tonic::Status>,
                    > + Send
                    + 'static,
            >,
        >;
        fn call(&mut self, request: tonic::Request<RefreshSessionRequest>) -> Self::Future {
            let inner = self.0.clone();
            Box::pin(async move { inner.refresh_session(request).await })
        }
    }

    struct Setup2faSvc<T>(std::sync::Arc<T>);
    impl<T: AuthService> tonic::server::UnaryService<Setup2faRequest> for Setup2faSvc<T> {
        type Response = TwoFactorSetupResponse;
        type Future = std::pin::Pin<
            Box<
                dyn std::future::Future<
                        Output = Result<tonic::Response<Self::Response>, tonic::Status>,
                    > + Send
                    + 'static,
            >,
        >;
        fn call(&mut self, request: tonic::Request<Setup2faRequest>) -> Self::Future {
            let inner = self.0.clone();
            Box::pin(async move { inner.setup2fa(request).await })
        }
    }

    struct Verify2faSvc<T>(std::sync::Arc<T>);
    impl<T: AuthService> tonic::server::UnaryService<Verify2faRequest> for Verify2faSvc<T> {
        type Response = MessageResponse;
        type Future = std::pin::Pin<
            Box<
                dyn std::future::Future<
                        Output = Result<tonic::Response<Self::Response>, tonic::Status>,
                    > + Send
                    + 'static,
            >,
        >;
        fn call(&mut self, request: tonic::Request<Verify2faRequest>) -> Self::Future {
            let inner = self.0.clone();
            Box::pin(async move { inner.verify2fa(request).await })
        }
    }

    struct Disable2faSvc<T>(std::sync::Arc<T>);
    impl<T: AuthService> tonic::server::UnaryService<Disable2faRequest> for Disable2faSvc<T> {
        type Response = MessageResponse;
        type Future = std::pin::Pin<
            Box<
                dyn std::future::Future<
                        Output = Result<tonic::Response<Self::Response>, tonic::Status>,
                    > + Send
                    + 'static,
            >,
        >;
        fn call(&mut self, request: tonic::Request<Disable2faRequest>) -> Self::Future {
            let inner = self.0.clone();
            Box::pin(async move { inner.disable2fa(request).await })
        }
    }

    struct ChangePasswordSvc<T>(std::sync::Arc<T>);
    impl<T: AuthService> tonic::server::UnaryService<ChangePasswordRequest> for ChangePasswordSvc<T> {
        type Response = MessageResponse;
        type Future = std::pin::Pin<
            Box<
                dyn std::future::Future<
                        Output = Result<tonic::Response<Self::Response>, tonic::Status>,
                    > + Send
                    + 'static,
            >,
        >;
        fn call(&mut self, request: tonic::Request<ChangePasswordRequest>) -> Self::Future {
            let inner = self.0.clone();
            Box::pin(async move { inner.change_password(request).await })
        }
    }
}

pub mod auth_service_client {
    use super::*;

    #[derive(Clone)]
    pub struct AuthServiceClient<T> {
        inner: tonic::client::Grpc<T>,
    }

    impl AuthServiceClient<tonic::transport::Channel> {
        pub async fn connect<D>(dst: D) -> Result<Self, tonic::transport::Error>
        where
            D: TryInto<tonic::transport::Endpoint>,
            D::Error: Into<Box<dyn std::error::Error + Send + Sync>>,
        {
            let conn = tonic::transport::Endpoint::new(dst)?.connect().await?;
            Ok(Self::new(conn))
        }
    }

    impl<T> AuthServiceClient<T>
    where
        T: tonic::client::GrpcService<tonic::body::Body>,
        T::Error: Into<Box<dyn std::error::Error + Send + Sync>>,
        T::ResponseBody: http_body::Body<Data = bytes::Bytes> + Send + 'static,
        <T::ResponseBody as http_body::Body>::Error:
            Into<Box<dyn std::error::Error + Send + Sync>> + Send,
    {
        pub fn new(inner: T) -> Self {
            let inner = tonic::client::Grpc::new(inner);
            Self { inner }
        }

        pub async fn signup(
            &mut self,
            request: impl tonic::IntoRequest<SignupRequest>,
        ) -> Result<tonic::Response<AuthResponse>, tonic::Status> {
            self.inner
                .ready()
                .await
                .map_err(|e| tonic::Status::unknown(format!("Service not ready: {}", e.into())))?;
            let codec = tonic_prost::ProstCodec::default();
            let path = http::uri::PathAndQuery::from_static("/tsa.v1.AuthService/Signup");
            self.inner.unary(request.into_request(), path, codec).await
        }

        pub async fn signin(
            &mut self,
            request: impl tonic::IntoRequest<SigninRequest>,
        ) -> Result<tonic::Response<AuthResponse>, tonic::Status> {
            self.inner
                .ready()
                .await
                .map_err(|e| tonic::Status::unknown(format!("Service not ready: {}", e.into())))?;
            let codec = tonic_prost::ProstCodec::default();
            let path = http::uri::PathAndQuery::from_static("/tsa.v1.AuthService/Signin");
            self.inner.unary(request.into_request(), path, codec).await
        }

        pub async fn signout(
            &mut self,
            request: impl tonic::IntoRequest<SignoutRequest>,
        ) -> Result<tonic::Response<MessageResponse>, tonic::Status> {
            self.inner
                .ready()
                .await
                .map_err(|e| tonic::Status::unknown(format!("Service not ready: {}", e.into())))?;
            let codec = tonic_prost::ProstCodec::default();
            let path = http::uri::PathAndQuery::from_static("/tsa.v1.AuthService/Signout");
            self.inner.unary(request.into_request(), path, codec).await
        }

        pub async fn refresh_session(
            &mut self,
            request: impl tonic::IntoRequest<RefreshSessionRequest>,
        ) -> Result<tonic::Response<RefreshSessionResponse>, tonic::Status> {
            self.inner
                .ready()
                .await
                .map_err(|e| tonic::Status::unknown(format!("Service not ready: {}", e.into())))?;
            let codec = tonic_prost::ProstCodec::default();
            let path = http::uri::PathAndQuery::from_static("/tsa.v1.AuthService/RefreshSession");
            self.inner.unary(request.into_request(), path, codec).await
        }

        pub async fn setup2fa(
            &mut self,
            request: impl tonic::IntoRequest<Setup2faRequest>,
        ) -> Result<tonic::Response<TwoFactorSetupResponse>, tonic::Status> {
            self.inner
                .ready()
                .await
                .map_err(|e| tonic::Status::unknown(format!("Service not ready: {}", e.into())))?;
            let codec = tonic_prost::ProstCodec::default();
            let path = http::uri::PathAndQuery::from_static("/tsa.v1.AuthService/Setup2fa");
            self.inner.unary(request.into_request(), path, codec).await
        }

        pub async fn verify2fa(
            &mut self,
            request: impl tonic::IntoRequest<Verify2faRequest>,
        ) -> Result<tonic::Response<MessageResponse>, tonic::Status> {
            self.inner
                .ready()
                .await
                .map_err(|e| tonic::Status::unknown(format!("Service not ready: {}", e.into())))?;
            let codec = tonic_prost::ProstCodec::default();
            let path = http::uri::PathAndQuery::from_static("/tsa.v1.AuthService/Verify2fa");
            self.inner.unary(request.into_request(), path, codec).await
        }

        pub async fn disable2fa(
            &mut self,
            request: impl tonic::IntoRequest<Disable2faRequest>,
        ) -> Result<tonic::Response<MessageResponse>, tonic::Status> {
            self.inner
                .ready()
                .await
                .map_err(|e| tonic::Status::unknown(format!("Service not ready: {}", e.into())))?;
            let codec = tonic_prost::ProstCodec::default();
            let path = http::uri::PathAndQuery::from_static("/tsa.v1.AuthService/Disable2fa");
            self.inner.unary(request.into_request(), path, codec).await
        }

        pub async fn change_password(
            &mut self,
            request: impl tonic::IntoRequest<ChangePasswordRequest>,
        ) -> Result<tonic::Response<MessageResponse>, tonic::Status> {
            self.inner
                .ready()
                .await
                .map_err(|e| tonic::Status::unknown(format!("Service not ready: {}", e.into())))?;
            let codec = tonic_prost::ProstCodec::default();
            let path = http::uri::PathAndQuery::from_static("/tsa.v1.AuthService/ChangePassword");
            self.inner.unary(request.into_request(), path, codec).await
        }
    }
}

pub mod user_service_server {
    use super::*;
    use tonic::{Request, Response, Status};

    #[tonic::async_trait]
    pub trait UserService: Send + Sync + 'static {
        async fn get_current_user(
            &self,
            request: Request<GetCurrentUserRequest>,
        ) -> Result<Response<UserResponse>, Status>;
        async fn update_current_user(
            &self,
            request: Request<UpdateCurrentUserRequest>,
        ) -> Result<Response<UserResponse>, Status>;
    }

    pub struct UserServiceServer<T: UserService> {
        inner: std::sync::Arc<T>,
    }

    impl<T: UserService> UserServiceServer<T> {
        pub fn new(inner: T) -> Self {
            Self {
                inner: std::sync::Arc::new(inner),
            }
        }
    }

    impl<T: UserService> Clone for UserServiceServer<T> {
        fn clone(&self) -> Self {
            Self {
                inner: self.inner.clone(),
            }
        }
    }

    impl<T: UserService> tonic::server::NamedService for UserServiceServer<T> {
        const NAME: &'static str = "tsa.v1.UserService";
    }

    impl<T, B> tower_service::Service<http::Request<B>> for UserServiceServer<T>
    where
        T: UserService,
        B: http_body::Body + Send + 'static,
        B::Error: Into<Box<dyn std::error::Error + Send + Sync>> + Send + 'static,
    {
        type Response = http::Response<tonic::body::Body>;
        type Error = std::convert::Infallible;
        type Future = std::pin::Pin<
            Box<
                dyn std::future::Future<Output = Result<Self::Response, Self::Error>>
                    + Send
                    + 'static,
            >,
        >;

        fn poll_ready(
            &mut self,
            _cx: &mut std::task::Context<'_>,
        ) -> std::task::Poll<Result<(), Self::Error>> {
            std::task::Poll::Ready(Ok(()))
        }

        fn call(&mut self, req: http::Request<B>) -> Self::Future {
            let inner = self.inner.clone();
            match req.uri().path() {
                "/tsa.v1.UserService/GetCurrentUser" => {
                    let inner = inner.clone();
                    Box::pin(async move {
                        let mut grpc = tonic::server::Grpc::new(tonic_prost::ProstCodec::default());
                        let res = grpc.unary(GetCurrentUserSvc(inner), req).await;
                        Ok(res)
                    })
                }
                "/tsa.v1.UserService/UpdateCurrentUser" => {
                    let inner = inner.clone();
                    Box::pin(async move {
                        let mut grpc = tonic::server::Grpc::new(tonic_prost::ProstCodec::default());
                        let res = grpc.unary(UpdateCurrentUserSvc(inner), req).await;
                        Ok(res)
                    })
                }
                _ => Box::pin(async move {
                    let mut res = http::Response::new(tonic::body::Body::empty());
                    *res.status_mut() = http::StatusCode::OK;
                    res.headers_mut().insert(
                        http::header::CONTENT_TYPE,
                        http::HeaderValue::from_static("application/grpc"),
                    );
                    res.headers_mut()
                        .insert("grpc-status", http::HeaderValue::from_static("12"));
                    res.headers_mut().insert(
                        "grpc-message",
                        http::HeaderValue::from_static("Unimplemented"),
                    );
                    Ok(res)
                }),
            }
        }
    }

    struct GetCurrentUserSvc<T>(std::sync::Arc<T>);
    impl<T: UserService> tonic::server::UnaryService<GetCurrentUserRequest> for GetCurrentUserSvc<T> {
        type Response = UserResponse;
        type Future = std::pin::Pin<
            Box<
                dyn std::future::Future<
                        Output = Result<tonic::Response<Self::Response>, tonic::Status>,
                    > + Send
                    + 'static,
            >,
        >;
        fn call(&mut self, request: tonic::Request<GetCurrentUserRequest>) -> Self::Future {
            let inner = self.0.clone();
            Box::pin(async move { inner.get_current_user(request).await })
        }
    }

    struct UpdateCurrentUserSvc<T>(std::sync::Arc<T>);
    impl<T: UserService> tonic::server::UnaryService<UpdateCurrentUserRequest>
        for UpdateCurrentUserSvc<T>
    {
        type Response = UserResponse;
        type Future = std::pin::Pin<
            Box<
                dyn std::future::Future<
                        Output = Result<tonic::Response<Self::Response>, tonic::Status>,
                    > + Send
                    + 'static,
            >,
        >;
        fn call(&mut self, request: tonic::Request<UpdateCurrentUserRequest>) -> Self::Future {
            let inner = self.0.clone();
            Box::pin(async move { inner.update_current_user(request).await })
        }
    }
}

pub mod user_service_client {
    use super::*;

    #[derive(Clone)]
    pub struct UserServiceClient<T> {
        inner: tonic::client::Grpc<T>,
    }

    impl UserServiceClient<tonic::transport::Channel> {
        pub async fn connect<D>(dst: D) -> Result<Self, tonic::transport::Error>
        where
            D: TryInto<tonic::transport::Endpoint>,
            D::Error: Into<Box<dyn std::error::Error + Send + Sync>>,
        {
            let conn = tonic::transport::Endpoint::new(dst)?.connect().await?;
            Ok(Self::new(conn))
        }
    }

    impl<T> UserServiceClient<T>
    where
        T: tonic::client::GrpcService<tonic::body::Body>,
        T::Error: Into<Box<dyn std::error::Error + Send + Sync>>,
        T::ResponseBody: http_body::Body<Data = bytes::Bytes> + Send + 'static,
        <T::ResponseBody as http_body::Body>::Error:
            Into<Box<dyn std::error::Error + Send + Sync>> + Send,
    {
        pub fn new(inner: T) -> Self {
            let inner = tonic::client::Grpc::new(inner);
            Self { inner }
        }

        pub async fn get_current_user(
            &mut self,
            request: impl tonic::IntoRequest<GetCurrentUserRequest>,
        ) -> Result<tonic::Response<UserResponse>, tonic::Status> {
            self.inner
                .ready()
                .await
                .map_err(|e| tonic::Status::unknown(format!("Service not ready: {}", e.into())))?;
            let codec = tonic_prost::ProstCodec::default();
            let path = http::uri::PathAndQuery::from_static("/tsa.v1.UserService/GetCurrentUser");
            self.inner.unary(request.into_request(), path, codec).await
        }

        pub async fn update_current_user(
            &mut self,
            request: impl tonic::IntoRequest<UpdateCurrentUserRequest>,
        ) -> Result<tonic::Response<UserResponse>, tonic::Status> {
            self.inner
                .ready()
                .await
                .map_err(|e| tonic::Status::unknown(format!("Service not ready: {}", e.into())))?;
            let codec = tonic_prost::ProstCodec::default();
            let path =
                http::uri::PathAndQuery::from_static("/tsa.v1.UserService/UpdateCurrentUser");
            self.inner.unary(request.into_request(), path, codec).await
        }
    }
}

pub mod session_service_server {
    use super::*;
    use tonic::{Request, Response, Status};

    #[tonic::async_trait]
    pub trait SessionService: Send + Sync + 'static {
        async fn list_sessions(
            &self,
            request: Request<ListSessionsRequest>,
        ) -> Result<Response<ListSessionsResponse>, Status>;
        async fn revoke_session(
            &self,
            request: Request<RevokeSessionRequest>,
        ) -> Result<Response<MessageResponse>, Status>;
        async fn revoke_all_sessions(
            &self,
            request: Request<RevokeAllSessionsRequest>,
        ) -> Result<Response<MessageResponse>, Status>;
    }

    pub struct SessionServiceServer<T: SessionService> {
        inner: std::sync::Arc<T>,
    }

    impl<T: SessionService> SessionServiceServer<T> {
        pub fn new(inner: T) -> Self {
            Self {
                inner: std::sync::Arc::new(inner),
            }
        }
    }

    impl<T: SessionService> Clone for SessionServiceServer<T> {
        fn clone(&self) -> Self {
            Self {
                inner: self.inner.clone(),
            }
        }
    }

    impl<T: SessionService> tonic::server::NamedService for SessionServiceServer<T> {
        const NAME: &'static str = "tsa.v1.SessionService";
    }

    impl<T, B> tower_service::Service<http::Request<B>> for SessionServiceServer<T>
    where
        T: SessionService,
        B: http_body::Body + Send + 'static,
        B::Error: Into<Box<dyn std::error::Error + Send + Sync>> + Send + 'static,
    {
        type Response = http::Response<tonic::body::Body>;
        type Error = std::convert::Infallible;
        type Future = std::pin::Pin<
            Box<
                dyn std::future::Future<Output = Result<Self::Response, Self::Error>>
                    + Send
                    + 'static,
            >,
        >;

        fn poll_ready(
            &mut self,
            _cx: &mut std::task::Context<'_>,
        ) -> std::task::Poll<Result<(), Self::Error>> {
            std::task::Poll::Ready(Ok(()))
        }

        fn call(&mut self, req: http::Request<B>) -> Self::Future {
            let inner = self.inner.clone();
            match req.uri().path() {
                "/tsa.v1.SessionService/ListSessions" => {
                    let inner = inner.clone();
                    Box::pin(async move {
                        let mut grpc = tonic::server::Grpc::new(tonic_prost::ProstCodec::default());
                        let res = grpc.unary(ListSessionsSvc(inner), req).await;
                        Ok(res)
                    })
                }
                "/tsa.v1.SessionService/RevokeSession" => {
                    let inner = inner.clone();
                    Box::pin(async move {
                        let mut grpc = tonic::server::Grpc::new(tonic_prost::ProstCodec::default());
                        let res = grpc.unary(RevokeSessionSvc(inner), req).await;
                        Ok(res)
                    })
                }
                "/tsa.v1.SessionService/RevokeAllSessions" => {
                    let inner = inner.clone();
                    Box::pin(async move {
                        let mut grpc = tonic::server::Grpc::new(tonic_prost::ProstCodec::default());
                        let res = grpc.unary(RevokeAllSessionsSvc(inner), req).await;
                        Ok(res)
                    })
                }
                _ => Box::pin(async move {
                    let mut res = http::Response::new(tonic::body::Body::empty());
                    *res.status_mut() = http::StatusCode::OK;
                    res.headers_mut().insert(
                        http::header::CONTENT_TYPE,
                        http::HeaderValue::from_static("application/grpc"),
                    );
                    res.headers_mut()
                        .insert("grpc-status", http::HeaderValue::from_static("12"));
                    res.headers_mut().insert(
                        "grpc-message",
                        http::HeaderValue::from_static("Unimplemented"),
                    );
                    Ok(res)
                }),
            }
        }
    }

    struct ListSessionsSvc<T>(std::sync::Arc<T>);
    impl<T: SessionService> tonic::server::UnaryService<ListSessionsRequest> for ListSessionsSvc<T> {
        type Response = ListSessionsResponse;
        type Future = std::pin::Pin<
            Box<
                dyn std::future::Future<
                        Output = Result<tonic::Response<Self::Response>, tonic::Status>,
                    > + Send
                    + 'static,
            >,
        >;
        fn call(&mut self, request: tonic::Request<ListSessionsRequest>) -> Self::Future {
            let inner = self.0.clone();
            Box::pin(async move { inner.list_sessions(request).await })
        }
    }

    struct RevokeSessionSvc<T>(std::sync::Arc<T>);
    impl<T: SessionService> tonic::server::UnaryService<RevokeSessionRequest> for RevokeSessionSvc<T> {
        type Response = MessageResponse;
        type Future = std::pin::Pin<
            Box<
                dyn std::future::Future<
                        Output = Result<tonic::Response<Self::Response>, tonic::Status>,
                    > + Send
                    + 'static,
            >,
        >;
        fn call(&mut self, request: tonic::Request<RevokeSessionRequest>) -> Self::Future {
            let inner = self.0.clone();
            Box::pin(async move { inner.revoke_session(request).await })
        }
    }

    struct RevokeAllSessionsSvc<T>(std::sync::Arc<T>);
    impl<T: SessionService> tonic::server::UnaryService<RevokeAllSessionsRequest>
        for RevokeAllSessionsSvc<T>
    {
        type Response = MessageResponse;
        type Future = std::pin::Pin<
            Box<
                dyn std::future::Future<
                        Output = Result<tonic::Response<Self::Response>, tonic::Status>,
                    > + Send
                    + 'static,
            >,
        >;
        fn call(&mut self, request: tonic::Request<RevokeAllSessionsRequest>) -> Self::Future {
            let inner = self.0.clone();
            Box::pin(async move { inner.revoke_all_sessions(request).await })
        }
    }
}

pub mod session_service_client {
    use super::*;

    #[derive(Clone)]
    pub struct SessionServiceClient<T> {
        inner: tonic::client::Grpc<T>,
    }

    impl SessionServiceClient<tonic::transport::Channel> {
        pub async fn connect<D>(dst: D) -> Result<Self, tonic::transport::Error>
        where
            D: TryInto<tonic::transport::Endpoint>,
            D::Error: Into<Box<dyn std::error::Error + Send + Sync>>,
        {
            let conn = tonic::transport::Endpoint::new(dst)?.connect().await?;
            Ok(Self::new(conn))
        }
    }

    impl<T> SessionServiceClient<T>
    where
        T: tonic::client::GrpcService<tonic::body::Body>,
        T::Error: Into<Box<dyn std::error::Error + Send + Sync>>,
        T::ResponseBody: http_body::Body<Data = bytes::Bytes> + Send + 'static,
        <T::ResponseBody as http_body::Body>::Error:
            Into<Box<dyn std::error::Error + Send + Sync>> + Send,
    {
        pub fn new(inner: T) -> Self {
            let inner = tonic::client::Grpc::new(inner);
            Self { inner }
        }

        pub async fn list_sessions(
            &mut self,
            request: impl tonic::IntoRequest<ListSessionsRequest>,
        ) -> Result<tonic::Response<ListSessionsResponse>, tonic::Status> {
            self.inner
                .ready()
                .await
                .map_err(|e| tonic::Status::unknown(format!("Service not ready: {}", e.into())))?;
            let codec = tonic_prost::ProstCodec::default();
            let path = http::uri::PathAndQuery::from_static("/tsa.v1.SessionService/ListSessions");
            self.inner.unary(request.into_request(), path, codec).await
        }

        pub async fn revoke_session(
            &mut self,
            request: impl tonic::IntoRequest<RevokeSessionRequest>,
        ) -> Result<tonic::Response<MessageResponse>, tonic::Status> {
            self.inner
                .ready()
                .await
                .map_err(|e| tonic::Status::unknown(format!("Service not ready: {}", e.into())))?;
            let codec = tonic_prost::ProstCodec::default();
            let path = http::uri::PathAndQuery::from_static("/tsa.v1.SessionService/RevokeSession");
            self.inner.unary(request.into_request(), path, codec).await
        }

        pub async fn revoke_all_sessions(
            &mut self,
            request: impl tonic::IntoRequest<RevokeAllSessionsRequest>,
        ) -> Result<tonic::Response<MessageResponse>, tonic::Status> {
            self.inner
                .ready()
                .await
                .map_err(|e| tonic::Status::unknown(format!("Service not ready: {}", e.into())))?;
            let codec = tonic_prost::ProstCodec::default();
            let path =
                http::uri::PathAndQuery::from_static("/tsa.v1.SessionService/RevokeAllSessions");
            self.inner.unary(request.into_request(), path, codec).await
        }
    }
}

pub mod organization_service_server {
    use super::*;
    use tonic::{Request, Response, Status};

    #[tonic::async_trait]
    pub trait OrganizationService: Send + Sync + 'static {
        async fn list_organizations(
            &self,
            request: Request<ListOrganizationsRequest>,
        ) -> Result<Response<ListOrganizationsResponse>, Status>;
        async fn create_organization(
            &self,
            request: Request<CreateOrganizationRequest>,
        ) -> Result<Response<OrganizationResponse>, Status>;
        async fn get_organization(
            &self,
            request: Request<GetOrganizationRequest>,
        ) -> Result<Response<OrganizationResponse>, Status>;
        async fn update_organization(
            &self,
            request: Request<UpdateOrganizationRequest>,
        ) -> Result<Response<OrganizationResponse>, Status>;
        async fn delete_organization(
            &self,
            request: Request<DeleteOrganizationRequest>,
        ) -> Result<Response<MessageResponse>, Status>;
        async fn list_members(
            &self,
            request: Request<ListMembersRequest>,
        ) -> Result<Response<ListMembersResponse>, Status>;
        async fn add_member(
            &self,
            request: Request<AddMemberRequest>,
        ) -> Result<Response<MemberResponse>, Status>;
        async fn update_member(
            &self,
            request: Request<UpdateMemberRequest>,
        ) -> Result<Response<MemberResponse>, Status>;
        async fn remove_member(
            &self,
            request: Request<RemoveMemberRequest>,
        ) -> Result<Response<MessageResponse>, Status>;
    }

    pub struct OrganizationServiceServer<T: OrganizationService> {
        inner: std::sync::Arc<T>,
    }

    impl<T: OrganizationService> OrganizationServiceServer<T> {
        pub fn new(inner: T) -> Self {
            Self {
                inner: std::sync::Arc::new(inner),
            }
        }
    }

    impl<T: OrganizationService> Clone for OrganizationServiceServer<T> {
        fn clone(&self) -> Self {
            Self {
                inner: self.inner.clone(),
            }
        }
    }

    impl<T: OrganizationService> tonic::server::NamedService for OrganizationServiceServer<T> {
        const NAME: &'static str = "tsa.v1.OrganizationService";
    }

    impl<T, B> tower_service::Service<http::Request<B>> for OrganizationServiceServer<T>
    where
        T: OrganizationService,
        B: http_body::Body + Send + 'static,
        B::Error: Into<Box<dyn std::error::Error + Send + Sync>> + Send + 'static,
    {
        type Response = http::Response<tonic::body::Body>;
        type Error = std::convert::Infallible;
        type Future = std::pin::Pin<
            Box<
                dyn std::future::Future<Output = Result<Self::Response, Self::Error>>
                    + Send
                    + 'static,
            >,
        >;

        fn poll_ready(
            &mut self,
            _cx: &mut std::task::Context<'_>,
        ) -> std::task::Poll<Result<(), Self::Error>> {
            std::task::Poll::Ready(Ok(()))
        }

        fn call(&mut self, req: http::Request<B>) -> Self::Future {
            let inner = self.inner.clone();
            match req.uri().path() {
                "/tsa.v1.OrganizationService/ListOrganizations" => {
                    let inner = inner.clone();
                    Box::pin(async move {
                        let mut grpc = tonic::server::Grpc::new(tonic_prost::ProstCodec::default());
                        let res = grpc.unary(ListOrganizationsSvc(inner), req).await;
                        Ok(res)
                    })
                }
                "/tsa.v1.OrganizationService/CreateOrganization" => {
                    let inner = inner.clone();
                    Box::pin(async move {
                        let mut grpc = tonic::server::Grpc::new(tonic_prost::ProstCodec::default());
                        let res = grpc.unary(CreateOrganizationSvc(inner), req).await;
                        Ok(res)
                    })
                }
                "/tsa.v1.OrganizationService/GetOrganization" => {
                    let inner = inner.clone();
                    Box::pin(async move {
                        let mut grpc = tonic::server::Grpc::new(tonic_prost::ProstCodec::default());
                        let res = grpc.unary(GetOrganizationSvc(inner), req).await;
                        Ok(res)
                    })
                }
                "/tsa.v1.OrganizationService/UpdateOrganization" => {
                    let inner = inner.clone();
                    Box::pin(async move {
                        let mut grpc = tonic::server::Grpc::new(tonic_prost::ProstCodec::default());
                        let res = grpc.unary(UpdateOrganizationSvc(inner), req).await;
                        Ok(res)
                    })
                }
                "/tsa.v1.OrganizationService/DeleteOrganization" => {
                    let inner = inner.clone();
                    Box::pin(async move {
                        let mut grpc = tonic::server::Grpc::new(tonic_prost::ProstCodec::default());
                        let res = grpc.unary(DeleteOrganizationSvc(inner), req).await;
                        Ok(res)
                    })
                }
                "/tsa.v1.OrganizationService/ListMembers" => {
                    let inner = inner.clone();
                    Box::pin(async move {
                        let mut grpc = tonic::server::Grpc::new(tonic_prost::ProstCodec::default());
                        let res = grpc.unary(ListMembersSvc(inner), req).await;
                        Ok(res)
                    })
                }
                "/tsa.v1.OrganizationService/AddMember" => {
                    let inner = inner.clone();
                    Box::pin(async move {
                        let mut grpc = tonic::server::Grpc::new(tonic_prost::ProstCodec::default());
                        let res = grpc.unary(AddMemberSvc(inner), req).await;
                        Ok(res)
                    })
                }
                "/tsa.v1.OrganizationService/UpdateMember" => {
                    let inner = inner.clone();
                    Box::pin(async move {
                        let mut grpc = tonic::server::Grpc::new(tonic_prost::ProstCodec::default());
                        let res = grpc.unary(UpdateMemberSvc(inner), req).await;
                        Ok(res)
                    })
                }
                "/tsa.v1.OrganizationService/RemoveMember" => {
                    let inner = inner.clone();
                    Box::pin(async move {
                        let mut grpc = tonic::server::Grpc::new(tonic_prost::ProstCodec::default());
                        let res = grpc.unary(RemoveMemberSvc(inner), req).await;
                        Ok(res)
                    })
                }
                _ => Box::pin(async move {
                    let mut res = http::Response::new(tonic::body::Body::empty());
                    *res.status_mut() = http::StatusCode::OK;
                    res.headers_mut().insert(
                        http::header::CONTENT_TYPE,
                        http::HeaderValue::from_static("application/grpc"),
                    );
                    res.headers_mut()
                        .insert("grpc-status", http::HeaderValue::from_static("12"));
                    res.headers_mut().insert(
                        "grpc-message",
                        http::HeaderValue::from_static("Unimplemented"),
                    );
                    Ok(res)
                }),
            }
        }
    }

    struct ListOrganizationsSvc<T>(std::sync::Arc<T>);
    impl<T: OrganizationService> tonic::server::UnaryService<ListOrganizationsRequest>
        for ListOrganizationsSvc<T>
    {
        type Response = ListOrganizationsResponse;
        type Future = std::pin::Pin<
            Box<
                dyn std::future::Future<
                        Output = Result<tonic::Response<Self::Response>, tonic::Status>,
                    > + Send
                    + 'static,
            >,
        >;
        fn call(&mut self, request: tonic::Request<ListOrganizationsRequest>) -> Self::Future {
            let inner = self.0.clone();
            Box::pin(async move { inner.list_organizations(request).await })
        }
    }

    struct CreateOrganizationSvc<T>(std::sync::Arc<T>);
    impl<T: OrganizationService> tonic::server::UnaryService<CreateOrganizationRequest>
        for CreateOrganizationSvc<T>
    {
        type Response = OrganizationResponse;
        type Future = std::pin::Pin<
            Box<
                dyn std::future::Future<
                        Output = Result<tonic::Response<Self::Response>, tonic::Status>,
                    > + Send
                    + 'static,
            >,
        >;
        fn call(&mut self, request: tonic::Request<CreateOrganizationRequest>) -> Self::Future {
            let inner = self.0.clone();
            Box::pin(async move { inner.create_organization(request).await })
        }
    }

    struct GetOrganizationSvc<T>(std::sync::Arc<T>);
    impl<T: OrganizationService> tonic::server::UnaryService<GetOrganizationRequest>
        for GetOrganizationSvc<T>
    {
        type Response = OrganizationResponse;
        type Future = std::pin::Pin<
            Box<
                dyn std::future::Future<
                        Output = Result<tonic::Response<Self::Response>, tonic::Status>,
                    > + Send
                    + 'static,
            >,
        >;
        fn call(&mut self, request: tonic::Request<GetOrganizationRequest>) -> Self::Future {
            let inner = self.0.clone();
            Box::pin(async move { inner.get_organization(request).await })
        }
    }

    struct UpdateOrganizationSvc<T>(std::sync::Arc<T>);
    impl<T: OrganizationService> tonic::server::UnaryService<UpdateOrganizationRequest>
        for UpdateOrganizationSvc<T>
    {
        type Response = OrganizationResponse;
        type Future = std::pin::Pin<
            Box<
                dyn std::future::Future<
                        Output = Result<tonic::Response<Self::Response>, tonic::Status>,
                    > + Send
                    + 'static,
            >,
        >;
        fn call(&mut self, request: tonic::Request<UpdateOrganizationRequest>) -> Self::Future {
            let inner = self.0.clone();
            Box::pin(async move { inner.update_organization(request).await })
        }
    }

    struct DeleteOrganizationSvc<T>(std::sync::Arc<T>);
    impl<T: OrganizationService> tonic::server::UnaryService<DeleteOrganizationRequest>
        for DeleteOrganizationSvc<T>
    {
        type Response = MessageResponse;
        type Future = std::pin::Pin<
            Box<
                dyn std::future::Future<
                        Output = Result<tonic::Response<Self::Response>, tonic::Status>,
                    > + Send
                    + 'static,
            >,
        >;
        fn call(&mut self, request: tonic::Request<DeleteOrganizationRequest>) -> Self::Future {
            let inner = self.0.clone();
            Box::pin(async move { inner.delete_organization(request).await })
        }
    }

    struct ListMembersSvc<T>(std::sync::Arc<T>);
    impl<T: OrganizationService> tonic::server::UnaryService<ListMembersRequest> for ListMembersSvc<T> {
        type Response = ListMembersResponse;
        type Future = std::pin::Pin<
            Box<
                dyn std::future::Future<
                        Output = Result<tonic::Response<Self::Response>, tonic::Status>,
                    > + Send
                    + 'static,
            >,
        >;
        fn call(&mut self, request: tonic::Request<ListMembersRequest>) -> Self::Future {
            let inner = self.0.clone();
            Box::pin(async move { inner.list_members(request).await })
        }
    }

    struct AddMemberSvc<T>(std::sync::Arc<T>);
    impl<T: OrganizationService> tonic::server::UnaryService<AddMemberRequest> for AddMemberSvc<T> {
        type Response = MemberResponse;
        type Future = std::pin::Pin<
            Box<
                dyn std::future::Future<
                        Output = Result<tonic::Response<Self::Response>, tonic::Status>,
                    > + Send
                    + 'static,
            >,
        >;
        fn call(&mut self, request: tonic::Request<AddMemberRequest>) -> Self::Future {
            let inner = self.0.clone();
            Box::pin(async move { inner.add_member(request).await })
        }
    }

    struct UpdateMemberSvc<T>(std::sync::Arc<T>);
    impl<T: OrganizationService> tonic::server::UnaryService<UpdateMemberRequest>
        for UpdateMemberSvc<T>
    {
        type Response = MemberResponse;
        type Future = std::pin::Pin<
            Box<
                dyn std::future::Future<
                        Output = Result<tonic::Response<Self::Response>, tonic::Status>,
                    > + Send
                    + 'static,
            >,
        >;
        fn call(&mut self, request: tonic::Request<UpdateMemberRequest>) -> Self::Future {
            let inner = self.0.clone();
            Box::pin(async move { inner.update_member(request).await })
        }
    }

    struct RemoveMemberSvc<T>(std::sync::Arc<T>);
    impl<T: OrganizationService> tonic::server::UnaryService<RemoveMemberRequest>
        for RemoveMemberSvc<T>
    {
        type Response = MessageResponse;
        type Future = std::pin::Pin<
            Box<
                dyn std::future::Future<
                        Output = Result<tonic::Response<Self::Response>, tonic::Status>,
                    > + Send
                    + 'static,
            >,
        >;
        fn call(&mut self, request: tonic::Request<RemoveMemberRequest>) -> Self::Future {
            let inner = self.0.clone();
            Box::pin(async move { inner.remove_member(request).await })
        }
    }
}

pub mod organization_service_client {
    use super::*;

    #[derive(Clone)]
    pub struct OrganizationServiceClient<T> {
        inner: tonic::client::Grpc<T>,
    }

    impl OrganizationServiceClient<tonic::transport::Channel> {
        pub async fn connect<D>(dst: D) -> Result<Self, tonic::transport::Error>
        where
            D: TryInto<tonic::transport::Endpoint>,
            D::Error: Into<Box<dyn std::error::Error + Send + Sync>>,
        {
            let conn = tonic::transport::Endpoint::new(dst)?.connect().await?;
            Ok(Self::new(conn))
        }
    }

    impl<T> OrganizationServiceClient<T>
    where
        T: tonic::client::GrpcService<tonic::body::Body>,
        T::Error: Into<Box<dyn std::error::Error + Send + Sync>>,
        T::ResponseBody: http_body::Body<Data = bytes::Bytes> + Send + 'static,
        <T::ResponseBody as http_body::Body>::Error:
            Into<Box<dyn std::error::Error + Send + Sync>> + Send,
    {
        pub fn new(inner: T) -> Self {
            let inner = tonic::client::Grpc::new(inner);
            Self { inner }
        }

        pub async fn list_organizations(
            &mut self,
            request: impl tonic::IntoRequest<ListOrganizationsRequest>,
        ) -> Result<tonic::Response<ListOrganizationsResponse>, tonic::Status> {
            self.inner
                .ready()
                .await
                .map_err(|e| tonic::Status::unknown(format!("Service not ready: {}", e.into())))?;
            let codec = tonic_prost::ProstCodec::default();
            let path = http::uri::PathAndQuery::from_static(
                "/tsa.v1.OrganizationService/ListOrganizations",
            );
            self.inner.unary(request.into_request(), path, codec).await
        }

        pub async fn create_organization(
            &mut self,
            request: impl tonic::IntoRequest<CreateOrganizationRequest>,
        ) -> Result<tonic::Response<OrganizationResponse>, tonic::Status> {
            self.inner
                .ready()
                .await
                .map_err(|e| tonic::Status::unknown(format!("Service not ready: {}", e.into())))?;
            let codec = tonic_prost::ProstCodec::default();
            let path = http::uri::PathAndQuery::from_static(
                "/tsa.v1.OrganizationService/CreateOrganization",
            );
            self.inner.unary(request.into_request(), path, codec).await
        }

        pub async fn get_organization(
            &mut self,
            request: impl tonic::IntoRequest<GetOrganizationRequest>,
        ) -> Result<tonic::Response<OrganizationResponse>, tonic::Status> {
            self.inner
                .ready()
                .await
                .map_err(|e| tonic::Status::unknown(format!("Service not ready: {}", e.into())))?;
            let codec = tonic_prost::ProstCodec::default();
            let path =
                http::uri::PathAndQuery::from_static("/tsa.v1.OrganizationService/GetOrganization");
            self.inner.unary(request.into_request(), path, codec).await
        }

        pub async fn update_organization(
            &mut self,
            request: impl tonic::IntoRequest<UpdateOrganizationRequest>,
        ) -> Result<tonic::Response<OrganizationResponse>, tonic::Status> {
            self.inner
                .ready()
                .await
                .map_err(|e| tonic::Status::unknown(format!("Service not ready: {}", e.into())))?;
            let codec = tonic_prost::ProstCodec::default();
            let path = http::uri::PathAndQuery::from_static(
                "/tsa.v1.OrganizationService/UpdateOrganization",
            );
            self.inner.unary(request.into_request(), path, codec).await
        }

        pub async fn delete_organization(
            &mut self,
            request: impl tonic::IntoRequest<DeleteOrganizationRequest>,
        ) -> Result<tonic::Response<MessageResponse>, tonic::Status> {
            self.inner
                .ready()
                .await
                .map_err(|e| tonic::Status::unknown(format!("Service not ready: {}", e.into())))?;
            let codec = tonic_prost::ProstCodec::default();
            let path = http::uri::PathAndQuery::from_static(
                "/tsa.v1.OrganizationService/DeleteOrganization",
            );
            self.inner.unary(request.into_request(), path, codec).await
        }

        pub async fn list_members(
            &mut self,
            request: impl tonic::IntoRequest<ListMembersRequest>,
        ) -> Result<tonic::Response<ListMembersResponse>, tonic::Status> {
            self.inner
                .ready()
                .await
                .map_err(|e| tonic::Status::unknown(format!("Service not ready: {}", e.into())))?;
            let codec = tonic_prost::ProstCodec::default();
            let path =
                http::uri::PathAndQuery::from_static("/tsa.v1.OrganizationService/ListMembers");
            self.inner.unary(request.into_request(), path, codec).await
        }

        pub async fn add_member(
            &mut self,
            request: impl tonic::IntoRequest<AddMemberRequest>,
        ) -> Result<tonic::Response<MemberResponse>, tonic::Status> {
            self.inner
                .ready()
                .await
                .map_err(|e| tonic::Status::unknown(format!("Service not ready: {}", e.into())))?;
            let codec = tonic_prost::ProstCodec::default();
            let path =
                http::uri::PathAndQuery::from_static("/tsa.v1.OrganizationService/AddMember");
            self.inner.unary(request.into_request(), path, codec).await
        }

        pub async fn update_member(
            &mut self,
            request: impl tonic::IntoRequest<UpdateMemberRequest>,
        ) -> Result<tonic::Response<MemberResponse>, tonic::Status> {
            self.inner
                .ready()
                .await
                .map_err(|e| tonic::Status::unknown(format!("Service not ready: {}", e.into())))?;
            let codec = tonic_prost::ProstCodec::default();
            let path =
                http::uri::PathAndQuery::from_static("/tsa.v1.OrganizationService/UpdateMember");
            self.inner.unary(request.into_request(), path, codec).await
        }

        pub async fn remove_member(
            &mut self,
            request: impl tonic::IntoRequest<RemoveMemberRequest>,
        ) -> Result<tonic::Response<MessageResponse>, tonic::Status> {
            self.inner
                .ready()
                .await
                .map_err(|e| tonic::Status::unknown(format!("Service not ready: {}", e.into())))?;
            let codec = tonic_prost::ProstCodec::default();
            let path =
                http::uri::PathAndQuery::from_static("/tsa.v1.OrganizationService/RemoveMember");
            self.inner.unary(request.into_request(), path, codec).await
        }
    }
}

pub mod api_key_service_server {
    use super::*;
    use tonic::{Request, Response, Status};

    #[tonic::async_trait]
    pub trait ApiKeyService: Send + Sync + 'static {
        async fn list_api_keys(
            &self,
            request: Request<ListApiKeysRequest>,
        ) -> Result<Response<ListApiKeysResponse>, Status>;
        async fn create_api_key(
            &self,
            request: Request<CreateApiKeyRequest>,
        ) -> Result<Response<CreateApiKeyResponse>, Status>;
        async fn update_api_key(
            &self,
            request: Request<UpdateApiKeyRequest>,
        ) -> Result<Response<ApiKeyResponse>, Status>;
        async fn delete_api_key(
            &self,
            request: Request<DeleteApiKeyRequest>,
        ) -> Result<Response<MessageResponse>, Status>;
    }

    pub struct ApiKeyServiceServer<T: ApiKeyService> {
        inner: std::sync::Arc<T>,
    }

    impl<T: ApiKeyService> ApiKeyServiceServer<T> {
        pub fn new(inner: T) -> Self {
            Self {
                inner: std::sync::Arc::new(inner),
            }
        }
    }

    impl<T: ApiKeyService> Clone for ApiKeyServiceServer<T> {
        fn clone(&self) -> Self {
            Self {
                inner: self.inner.clone(),
            }
        }
    }

    impl<T: ApiKeyService> tonic::server::NamedService for ApiKeyServiceServer<T> {
        const NAME: &'static str = "tsa.v1.ApiKeyService";
    }

    impl<T, B> tower_service::Service<http::Request<B>> for ApiKeyServiceServer<T>
    where
        T: ApiKeyService,
        B: http_body::Body + Send + 'static,
        B::Error: Into<Box<dyn std::error::Error + Send + Sync>> + Send + 'static,
    {
        type Response = http::Response<tonic::body::Body>;
        type Error = std::convert::Infallible;
        type Future = std::pin::Pin<
            Box<
                dyn std::future::Future<Output = Result<Self::Response, Self::Error>>
                    + Send
                    + 'static,
            >,
        >;

        fn poll_ready(
            &mut self,
            _cx: &mut std::task::Context<'_>,
        ) -> std::task::Poll<Result<(), Self::Error>> {
            std::task::Poll::Ready(Ok(()))
        }

        fn call(&mut self, req: http::Request<B>) -> Self::Future {
            let inner = self.inner.clone();
            match req.uri().path() {
                "/tsa.v1.ApiKeyService/ListApiKeys" => {
                    let inner = inner.clone();
                    Box::pin(async move {
                        let mut grpc = tonic::server::Grpc::new(tonic_prost::ProstCodec::default());
                        let res = grpc.unary(ListApiKeysSvc(inner), req).await;
                        Ok(res)
                    })
                }
                "/tsa.v1.ApiKeyService/CreateApiKey" => {
                    let inner = inner.clone();
                    Box::pin(async move {
                        let mut grpc = tonic::server::Grpc::new(tonic_prost::ProstCodec::default());
                        let res = grpc.unary(CreateApiKeySvc(inner), req).await;
                        Ok(res)
                    })
                }
                "/tsa.v1.ApiKeyService/UpdateApiKey" => {
                    let inner = inner.clone();
                    Box::pin(async move {
                        let mut grpc = tonic::server::Grpc::new(tonic_prost::ProstCodec::default());
                        let res = grpc.unary(UpdateApiKeySvc(inner), req).await;
                        Ok(res)
                    })
                }
                "/tsa.v1.ApiKeyService/DeleteApiKey" => {
                    let inner = inner.clone();
                    Box::pin(async move {
                        let mut grpc = tonic::server::Grpc::new(tonic_prost::ProstCodec::default());
                        let res = grpc.unary(DeleteApiKeySvc(inner), req).await;
                        Ok(res)
                    })
                }
                _ => Box::pin(async move {
                    let mut res = http::Response::new(tonic::body::Body::empty());
                    *res.status_mut() = http::StatusCode::OK;
                    res.headers_mut().insert(
                        http::header::CONTENT_TYPE,
                        http::HeaderValue::from_static("application/grpc"),
                    );
                    res.headers_mut()
                        .insert("grpc-status", http::HeaderValue::from_static("12"));
                    res.headers_mut().insert(
                        "grpc-message",
                        http::HeaderValue::from_static("Unimplemented"),
                    );
                    Ok(res)
                }),
            }
        }
    }

    struct ListApiKeysSvc<T>(std::sync::Arc<T>);
    impl<T: ApiKeyService> tonic::server::UnaryService<ListApiKeysRequest> for ListApiKeysSvc<T> {
        type Response = ListApiKeysResponse;
        type Future = std::pin::Pin<
            Box<
                dyn std::future::Future<
                        Output = Result<tonic::Response<Self::Response>, tonic::Status>,
                    > + Send
                    + 'static,
            >,
        >;
        fn call(&mut self, request: tonic::Request<ListApiKeysRequest>) -> Self::Future {
            let inner = self.0.clone();
            Box::pin(async move { inner.list_api_keys(request).await })
        }
    }

    struct CreateApiKeySvc<T>(std::sync::Arc<T>);
    impl<T: ApiKeyService> tonic::server::UnaryService<CreateApiKeyRequest> for CreateApiKeySvc<T> {
        type Response = CreateApiKeyResponse;
        type Future = std::pin::Pin<
            Box<
                dyn std::future::Future<
                        Output = Result<tonic::Response<Self::Response>, tonic::Status>,
                    > + Send
                    + 'static,
            >,
        >;
        fn call(&mut self, request: tonic::Request<CreateApiKeyRequest>) -> Self::Future {
            let inner = self.0.clone();
            Box::pin(async move { inner.create_api_key(request).await })
        }
    }

    struct UpdateApiKeySvc<T>(std::sync::Arc<T>);
    impl<T: ApiKeyService> tonic::server::UnaryService<UpdateApiKeyRequest> for UpdateApiKeySvc<T> {
        type Response = ApiKeyResponse;
        type Future = std::pin::Pin<
            Box<
                dyn std::future::Future<
                        Output = Result<tonic::Response<Self::Response>, tonic::Status>,
                    > + Send
                    + 'static,
            >,
        >;
        fn call(&mut self, request: tonic::Request<UpdateApiKeyRequest>) -> Self::Future {
            let inner = self.0.clone();
            Box::pin(async move { inner.update_api_key(request).await })
        }
    }

    struct DeleteApiKeySvc<T>(std::sync::Arc<T>);
    impl<T: ApiKeyService> tonic::server::UnaryService<DeleteApiKeyRequest> for DeleteApiKeySvc<T> {
        type Response = MessageResponse;
        type Future = std::pin::Pin<
            Box<
                dyn std::future::Future<
                        Output = Result<tonic::Response<Self::Response>, tonic::Status>,
                    > + Send
                    + 'static,
            >,
        >;
        fn call(&mut self, request: tonic::Request<DeleteApiKeyRequest>) -> Self::Future {
            let inner = self.0.clone();
            Box::pin(async move { inner.delete_api_key(request).await })
        }
    }
}

pub mod api_key_service_client {
    use super::*;

    #[derive(Clone)]
    pub struct ApiKeyServiceClient<T> {
        inner: tonic::client::Grpc<T>,
    }

    impl ApiKeyServiceClient<tonic::transport::Channel> {
        pub async fn connect<D>(dst: D) -> Result<Self, tonic::transport::Error>
        where
            D: TryInto<tonic::transport::Endpoint>,
            D::Error: Into<Box<dyn std::error::Error + Send + Sync>>,
        {
            let conn = tonic::transport::Endpoint::new(dst)?.connect().await?;
            Ok(Self::new(conn))
        }
    }

    impl<T> ApiKeyServiceClient<T>
    where
        T: tonic::client::GrpcService<tonic::body::Body>,
        T::Error: Into<Box<dyn std::error::Error + Send + Sync>>,
        T::ResponseBody: http_body::Body<Data = bytes::Bytes> + Send + 'static,
        <T::ResponseBody as http_body::Body>::Error:
            Into<Box<dyn std::error::Error + Send + Sync>> + Send,
    {
        pub fn new(inner: T) -> Self {
            let inner = tonic::client::Grpc::new(inner);
            Self { inner }
        }

        pub async fn list_api_keys(
            &mut self,
            request: impl tonic::IntoRequest<ListApiKeysRequest>,
        ) -> Result<tonic::Response<ListApiKeysResponse>, tonic::Status> {
            self.inner
                .ready()
                .await
                .map_err(|e| tonic::Status::unknown(format!("Service not ready: {}", e.into())))?;
            let codec = tonic_prost::ProstCodec::default();
            let path = http::uri::PathAndQuery::from_static("/tsa.v1.ApiKeyService/ListApiKeys");
            self.inner.unary(request.into_request(), path, codec).await
        }

        pub async fn create_api_key(
            &mut self,
            request: impl tonic::IntoRequest<CreateApiKeyRequest>,
        ) -> Result<tonic::Response<CreateApiKeyResponse>, tonic::Status> {
            self.inner
                .ready()
                .await
                .map_err(|e| tonic::Status::unknown(format!("Service not ready: {}", e.into())))?;
            let codec = tonic_prost::ProstCodec::default();
            let path = http::uri::PathAndQuery::from_static("/tsa.v1.ApiKeyService/CreateApiKey");
            self.inner.unary(request.into_request(), path, codec).await
        }

        pub async fn update_api_key(
            &mut self,
            request: impl tonic::IntoRequest<UpdateApiKeyRequest>,
        ) -> Result<tonic::Response<ApiKeyResponse>, tonic::Status> {
            self.inner
                .ready()
                .await
                .map_err(|e| tonic::Status::unknown(format!("Service not ready: {}", e.into())))?;
            let codec = tonic_prost::ProstCodec::default();
            let path = http::uri::PathAndQuery::from_static("/tsa.v1.ApiKeyService/UpdateApiKey");
            self.inner.unary(request.into_request(), path, codec).await
        }

        pub async fn delete_api_key(
            &mut self,
            request: impl tonic::IntoRequest<DeleteApiKeyRequest>,
        ) -> Result<tonic::Response<MessageResponse>, tonic::Status> {
            self.inner
                .ready()
                .await
                .map_err(|e| tonic::Status::unknown(format!("Service not ready: {}", e.into())))?;
            let codec = tonic_prost::ProstCodec::default();
            let path = http::uri::PathAndQuery::from_static("/tsa.v1.ApiKeyService/DeleteApiKey");
            self.inner.unary(request.into_request(), path, codec).await
        }
    }
}

pub mod health_service_server {
    use super::*;
    use tonic::{Request, Response, Status};

    #[tonic::async_trait]
    pub trait HealthService: Send + Sync + 'static {
        async fn check(
            &self,
            request: Request<HealthCheckRequest>,
        ) -> Result<Response<HealthCheckResponse>, Status>;
    }

    pub struct HealthServiceServer<T: HealthService> {
        inner: std::sync::Arc<T>,
    }

    impl<T: HealthService> HealthServiceServer<T> {
        pub fn new(inner: T) -> Self {
            Self {
                inner: std::sync::Arc::new(inner),
            }
        }
    }

    impl<T: HealthService> Clone for HealthServiceServer<T> {
        fn clone(&self) -> Self {
            Self {
                inner: self.inner.clone(),
            }
        }
    }

    impl<T: HealthService> tonic::server::NamedService for HealthServiceServer<T> {
        const NAME: &'static str = "tsa.v1.HealthService";
    }

    impl<T, B> tower_service::Service<http::Request<B>> for HealthServiceServer<T>
    where
        T: HealthService,
        B: http_body::Body + Send + 'static,
        B::Error: Into<Box<dyn std::error::Error + Send + Sync>> + Send + 'static,
    {
        type Response = http::Response<tonic::body::Body>;
        type Error = std::convert::Infallible;
        type Future = std::pin::Pin<
            Box<
                dyn std::future::Future<Output = Result<Self::Response, Self::Error>>
                    + Send
                    + 'static,
            >,
        >;

        fn poll_ready(
            &mut self,
            _cx: &mut std::task::Context<'_>,
        ) -> std::task::Poll<Result<(), Self::Error>> {
            std::task::Poll::Ready(Ok(()))
        }

        fn call(&mut self, req: http::Request<B>) -> Self::Future {
            let inner = self.inner.clone();
            match req.uri().path() {
                "/tsa.v1.HealthService/Check" => {
                    let inner = inner.clone();
                    Box::pin(async move {
                        let mut grpc = tonic::server::Grpc::new(tonic_prost::ProstCodec::default());
                        let res = grpc.unary(HealthCheckSvc(inner), req).await;
                        Ok(res)
                    })
                }
                _ => Box::pin(async move {
                    let mut res = http::Response::new(tonic::body::Body::empty());
                    *res.status_mut() = http::StatusCode::OK;
                    res.headers_mut().insert(
                        http::header::CONTENT_TYPE,
                        http::HeaderValue::from_static("application/grpc"),
                    );
                    res.headers_mut()
                        .insert("grpc-status", http::HeaderValue::from_static("12"));
                    res.headers_mut().insert(
                        "grpc-message",
                        http::HeaderValue::from_static("Unimplemented"),
                    );
                    Ok(res)
                }),
            }
        }
    }

    struct HealthCheckSvc<T>(std::sync::Arc<T>);
    impl<T: HealthService> tonic::server::UnaryService<HealthCheckRequest> for HealthCheckSvc<T> {
        type Response = HealthCheckResponse;
        type Future = std::pin::Pin<
            Box<
                dyn std::future::Future<
                        Output = Result<tonic::Response<Self::Response>, tonic::Status>,
                    > + Send
                    + 'static,
            >,
        >;
        fn call(&mut self, request: tonic::Request<HealthCheckRequest>) -> Self::Future {
            let inner = self.0.clone();
            Box::pin(async move { inner.check(request).await })
        }
    }
}

pub mod health_service_client {
    use super::*;

    #[derive(Clone)]
    pub struct HealthServiceClient<T> {
        inner: tonic::client::Grpc<T>,
    }

    impl HealthServiceClient<tonic::transport::Channel> {
        pub async fn connect<D>(dst: D) -> Result<Self, tonic::transport::Error>
        where
            D: TryInto<tonic::transport::Endpoint>,
            D::Error: Into<Box<dyn std::error::Error + Send + Sync>>,
        {
            let conn = tonic::transport::Endpoint::new(dst)?.connect().await?;
            Ok(Self::new(conn))
        }
    }

    impl<T> HealthServiceClient<T>
    where
        T: tonic::client::GrpcService<tonic::body::Body>,
        T::Error: Into<Box<dyn std::error::Error + Send + Sync>>,
        T::ResponseBody: http_body::Body<Data = bytes::Bytes> + Send + 'static,
        <T::ResponseBody as http_body::Body>::Error:
            Into<Box<dyn std::error::Error + Send + Sync>> + Send,
    {
        pub fn new(inner: T) -> Self {
            let inner = tonic::client::Grpc::new(inner);
            Self { inner }
        }

        pub async fn check(
            &mut self,
            request: impl tonic::IntoRequest<HealthCheckRequest>,
        ) -> Result<tonic::Response<HealthCheckResponse>, tonic::Status> {
            self.inner
                .ready()
                .await
                .map_err(|e| tonic::Status::unknown(format!("Service not ready: {}", e.into())))?;
            let codec = tonic_prost::ProstCodec::default();
            let path = http::uri::PathAndQuery::from_static("/tsa.v1.HealthService/Check");
            self.inner.unary(request.into_request(), path, codec).await
        }
    }
}
