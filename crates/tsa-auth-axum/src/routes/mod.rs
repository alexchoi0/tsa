mod auth;
mod health;
mod organizations;
mod sessions;
mod users;

use std::sync::Arc;

use axum::{
    middleware,
    routing::{delete, get, post, put},
    Router,
};
use tower_http::cors::{Any, CorsLayer};
use tower_http::trace::TraceLayer;

use crate::middleware::request_logger;
use crate::state::AppState;

pub fn create_router(state: Arc<AppState>) -> Router {
    let cors = CorsLayer::new()
        .allow_origin(Any)
        .allow_methods(Any)
        .allow_headers(Any);

    let api_routes = Router::new()
        .route("/auth/signup", post(auth::signup))
        .route("/auth/signin", post(auth::signin))
        .route("/auth/signout", post(auth::signout))
        .route("/auth/refresh", post(auth::refresh_session))
        .route("/auth/2fa/setup", post(auth::setup_2fa))
        .route("/auth/2fa/verify", post(auth::verify_2fa))
        .route("/auth/2fa/disable", post(auth::disable_2fa))
        .route("/auth/password", put(auth::change_password))
        .route("/users/me", get(users::get_current_user))
        .route("/users/me", put(users::update_current_user))
        .route("/users/me/sessions", get(sessions::list_sessions))
        .route("/users/me/sessions/:id", delete(sessions::revoke_session))
        .route("/users/me/sessions", delete(sessions::revoke_all_sessions))
        .route("/users/me/api-keys", get(users::list_api_keys))
        .route("/users/me/api-keys", post(users::create_api_key))
        .route("/users/me/api-keys/:id", put(users::update_api_key))
        .route("/users/me/api-keys/:id", delete(users::delete_api_key))
        .route("/organizations", get(organizations::list_organizations))
        .route("/organizations", post(organizations::create_organization))
        .route("/organizations/:slug", get(organizations::get_organization))
        .route(
            "/organizations/:id",
            put(organizations::update_organization),
        )
        .route(
            "/organizations/:id",
            delete(organizations::delete_organization),
        )
        .route(
            "/organizations/:id/members",
            get(organizations::list_members),
        )
        .route(
            "/organizations/:id/members",
            post(organizations::add_member),
        )
        .route(
            "/organizations/:id/members/:user_id",
            put(organizations::update_member),
        )
        .route(
            "/organizations/:id/members/:user_id",
            delete(organizations::remove_member),
        );

    Router::new()
        .route("/health", get(health::health_check))
        .nest("/api/v1", api_routes)
        .layer(middleware::from_fn(request_logger))
        .layer(TraceLayer::new_for_http())
        .layer(cors)
        .with_state(state)
}
