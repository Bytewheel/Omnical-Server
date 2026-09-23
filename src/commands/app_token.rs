use clap::{Parser, Subcommand};
use rand::{RngExt, distr::Alphanumeric};
use rustical_store::auth::AuthenticationProvider;

// TODO: Move token generation to store
pub fn generate_app_token() -> String {
    rand::rng()
        .sample_iter(Alphanumeric)
        .map(char::from)
        .take(64)
        .collect()
}

#[derive(Debug, Parser)]
pub struct CreateArgs {
    principal: String,
    #[arg(long, help = "The app name")]
    name: String,
}

#[derive(Debug, Parser)]
pub struct RemoveArgs {
    principal: String,
    id: String,
}

#[derive(Debug, Parser)]
pub struct RegenerateArgs {
    principal: String,
    id: String,
}

#[derive(Debug, Parser)]
pub struct ListArgs {
    principal: String,
}

#[derive(Debug, Subcommand)]
pub enum AppTokenCommand {
    Create(CreateArgs),
    Remove(RemoveArgs),
    /// Rotate the secret of an existing token (old secret stops working; the
    /// new one is printed once — app-token secrets are stored hashed)
    Regenerate(RegenerateArgs),
    List(ListArgs),
}

#[derive(Parser, Debug)]
pub struct AppTokenArgs {
    #[command(subcommand)]
    pub command: AppTokenCommand,
}

#[allow(clippy::missing_errors_doc, clippy::missing_panics_doc)]
pub async fn cmd_app_token(
    user_store: &impl AuthenticationProvider,
    AppTokenArgs { command }: AppTokenArgs,
) -> anyhow::Result<()> {
    let principal = match &command {
        AppTokenCommand::Create(CreateArgs { principal, .. })
        | AppTokenCommand::Remove(RemoveArgs { principal, .. })
        | AppTokenCommand::Regenerate(RegenerateArgs { principal, .. })
        | AppTokenCommand::List(ListArgs { principal }) => principal,
    };

    match &command {
        AppTokenCommand::Create(CreateArgs { name, .. }) => {
            let token = generate_app_token();
            let mut token_id = user_store
                .add_app_token(principal, name.clone(), token.clone())
                .await?;
            // Get first 4 characters of token identifier
            token_id.truncate(4);
            // This will be a hint for the token validator which app token hash to verify against
            println!("{token_id}_{token}");
        }
        AppTokenCommand::Remove(RemoveArgs { id, .. }) => {
            user_store.remove_app_token(principal, id).await?;
        }
        AppTokenCommand::Regenerate(RegenerateArgs { id, .. }) => {
            let token = generate_app_token();
            user_store
                .update_app_token(principal, id, token.clone())
                .await?;
            let mut token_id = id.clone();
            token_id.truncate(4);
            println!("{token_id}_{token}");
        }
        AppTokenCommand::List(ListArgs { .. }) => {
            println!(
                "{}",
                user_store
                    .get_app_tokens(principal)
                    .await?
                    .iter()
                    .map(|token| format!("{} - {}", token.id, token.name))
                    .collect::<Vec<_>>()
                    .join("\n")
            );
        }
    }
    Ok(())
}
