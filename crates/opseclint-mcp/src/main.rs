//! `opseclint-mcp`: an MCP server over opseclint's detection knowledge base.
//!
//! Speaks MCP over stdio, so it is wired up by pointing a client at this
//! binary. Nothing is read from disk or the network at runtime — every
//! knowledge base is compiled in.
//!
//! ```json
//! {
//!   "mcpServers": {
//!     "opseclint": { "command": "opseclint-mcp" }
//!   }
//! }
//! ```

mod server;
mod shape;

use std::process::ExitCode;

use rmcp::ServiceExt;
use rmcp::transport::stdio;

#[tokio::main(flavor = "current_thread")]
async fn main() -> ExitCode {
    // stdout is the transport. Anything written to it that is not a JSON-RPC
    // frame corrupts the session, so every diagnostic goes to stderr.
    let service = match server::Opseclint::new() {
        Ok(s) => s,
        Err(e) => {
            eprintln!("opseclint-mcp: failed to load knowledge base: {e}");
            return ExitCode::from(2);
        }
    };

    let running = match service.serve(stdio()).await {
        Ok(r) => r,
        Err(e) => {
            eprintln!("opseclint-mcp: failed to start: {e}");
            return ExitCode::from(2);
        }
    };

    if let Err(e) = running.waiting().await {
        eprintln!("opseclint-mcp: session ended with an error: {e}");
        return ExitCode::from(1);
    }
    ExitCode::SUCCESS
}
