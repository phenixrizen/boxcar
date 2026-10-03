// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 The boxcar Authors

//! `boxcar stop`: stops a running VM through its control socket.

use std::process::ExitCode;
use std::time::Duration;

use anyhow::{bail, Context};
use boxcar_proto::control::{StopMode, StopParams};

use crate::cli::StopArgs;
use crate::client::{self, Message};

/// How much longer than the stop's own timeout `boxcar stop` waits for the
/// VM to stop.
const STOP_MARGIN: Duration = Duration::from_secs(10);

/// Asks the session `args` names to stop, then waits for its `stopped`
/// event or for the socket to close, which the VMM does once it stopped.
pub fn run(args: &StopArgs) -> anyhow::Result<ExitCode> {
    let session = &args.session;
    let mut client = client::connect(session.control.as_deref(), session.session_id.as_deref())?;
    let params = StopParams {
        mode: if args.force {
            StopMode::Force
        } else {
            StopMode::Graceful
        },
        timeout_ms: args.timeout_ms,
    };
    let wait = Duration::from_millis(params.effective_timeout_ms()).saturating_add(STOP_MARGIN);
    if let Err(error) = client.request("stop", serde_json::to_value(&params)?)? {
        bail!("stop: {error}");
    }
    client.set_timeout(Some(wait))?;
    loop {
        match client
            .next_message()
            .context("waiting for the VM to stop")?
        {
            None => break,
            Some(Message::Event { name, body })
                if name == "state" && body["state"] == "stopped" =>
            {
                break
            }
            Some(_) => {}
        }
    }
    Ok(ExitCode::SUCCESS)
}
