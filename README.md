# burp-codex-assistant

Burp Suite Jython extension that sends Repeater requests to Codex for quick pentest and bug bounty analysis.

## Features

- Native `Codex` tab in Burp
- Editable request pane
- AI analysis pane
- Chat with Codex about the current request
- Secret redaction by default

## Requirements

- Burp Suite
- Jython 2.7 configured in Burp
- Local `codex` CLI installed and authenticated

## Install

1. Open Burp.
2. Go to `Extensions > Installed > Add`.
3. Choose type `Python`.
4. Load `codex_burp_extension.py`.

## Use

1. Send a request to Repeater.
2. Right-click the request.
3. Click `Send selection to Codex`.
4. Open the `Codex` tab.
5. Edit the request, click `Analyze`, or ask a question in the chat box.

## Note

Codex runs through your local Codex CLI config. Do not send sensitive or out-of-scope traffic unless you know where your Codex provider sends data.
