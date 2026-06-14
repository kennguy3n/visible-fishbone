//! AI-app upload exfiltration signal.
//!
//! Generative-AI assistants have become the highest-volume
//! uncontrolled egress path on a managed endpoint: an employee pastes
//! a customer spreadsheet into a chat box, drops a contract into a
//! "summarise this" tool, or wires a code assistant straight at a repo
//! full of API keys. The risk is not one or two well-known vendors —
//! it is the **long tail**. For every ChatGPT or Claude there are
//! hundreds of niche wrappers, browser extensions, and self-hosted
//! front-ends, and a deny-list of two domains catches none of them.
//!
//! This module adds an [`AiAppExfilDetector`] that flags a request
//! body bound for *any* AI-app destination when it carries sensitive
//! data. It is built on the existing detection stack rather than
//! beside it:
//!
//! * **PII** reuses the full [`crate::classifier`] /
//!   [`crate::detectors`] catalog (every jurisdiction identifier, the
//!   generic builtins, and the ML-NER head) via a default rule set —
//!   so a national-ID detector added for the SWG immediately protects
//!   the AI-upload path too, with no duplicated regexes.
//! * **Secrets** ([`SecretScanner`]) covers cloud keys, VCS / CI
//!   tokens, and private keys, each gated by a prefix/shape match plus
//!   a Shannon-entropy floor so a literal example string does not
//!   masquerade as a live credential.
//! * **Company-confidential markers** ([`ConfidentialScanner`])
//!   matches the classification banners ("CONFIDENTIAL", "INTERNAL
//!   USE ONLY", "attorney-client privileged", …) real internal
//!   documents carry.
//!
//! ## Coach-first, non-blocking by default
//!
//! False positives are the fastest way to get a DLP control switched
//! off. The detector therefore defaults to a **non-blocking** posture:
//! every flagged upload is either silently recorded
//! ([`AiAppAction::Monitor`]) or surfaced as a coaching nudge the user
//! can dismiss ([`AiAppAction::Coach`]). It escalates to
//! [`AiAppAction::Block`] *only* when the operator has explicitly
//! opted in ([`AiAppPolicy::block_opt_in`]) **and** the signal clears a
//! high-confidence bar **and** the destination is a *known* AI app
//! (never a heuristic "suspected" one). The default
//! [`AiAppPolicy`] never blocks.
//!
//! ## Redaction invariant
//!
//! Like the rest of the crate, nothing here ever retains or serialises
//! the matched bytes (see the [`crate::classifier`] redaction
//! invariant). A [`SecretMatch`] / [`MarkerMatch`] carries only the
//! detector identity and the offset/length of the hit, and the
//! operator-facing [`AiAppSignal`] aggregates findings down to
//! per-class counts — enough to triage and to author policy, never
//! enough to reconstruct the credential or record that produced it.

use crate::channels::DlpChannel;
use crate::classifier::{ContentClassifier, ContentMetadata, RuleMatch};
use crate::detectors;
use crate::engine::{DlpVerdict, VerdictDetails};
use crate::error::DlpResult;
use crate::ml_classifier::EntityClass;
use crate::rules::{DlpRule, PatternType, RuleAction, Severity};
use aho_corasick::{AhoCorasick, MatchKind};
use regex::{Regex, RegexSet};
use serde::{Deserialize, Serialize};
use std::collections::BTreeSet;

/// The egress channel an AI-app upload is observed on. AI assistants
/// are reached over the network from the browser or a native client,
/// so the upload is a [`DlpChannel::BrowserUpload`] for the purpose of
/// the reused contextual scorer (which weights browser uploads as a
/// high-risk off-host path). Kept as a named constant so the choice is
/// documented in one place rather than scattered as a literal.
const AI_UPLOAD_CHANNEL: DlpChannel = DlpChannel::BrowserUpload;

/// Confidence assigned to a destination matched in the curated
/// [`KNOWN_AI_APPS`] catalog — an unambiguous AI-app vendor.
const DESTINATION_CONFIDENCE_KNOWN: f64 = 1.0;

/// Confidence assigned to a destination matched only by the long-tail
/// host/path heuristic ([`heuristic_ai_app`]). Deliberately below the
/// default [`AiAppPolicy::min_report_confidence`] so a suspected
/// destination alone never flags — it must combine with a strong
/// content finding to clear the bar, and can never reach the block
/// threshold.
const DESTINATION_CONFIDENCE_SUSPECTED: f64 = 0.6;

/// Content confidence for a secret whose prefix/shape matched and that
/// cleared its entropy floor. A keyed credential with a vendor prefix
/// is about as unambiguous as detection gets.
const SECRET_CONFIDENCE: f64 = 1.0;

/// Content confidence for a company-confidential banner hit. Banners
/// are deliberate human classifications, but the phrase can also occur
/// in incidental prose, so it sits below a keyed secret.
const CONFIDENTIAL_CONFIDENCE: f64 = 0.7;

// ---------------------------------------------------------------------------
// Destination classification
// ---------------------------------------------------------------------------

/// How a destination was recognised as an AI app.
#[derive(Copy, Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AiAppKind {
    /// Matched the curated [`KNOWN_AI_APPS`] catalog.
    Known,
    /// Matched the long-tail host/path heuristic only.
    Suspected,
    /// Not recognised as an AI app.
    NotAiApp,
}

/// The product category of a known AI app, recorded so an operator can
/// reason about exposure by tool type ("how much PII went to
/// code assistants this week") without an allow/deny list per vendor.
#[derive(Copy, Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AiAppCategory {
    /// General-purpose conversational assistant (ChatGPT, Claude, …).
    Chatbot,
    /// Code-generation / pair-programming assistant (Copilot, …).
    CodeAssistant,
    /// Writing / marketing-copy assistant (Jasper, Writesonic, …).
    WritingAssistant,
    /// Image / media generation (Midjourney, Stable Diffusion hosts).
    ImageGenerator,
    /// Search / answer engine (Perplexity, …).
    SearchAssistant,
    /// Model API gateway or hosting hub (`OpenAI`/Azure APIs, Hugging
    /// Face, Replicate) — where a body is uploaded programmatically.
    ModelPlatform,
    /// Meeting / transcription assistant (Otter, Fireflies, …).
    MeetingAssistant,
    /// Recognised as an AI app by heuristic; specific category unknown.
    Other,
}

/// The classification of an upload destination.
///
/// `domain` is the registrable host the match was attributed to, kept
/// for the audit trail. Only the host is retained — never the path or
/// query string, which can themselves carry tokens or identifiers.
///
/// Serialise-only: it carries `&'static` catalog ids, so it is an
/// output/telemetry type, not one Rust round-trips.
#[derive(Clone, Debug, PartialEq, Serialize)]
pub struct AiAppDestination {
    /// How the destination was recognised.
    pub kind: AiAppKind,
    /// Stable app id from the catalog (e.g. `chatgpt`), or `None` for a
    /// heuristic match. Catalog ids are constants, never user data.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub app: Option<&'static str>,
    /// Product category, when known.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub category: Option<AiAppCategory>,
    /// The host the match was attributed to (no scheme, no path, no
    /// port). Empty when the input had no parseable host.
    pub domain: String,
    /// Confidence the destination really is an AI app, `0.0..=1.0`.
    pub confidence: f64,
}

impl AiAppDestination {
    /// Whether the destination is an AI app (known or suspected).
    #[must_use]
    pub const fn is_ai_app(&self) -> bool {
        matches!(self.kind, AiAppKind::Known | AiAppKind::Suspected)
    }
}

/// One entry in the curated AI-app catalog: a registrable domain
/// suffix, the stable app id, and the product category.
struct KnownAiApp {
    /// Registrable domain (matched as an exact host or a suffix after a
    /// `.` boundary, so `chat.openai.com` matches `openai.com`).
    domain: &'static str,
    /// Stable app id used in signals and policy.
    app: &'static str,
    /// Product category.
    category: AiAppCategory,
}

/// The curated catalog of well-known AI-app destinations. This is the
/// *high-confidence* tier; the long-tail heuristic
/// ([`heuristic_ai_app`]) covers everything else. The list is
/// intentionally broad (not just ChatGPT/Claude) but is not expected to
/// be exhaustive — exhaustiveness is the heuristic's job. New high-
/// volume vendors are cheap to add here for a confidence/category bump.
const KNOWN_AI_APPS: &[KnownAiApp] = &[
    // --- General-purpose chatbots ---
    KnownAiApp {
        domain: "openai.com",
        app: "chatgpt",
        category: AiAppCategory::Chatbot,
    },
    KnownAiApp {
        domain: "chatgpt.com",
        app: "chatgpt",
        category: AiAppCategory::Chatbot,
    },
    KnownAiApp {
        domain: "claude.ai",
        app: "claude",
        category: AiAppCategory::Chatbot,
    },
    KnownAiApp {
        domain: "anthropic.com",
        app: "claude",
        category: AiAppCategory::Chatbot,
    },
    KnownAiApp {
        domain: "gemini.google.com",
        app: "gemini",
        category: AiAppCategory::Chatbot,
    },
    KnownAiApp {
        domain: "bard.google.com",
        app: "gemini",
        category: AiAppCategory::Chatbot,
    },
    KnownAiApp {
        domain: "copilot.microsoft.com",
        app: "copilot",
        category: AiAppCategory::Chatbot,
    },
    KnownAiApp {
        domain: "poe.com",
        app: "poe",
        category: AiAppCategory::Chatbot,
    },
    KnownAiApp {
        domain: "pi.ai",
        app: "pi",
        category: AiAppCategory::Chatbot,
    },
    KnownAiApp {
        domain: "chat.mistral.ai",
        app: "le_chat",
        category: AiAppCategory::Chatbot,
    },
    KnownAiApp {
        domain: "mistral.ai",
        app: "mistral",
        category: AiAppCategory::Chatbot,
    },
    KnownAiApp {
        domain: "chat.deepseek.com",
        app: "deepseek",
        category: AiAppCategory::Chatbot,
    },
    KnownAiApp {
        domain: "deepseek.com",
        app: "deepseek",
        category: AiAppCategory::Chatbot,
    },
    KnownAiApp {
        domain: "x.ai",
        app: "grok",
        category: AiAppCategory::Chatbot,
    },
    KnownAiApp {
        domain: "grok.com",
        app: "grok",
        category: AiAppCategory::Chatbot,
    },
    KnownAiApp {
        domain: "character.ai",
        app: "character_ai",
        category: AiAppCategory::Chatbot,
    },
    KnownAiApp {
        domain: "chatglm.cn",
        app: "chatglm",
        category: AiAppCategory::Chatbot,
    },
    KnownAiApp {
        domain: "moonshot.cn",
        app: "kimi",
        category: AiAppCategory::Chatbot,
    },
    KnownAiApp {
        domain: "tongyi.aliyun.com",
        app: "tongyi",
        category: AiAppCategory::Chatbot,
    },
    KnownAiApp {
        domain: "doubao.com",
        app: "doubao",
        category: AiAppCategory::Chatbot,
    },
    // --- Code assistants ---
    KnownAiApp {
        domain: "github.com",
        app: "github_copilot",
        category: AiAppCategory::CodeAssistant,
    },
    KnownAiApp {
        domain: "githubcopilot.com",
        app: "github_copilot",
        category: AiAppCategory::CodeAssistant,
    },
    KnownAiApp {
        domain: "cursor.com",
        app: "cursor",
        category: AiAppCategory::CodeAssistant,
    },
    KnownAiApp {
        domain: "cursor.sh",
        app: "cursor",
        category: AiAppCategory::CodeAssistant,
    },
    KnownAiApp {
        domain: "codeium.com",
        app: "codeium",
        category: AiAppCategory::CodeAssistant,
    },
    KnownAiApp {
        domain: "tabnine.com",
        app: "tabnine",
        category: AiAppCategory::CodeAssistant,
    },
    KnownAiApp {
        domain: "phind.com",
        app: "phind",
        category: AiAppCategory::CodeAssistant,
    },
    KnownAiApp {
        domain: "codium.ai",
        app: "qodo",
        category: AiAppCategory::CodeAssistant,
    },
    KnownAiApp {
        domain: "sourcegraph.com",
        app: "cody",
        category: AiAppCategory::CodeAssistant,
    },
    KnownAiApp {
        domain: "replit.com",
        app: "replit_ai",
        category: AiAppCategory::CodeAssistant,
    },
    // --- Writing assistants ---
    KnownAiApp {
        domain: "jasper.ai",
        app: "jasper",
        category: AiAppCategory::WritingAssistant,
    },
    KnownAiApp {
        domain: "writesonic.com",
        app: "writesonic",
        category: AiAppCategory::WritingAssistant,
    },
    KnownAiApp {
        domain: "copy.ai",
        app: "copy_ai",
        category: AiAppCategory::WritingAssistant,
    },
    KnownAiApp {
        domain: "rytr.me",
        app: "rytr",
        category: AiAppCategory::WritingAssistant,
    },
    KnownAiApp {
        domain: "quillbot.com",
        app: "quillbot",
        category: AiAppCategory::WritingAssistant,
    },
    KnownAiApp {
        domain: "grammarly.com",
        app: "grammarly",
        category: AiAppCategory::WritingAssistant,
    },
    KnownAiApp {
        domain: "notion.so",
        app: "notion_ai",
        category: AiAppCategory::WritingAssistant,
    },
    // --- Image / media generators ---
    KnownAiApp {
        domain: "midjourney.com",
        app: "midjourney",
        category: AiAppCategory::ImageGenerator,
    },
    KnownAiApp {
        domain: "leonardo.ai",
        app: "leonardo",
        category: AiAppCategory::ImageGenerator,
    },
    KnownAiApp {
        domain: "stability.ai",
        app: "stability",
        category: AiAppCategory::ImageGenerator,
    },
    KnownAiApp {
        domain: "runwayml.com",
        app: "runway",
        category: AiAppCategory::ImageGenerator,
    },
    KnownAiApp {
        domain: "elevenlabs.io",
        app: "elevenlabs",
        category: AiAppCategory::ImageGenerator,
    },
    // --- Search / answer engines ---
    KnownAiApp {
        domain: "perplexity.ai",
        app: "perplexity",
        category: AiAppCategory::SearchAssistant,
    },
    KnownAiApp {
        domain: "you.com",
        app: "you",
        category: AiAppCategory::SearchAssistant,
    },
    KnownAiApp {
        domain: "phind.ai",
        app: "phind",
        category: AiAppCategory::SearchAssistant,
    },
    // --- Model platforms / API gateways ---
    KnownAiApp {
        domain: "api.openai.com",
        app: "openai_api",
        category: AiAppCategory::ModelPlatform,
    },
    KnownAiApp {
        domain: "api.anthropic.com",
        app: "anthropic_api",
        category: AiAppCategory::ModelPlatform,
    },
    KnownAiApp {
        domain: "huggingface.co",
        app: "huggingface",
        category: AiAppCategory::ModelPlatform,
    },
    KnownAiApp {
        domain: "replicate.com",
        app: "replicate",
        category: AiAppCategory::ModelPlatform,
    },
    KnownAiApp {
        domain: "cohere.com",
        app: "cohere",
        category: AiAppCategory::ModelPlatform,
    },
    KnownAiApp {
        domain: "cohere.ai",
        app: "cohere",
        category: AiAppCategory::ModelPlatform,
    },
    KnownAiApp {
        domain: "together.ai",
        app: "together",
        category: AiAppCategory::ModelPlatform,
    },
    KnownAiApp {
        domain: "fireworks.ai",
        app: "fireworks",
        category: AiAppCategory::ModelPlatform,
    },
    KnownAiApp {
        domain: "groq.com",
        app: "groq",
        category: AiAppCategory::ModelPlatform,
    },
    KnownAiApp {
        domain: "openrouter.ai",
        app: "openrouter",
        category: AiAppCategory::ModelPlatform,
    },
    KnownAiApp {
        domain: "anyscale.com",
        app: "anyscale",
        category: AiAppCategory::ModelPlatform,
    },
    KnownAiApp {
        domain: "azure.com",
        app: "azure_openai",
        category: AiAppCategory::ModelPlatform,
    },
    // --- Meeting / transcription assistants ---
    KnownAiApp {
        domain: "otter.ai",
        app: "otter",
        category: AiAppCategory::MeetingAssistant,
    },
    KnownAiApp {
        domain: "fireflies.ai",
        app: "fireflies",
        category: AiAppCategory::MeetingAssistant,
    },
    KnownAiApp {
        domain: "fathom.video",
        app: "fathom",
        category: AiAppCategory::MeetingAssistant,
    },
    KnownAiApp {
        domain: "tldv.io",
        app: "tldv",
        category: AiAppCategory::MeetingAssistant,
    },
];

/// Strong AI-app tokens. A host label equal to (or, for the
/// multi-character tokens, containing) one of these marks the
/// destination as a *suspected* AI app. `ai` is handled separately as
/// an exact-label / hyphen-token match to avoid firing on every host
/// that merely contains the bigram (e.g. `email`, `retail`).
const AI_HOST_TOKENS: &[&str] = &[
    "chatgpt",
    "gpt",
    "claude",
    "gemini",
    "copilot",
    "perplexity",
    "llm",
    "genai",
    "chatbot",
    "deepseek",
    "mistral",
    "huggingface",
    "assistant",
];

/// Path fragments that signal a programmatic AI/LLM API call. Combined
/// with an `ai`-ish host they raise the heuristic's confidence; on
/// their own (generic host) they are not enough.
const AI_PATH_TOKENS: &[&str] = &[
    "/v1/chat/completions",
    "/v1/completions",
    "/v1/messages",
    "/v1/embeddings",
    "/api/generate",
    "/api/chat",
    "/chat/completions",
];

/// Split a raw destination (a URL or a bare host) into its lowercased
/// host and path. Returns `("", "")` when no host can be recovered.
/// The query/fragment is discarded entirely — it may contain secrets.
fn split_destination(dest: &str) -> (String, String) {
    let trimmed = dest.trim();
    // Strip an optional scheme.
    let after_scheme = trimmed.split_once("://").map_or(trimmed, |(_, rest)| rest);
    // Authority ends at the first '/', '?' or '#'.
    let auth_end = after_scheme
        .find(['/', '?', '#'])
        .unwrap_or(after_scheme.len());
    let authority = &after_scheme[..auth_end];
    // Path is everything from the slash up to a '?' or '#'.
    let rest = &after_scheme[auth_end..];
    let path_end = rest.find(['?', '#']).unwrap_or(rest.len());
    let path = &rest[..path_end];
    // Drop userinfo (`user:pass@host`) and the port.
    let host_with_port = authority.rsplit_once('@').map_or(authority, |(_, h)| h);
    let host = host_with_port
        .rsplit_once(':')
        .map_or(host_with_port, |(h, _)| h);
    (host.to_ascii_lowercase(), path.to_ascii_lowercase())
}

/// True when `host` equals `domain` or is a subdomain of it (matched on
/// a `.` boundary so `notopenai.com` does not match `openai.com`).
fn host_matches_domain(host: &str, domain: &str) -> bool {
    host == domain || host.ends_with(&format!(".{domain}"))
}

/// Look up `host` in the curated catalog, preferring the **most
/// specific** (longest) matching domain so a subdomain entry
/// (`api.anthropic.com`) wins over its parent (`anthropic.com`)
/// regardless of catalog ordering.
fn known_ai_app(host: &str) -> Option<&'static KnownAiApp> {
    KNOWN_AI_APPS
        .iter()
        .filter(|a| host_matches_domain(host, a.domain))
        .max_by_key(|a| a.domain.len())
}

/// The long-tail heuristic: decide whether a non-catalog `host`/`path`
/// looks like an AI app. Returns the matched category and whether an
/// API path corroborated the host (used only to keep the signal honest
/// in the destination record — confidence stays at the suspected tier).
fn heuristic_ai_app(host: &str, path: &str) -> bool {
    if host.is_empty() {
        return false;
    }
    let labels = host.split('.');
    for label in labels {
        // Hyphenated labels (`my-ai-tool`) are split into tokens so a
        // standalone `ai` is recognised without firing on `email`.
        for token in label.split('-') {
            if token == "ai" {
                return true;
            }
        }
        if AI_HOST_TOKENS.iter().any(|t| label.contains(t)) {
            return true;
        }
    }
    // A generic host that nonetheless posts to a chat/completions API
    // is still an AI upload (e.g. a self-hosted gateway).
    AI_PATH_TOKENS.iter().any(|t| path.contains(t))
}

/// Classify an upload destination (a URL or bare host) as an AI app.
/// Pure and allocation-light; safe to call on the hot path.
#[must_use]
pub fn classify_destination(dest: &str) -> AiAppDestination {
    let (host, path) = split_destination(dest);
    if let Some(app) = known_ai_app(&host) {
        return AiAppDestination {
            kind: AiAppKind::Known,
            app: Some(app.app),
            category: Some(app.category),
            domain: host,
            confidence: DESTINATION_CONFIDENCE_KNOWN,
        };
    }
    if heuristic_ai_app(&host, &path) {
        return AiAppDestination {
            kind: AiAppKind::Suspected,
            app: None,
            category: Some(AiAppCategory::Other),
            domain: host,
            confidence: DESTINATION_CONFIDENCE_SUSPECTED,
        };
    }
    AiAppDestination {
        kind: AiAppKind::NotAiApp,
        app: None,
        category: None,
        domain: host,
        confidence: 0.0,
    }
}

// ---------------------------------------------------------------------------
// Secret scanning
// ---------------------------------------------------------------------------

/// A class of credential the [`SecretScanner`] recognises.
#[derive(Copy, Clone, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SecretKind {
    /// AWS access key id (`AKIA…`, `ASIA…`).
    AwsAccessKeyId,
    /// Google API key (`AIza…`).
    GoogleApiKey,
    /// GitHub personal-access / OAuth / app token (`ghp_`, `gho_`, …).
    GitHubToken,
    /// GitLab personal-access token (`glpat-…`).
    GitLabToken,
    /// Slack token (`xoxb-`, `xoxp-`, …).
    SlackToken,
    /// Stripe live secret key (`sk_live_…`, `rk_live_…`).
    StripeSecretKey,
    /// `OpenAI`-style API key (`sk-…`, `sk-proj-…`).
    OpenAiKey,
    /// Anthropic API key (`sk-ant-…`).
    AnthropicKey,
    /// Twilio Account SID / API-key SID (`AC…`, `SK…` + 32 hex).
    TwilioKey,
    /// `SendGrid` API key (`SG.…`).
    SendGridKey,
    /// npm access token (`npm_…`).
    NpmToken,
    /// A PEM-encoded private key block.
    PrivateKey,
    /// A JSON Web Token (`eyJ….eyJ….…`).
    JsonWebToken,
}

impl SecretKind {
    /// Stable wire id, also used as the finding label.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::AwsAccessKeyId => "aws_access_key_id",
            Self::GoogleApiKey => "google_api_key",
            Self::GitHubToken => "github_token",
            Self::GitLabToken => "gitlab_token",
            Self::SlackToken => "slack_token",
            Self::StripeSecretKey => "stripe_secret_key",
            Self::OpenAiKey => "openai_api_key",
            Self::AnthropicKey => "anthropic_api_key",
            Self::TwilioKey => "twilio_api_key",
            Self::SendGridKey => "sendgrid_api_key",
            Self::NpmToken => "npm_token",
            Self::PrivateKey => "private_key",
            Self::JsonWebToken => "json_web_token",
        }
    }

    /// Severity of an exposed credential of this kind. A private key or
    /// a live cloud/payment key is `Critical`; a JWT (often short-lived
    /// and lower-privilege) is `High`.
    #[must_use]
    pub const fn severity(self) -> Severity {
        match self {
            Self::JsonWebToken => Severity::High,
            _ => Severity::Critical,
        }
    }
}

/// A single secret detection. **Metadata only** — the credential bytes
/// are never retained (see the module redaction invariant).
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct SecretMatch {
    /// The credential class.
    pub kind: SecretKind,
    /// Byte offset of the hit in the scanned text.
    pub offset: usize,
    /// Byte length of the hit.
    pub length: usize,
}

/// One compiled secret pattern.
struct SecretPattern {
    kind: SecretKind,
    regex: Regex,
    /// Minimum Shannon entropy (bits/char) of the matched substring for
    /// the hit to count. Filters illustrative / placeholder values that
    /// share the shape of a real key. `0.0` disables the gate (used for
    /// structurally unambiguous matches like a PEM header).
    min_entropy: f64,
}

/// Shannon entropy in bits per character of `s`. Returns `0.0` for the
/// empty string. Used as a cheap "does this look random enough to be a
/// real key" gate, not as a cryptographic measure.
#[must_use]
fn shannon_entropy(s: &str) -> f64 {
    if s.is_empty() {
        return 0.0;
    }
    let mut counts = [0u32; 256];
    let mut total = 0u32;
    for b in s.bytes() {
        counts[b as usize] += 1;
        total += 1;
    }
    let total_f = f64::from(total);
    let mut entropy = 0.0;
    for &c in &counts {
        if c == 0 {
            continue;
        }
        let p = f64::from(c) / total_f;
        entropy -= p * p.log2();
    }
    entropy
}

/// Compiled scanner for credential material. Construct once with
/// [`SecretScanner::new`]; cheap to call [`SecretScanner::scan`]
/// repeatedly. Uses a [`RegexSet`] so a single pass reports which of
/// the N patterns hit, and only those are re-run to recover spans.
///
/// The patterns are compile-time constants, so construction cannot
/// fail in practice — but it is written to *degrade gracefully* rather
/// than panic: any pattern that fails to compile is dropped, and the
/// scanner simply matches one fewer credential class. Endpoint code
/// never aborts the agent over a detector-catalog bug.
#[derive(Debug)]
pub struct SecretScanner {
    set: Option<RegexSet>,
    patterns: Vec<SecretPattern>,
}

impl std::fmt::Debug for SecretPattern {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("SecretPattern")
            .field("kind", &self.kind)
            .field("min_entropy", &self.min_entropy)
            .finish_non_exhaustive()
    }
}

impl SecretScanner {
    /// Build the scanner with the builtin credential catalog.
    #[must_use]
    pub fn new() -> Self {
        // (kind, pattern, min_entropy). Patterns anchor on the vendor
        // prefix + length; the entropy floor rejects same-shaped
        // placeholders ("AKIAIOSFODNN7EXAMPLE" is the canonical AWS doc
        // key and is intentionally low-entropy enough to be excluded by
        // a real-world tuned floor, but we keep AWS's floor modest so
        // genuine keys are never missed — the prefix alone is strong).
        let specs: &[(SecretKind, &str, f64)] = &[
            (
                SecretKind::AwsAccessKeyId,
                r"\b(?:AKIA|ASIA|AGPA|AIDA|AROA|AIPA|ANPA|ANVA)[0-9A-Z]{16}\b",
                2.5,
            ),
            (SecretKind::GoogleApiKey, r"\bAIza[0-9A-Za-z_\-]{35}\b", 3.0),
            (
                SecretKind::GitHubToken,
                r"\b(?:ghp|gho|ghu|ghs|ghr)_[0-9A-Za-z]{36}\b",
                3.0,
            ),
            (
                SecretKind::GitHubToken,
                r"\bgithub_pat_[0-9A-Za-z_]{22,}\b",
                3.0,
            ),
            (
                SecretKind::GitLabToken,
                r"\bglpat-[0-9A-Za-z_\-]{20,}\b",
                3.0,
            ),
            (
                SecretKind::SlackToken,
                r"\bxox[baprs]-[0-9A-Za-z-]{10,}\b",
                2.5,
            ),
            (
                SecretKind::StripeSecretKey,
                r"\b(?:sk|rk)_live_[0-9A-Za-z]{16,}\b",
                3.0,
            ),
            // Anthropic precedes OpenAI: an `sk-ant-…` key matches both
            // shapes, and `scan` keeps the specific Anthropic kind for
            // any span both report.
            (
                SecretKind::AnthropicKey,
                r"\bsk-ant-[0-9A-Za-z_\-]{20,}\b",
                3.5,
            ),
            (
                SecretKind::OpenAiKey,
                r"\bsk-(?:proj-)?[0-9A-Za-z_\-]{20,}\b",
                3.5,
            ),
            (SecretKind::TwilioKey, r"\b(?:AC|SK)[0-9a-f]{32}\b", 3.0),
            (
                SecretKind::SendGridKey,
                r"\bSG\.[0-9A-Za-z_\-]{22}\.[0-9A-Za-z_\-]{43}\b",
                3.5,
            ),
            (SecretKind::NpmToken, r"\bnpm_[0-9A-Za-z]{36}\b", 3.0),
            (
                SecretKind::PrivateKey,
                r"-----BEGIN (?:RSA |EC |DSA |OPENSSH |PGP |ENCRYPTED )?PRIVATE KEY-----",
                0.0,
            ),
            (
                SecretKind::JsonWebToken,
                r"\beyJ[0-9A-Za-z_\-]+\.eyJ[0-9A-Za-z_\-]+\.[0-9A-Za-z_\-]+\b",
                3.5,
            ),
        ];
        let mut patterns = Vec::with_capacity(specs.len());
        let mut raw = Vec::with_capacity(specs.len());
        for &(kind, pat, min_entropy) in specs {
            // Drop (rather than panic on) any pattern that fails to
            // compile so a catalog bug degrades detection by one class
            // instead of crashing the endpoint agent. `raw` and
            // `patterns` stay index-aligned because both are pushed
            // together only on success.
            if let Ok(regex) = Regex::new(pat) {
                raw.push(pat.to_string());
                patterns.push(SecretPattern {
                    kind,
                    regex,
                    min_entropy,
                });
            }
        }
        let set = RegexSet::new(&raw).ok();
        Self { set, patterns }
    }

    /// Scan `text`, returning one [`SecretMatch`] per credential hit
    /// that clears its entropy floor.
    #[must_use]
    pub fn scan(&self, text: &str) -> Vec<SecretMatch> {
        let mut out = Vec::new();
        let Some(set) = &self.set else {
            return out;
        };
        for idx in set.matches(text) {
            let Some(p) = self.patterns.get(idx) else {
                continue;
            };
            for m in p.regex.find_iter(text) {
                if p.min_entropy > 0.0 && shannon_entropy(m.as_str()) < p.min_entropy {
                    continue;
                }
                out.push(SecretMatch {
                    kind: p.kind,
                    offset: m.start(),
                    length: m.end() - m.start(),
                });
            }
        }
        // An `sk-ant-…` key matches both the specific Anthropic shape and
        // the broader OpenAI `sk-…` shape. Keep only the Anthropic kind
        // for any span both reported, so the credential is labeled once,
        // with the correct vendor.
        let ant_spans: Vec<(usize, usize)> = out
            .iter()
            .filter(|m| m.kind == SecretKind::AnthropicKey)
            .map(|m| (m.offset, m.length))
            .collect();
        out.retain(|m| {
            m.kind != SecretKind::OpenAiKey || !ant_spans.contains(&(m.offset, m.length))
        });
        out
    }
}

impl Default for SecretScanner {
    fn default() -> Self {
        Self::new()
    }
}

// ---------------------------------------------------------------------------
// Company-confidential markers
// ---------------------------------------------------------------------------

/// A company-confidential banner hit. **Metadata only.** Serialise-only
/// (carries a `&'static` marker label).
#[derive(Clone, Debug, PartialEq, Serialize)]
pub struct MarkerMatch {
    /// The canonical marker label (e.g. `confidential`).
    pub marker: &'static str,
    /// Severity of the marker.
    pub severity: Severity,
    /// Byte offset of the hit in the (lowercased) scanned text.
    pub offset: usize,
    /// Byte length of the hit.
    pub length: usize,
}

/// One confidential-marker phrase and the label/severity it maps to.
struct ConfidentialMarker {
    /// The phrase to match (matched case-insensitively).
    phrase: &'static str,
    /// Canonical label reported for any of the phrase's variants.
    label: &'static str,
    /// Severity of the marker.
    severity: Severity,
}

/// The builtin catalog of company-confidential banners. Phrases are
/// matched leftmost-longest and case-insensitively. Multiple phrases
/// can map to the same `label` so synonyms aggregate together.
const CONFIDENTIAL_MARKERS: &[ConfidentialMarker] = &[
    ConfidentialMarker {
        phrase: "company confidential",
        label: "confidential",
        severity: Severity::High,
    },
    ConfidentialMarker {
        phrase: "strictly confidential",
        label: "confidential",
        severity: Severity::High,
    },
    ConfidentialMarker {
        phrase: "confidential",
        label: "confidential",
        severity: Severity::Medium,
    },
    ConfidentialMarker {
        phrase: "internal use only",
        label: "internal_only",
        severity: Severity::Medium,
    },
    ConfidentialMarker {
        phrase: "internal only",
        label: "internal_only",
        severity: Severity::Medium,
    },
    ConfidentialMarker {
        phrase: "for internal use",
        label: "internal_only",
        severity: Severity::Medium,
    },
    ConfidentialMarker {
        phrase: "proprietary and confidential",
        label: "proprietary",
        severity: Severity::High,
    },
    ConfidentialMarker {
        phrase: "proprietary",
        label: "proprietary",
        severity: Severity::Medium,
    },
    ConfidentialMarker {
        phrase: "trade secret",
        label: "trade_secret",
        severity: Severity::High,
    },
    ConfidentialMarker {
        phrase: "do not distribute",
        label: "do_not_distribute",
        severity: Severity::High,
    },
    ConfidentialMarker {
        phrase: "do not share",
        label: "do_not_distribute",
        severity: Severity::Medium,
    },
    ConfidentialMarker {
        phrase: "attorney-client privileged",
        label: "privileged",
        severity: Severity::High,
    },
    ConfidentialMarker {
        phrase: "attorney client privileged",
        label: "privileged",
        severity: Severity::High,
    },
    ConfidentialMarker {
        phrase: "privileged and confidential",
        label: "privileged",
        severity: Severity::High,
    },
];

/// Compiled scanner for company-confidential banners. Folds every
/// phrase into a single leftmost-longest [`AhoCorasick`] automaton, so
/// the whole catalog costs one pass over the content. Like
/// [`SecretScanner`] it degrades gracefully: if the automaton fails to
/// build it simply matches nothing rather than panicking.
#[derive(Debug)]
pub struct ConfidentialScanner {
    ac: Option<AhoCorasick>,
}

impl ConfidentialScanner {
    /// Build the scanner with the builtin marker catalog.
    #[must_use]
    pub fn new() -> Self {
        let ac = AhoCorasick::builder()
            .match_kind(MatchKind::LeftmostLongest)
            .ascii_case_insensitive(true)
            .build(CONFIDENTIAL_MARKERS.iter().map(|m| m.phrase))
            .ok();
        Self { ac }
    }

    /// Scan `text` for confidential banners. Offsets are into `text` as
    /// supplied by the caller.
    #[must_use]
    pub fn scan(&self, text: &str) -> Vec<MarkerMatch> {
        let mut out = Vec::new();
        let Some(ac) = &self.ac else {
            return out;
        };
        for m in ac.find_iter(text) {
            let Some(marker) = CONFIDENTIAL_MARKERS.get(m.pattern().as_usize()) else {
                continue;
            };
            out.push(MarkerMatch {
                marker: marker.label,
                severity: marker.severity,
                offset: m.start(),
                length: m.end() - m.start(),
            });
        }
        out
    }
}

impl Default for ConfidentialScanner {
    fn default() -> Self {
        Self::new()
    }
}

// ---------------------------------------------------------------------------
// Policy + detector
// ---------------------------------------------------------------------------

/// Operator policy for the AI-app exfiltration signal. The default is
/// deliberately **coach-first and non-blocking**: it monitors and
/// coaches but never blocks until an operator opts in.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct AiAppPolicy {
    /// Master switch. When `false` the detector returns
    /// [`AiAppAction::Monitor`] with no findings (a pure no-op).
    pub enabled: bool,
    /// Whether the operator has explicitly opted in to *blocking*.
    /// Until this is `true`, the signal can never produce
    /// [`AiAppAction::Block`] — the false-positive-averse default.
    pub block_opt_in: bool,
    /// Confidence at or above which a flagged upload may escalate to
    /// block (only when `block_opt_in` and the destination is *known*).
    pub block_confidence: f64,
    /// Confidence below which an upload is not flagged at all (silently
    /// monitored). Caps the long-tail heuristic's false-positive blast
    /// radius.
    pub min_report_confidence: f64,
    /// Severity at or above which a flagged upload is surfaced as a
    /// coaching nudge rather than silently monitored. Secrets always
    /// coach regardless of this floor.
    pub coach_severity_floor: Severity,
    /// Destination apps an operator has confirmed should be blocked
    /// (via a `block` decision in the HITL review queue). A sensitive
    /// upload to any app in this set escalates straight to
    /// [`AiAppAction::Block`], independent of [`Self::block_opt_in`] and
    /// the known/critical gate — the operator has already made the call.
    /// Keyed by the catalog app id, or the [`SUSPECTED_AI_APP`] sentinel
    /// for heuristic (unknown) destinations. Empty by default and
    /// omitted from the wire when empty.
    #[serde(default, skip_serializing_if = "BTreeSet::is_empty")]
    pub blocked_apps: BTreeSet<String>,
}

impl Default for AiAppPolicy {
    fn default() -> Self {
        Self {
            enabled: true,
            block_opt_in: false,
            block_confidence: 0.9,
            min_report_confidence: 0.5,
            coach_severity_floor: Severity::High,
            blocked_apps: BTreeSet::new(),
        }
    }
}

/// The action the detector recommends for a flagged AI-app upload.
/// Ordered by user impact: [`Self::Monitor`] < [`Self::Coach`] <
/// [`Self::Block`].
#[derive(Copy, Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AiAppAction {
    /// Record the event for audit; do not interrupt the user.
    Monitor,
    /// Surface a non-blocking coaching nudge the user can dismiss.
    Coach,
    /// Refuse the upload. Only ever produced when the operator has
    /// opted in and the signal cleared the high-confidence bar.
    Block,
}

impl AiAppAction {
    /// The equivalent rule action, for mapping into a [`DlpVerdict`].
    /// `Monitor` → `Log`, `Coach` → `Warn`, `Block` → `Block`.
    #[must_use]
    pub const fn as_rule_action(self) -> RuleAction {
        match self {
            Self::Monitor => RuleAction::Log,
            Self::Coach => RuleAction::Warn,
            Self::Block => RuleAction::Block,
        }
    }
}

/// An aggregated, redacted finding for one detector class within a
/// signal: how many times it hit, the strongest confidence, and its
/// severity. This is the per-class roll-up an operator triages and the
/// control plane persists — never the matched content.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct FindingSummary {
    /// The finding family.
    pub kind: FindingKind,
    /// The detector label within the family (e.g. `ssn_us`,
    /// `aws_access_key_id`, `confidential`).
    pub label: String,
    /// Number of hits of this label.
    pub count: usize,
    /// Strongest confidence across the hits, `0.0..=1.0`.
    pub max_confidence: f64,
    /// Severity of the finding.
    pub severity: Severity,
}

/// The family a [`FindingSummary`] belongs to.
#[derive(Copy, Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum FindingKind {
    /// Personally-identifiable information (reused PII detectors).
    Pii,
    /// A credential / secret.
    Secret,
    /// A company-confidential banner.
    Confidential,
}

/// The result of inspecting one AI-app upload. Serialisable and
/// metadata-only: safe to emit as telemetry or persist as
/// `evidence_redacted` for the human review queue. Serialise-only.
#[derive(Clone, Debug, PartialEq, Serialize)]
pub struct AiAppSignal {
    /// The classified destination.
    pub destination: AiAppDestination,
    /// The recommended action (coach-first).
    pub action: AiAppAction,
    /// Overall severity (max across findings).
    pub severity: Severity,
    /// Overall confidence this is a real exfiltration, `0.0..=1.0`.
    pub confidence: f64,
    /// Aggregated, redacted per-class findings.
    pub findings: Vec<FindingSummary>,
    /// Number of bytes actually scanned (post scan-ceiling truncation).
    pub scanned_bytes: usize,
    /// Whether the content was truncated at the scan ceiling.
    pub truncated: bool,
}

impl AiAppSignal {
    /// Whether the upload was flagged (the destination is an AI app and
    /// the signal cleared the report threshold). A non-flagged signal
    /// is always [`AiAppAction::Monitor`] with no findings.
    #[must_use]
    pub fn is_flagged(&self) -> bool {
        self.action != AiAppAction::Monitor || !self.findings.is_empty()
    }

    /// Whether the recommended action blocks the upload.
    #[must_use]
    pub const fn is_blocking(&self) -> bool {
        matches!(self.action, AiAppAction::Block)
    }

    /// Project this signal onto the redacted [`sng_core::DlpEvent`] wire
    /// type the control plane consumes (its human-in-the-loop review
    /// queue producer half). The projection is metadata-only by
    /// construction — it copies the destination app id, severity,
    /// confidence, and per-class finding *summaries*, never any matched
    /// bytes — so it preserves the same redaction invariant the signal
    /// itself enforces.
    ///
    /// A heuristic (`Suspected`) destination with no catalog id maps to
    /// the [`SUSPECTED_AI_APP`] sentinel, matching the Go side's
    /// `dlpreview.SuspectedAppSentinel`.
    ///
    /// # Precondition
    /// Only ever projected for *flagged* signals (see [`Self::is_flagged`]).
    /// A flagged signal always has an AI-app destination, because a
    /// non-AI destination skips the content scan entirely and short-
    /// circuits to `Monitor` with no findings (so it is never flagged
    /// and never reaches the wire). The `SUSPECTED_AI_APP` fallback is
    /// therefore only applied to a genuinely *suspected* AI app, never
    /// mislabelling a non-AI destination. The debug assertion encodes
    /// this invariant so any future caller that projects a non-flagged
    /// signal is caught in tests rather than emitting a misleading
    /// destination label.
    #[must_use]
    pub fn to_wire_event(&self) -> sng_core::DlpEvent {
        debug_assert!(
            self.destination.is_ai_app(),
            "to_wire_event projected for a non-AI-app destination ({:?}); \
             only flagged signals (always AI-app) should reach the wire",
            self.destination.kind,
        );
        sng_core::DlpEvent {
            destination_app: self.destination.app.unwrap_or(SUSPECTED_AI_APP).to_string(),
            action: self.action.to_wire(),
            severity: self.severity.as_str().to_string(),
            confidence: self.confidence,
            findings: self.findings.iter().map(FindingSummary::to_wire).collect(),
            scanned_bytes: self.scanned_bytes as u64,
            truncated: self.truncated,
        }
    }
}

/// The `destination_app` value emitted for a heuristic (`Suspected`)
/// AI-app match that carries no catalog id. Must stay in sync with the
/// Go `internal/service/dlpreview.SuspectedAppSentinel`.
pub const SUSPECTED_AI_APP: &str = "suspected_ai_app";

impl AiAppAction {
    /// Project onto the [`sng_core::DlpAction`] wire enum.
    #[must_use]
    pub const fn to_wire(self) -> sng_core::DlpAction {
        match self {
            Self::Monitor => sng_core::DlpAction::Monitor,
            Self::Coach => sng_core::DlpAction::Coach,
            Self::Block => sng_core::DlpAction::Block,
        }
    }
}

impl FindingKind {
    /// Project onto the [`sng_core::DlpFindingKind`] wire enum.
    #[must_use]
    pub const fn to_wire(self) -> sng_core::DlpFindingKind {
        match self {
            Self::Pii => sng_core::DlpFindingKind::Pii,
            Self::Secret => sng_core::DlpFindingKind::Secret,
            Self::Confidential => sng_core::DlpFindingKind::Confidential,
        }
    }
}

impl FindingSummary {
    /// Project onto the redacted [`sng_core::DlpFinding`] wire row.
    #[must_use]
    pub fn to_wire(&self) -> sng_core::DlpFinding {
        sng_core::DlpFinding {
            kind: self.kind.to_wire(),
            label: self.label.clone(),
            // Match counts are tiny in practice; saturate rather than
            // wrap on the (impossible) overflow so the wire value is
            // never silently truncated to a small number.
            count: u32::try_from(self.count).unwrap_or(u32::MAX),
            max_confidence: self.max_confidence,
            severity: self.severity.as_str().to_string(),
        }
    }
}

/// Per-class accumulator used while aggregating raw matches into
/// [`FindingSummary`] rows, keyed by `(kind, label)`.
struct FindingAcc {
    kind: FindingKind,
    label: String,
    count: usize,
    max_confidence: f64,
    severity: Severity,
}

/// The AI-app exfiltration detector. Holds the reused PII classifier
/// plus the secret and confidential scanners, and applies the coach-
/// first [`AiAppPolicy`] to turn raw matches into an [`AiAppSignal`].
///
/// Construct once (it compiles the full detector catalog) and reuse
/// across uploads; [`Self::inspect`] is read-only and allocation-light.
#[derive(Debug)]
pub struct AiAppExfilDetector {
    classifier: ContentClassifier,
    secrets: SecretScanner,
    confidential: ConfidentialScanner,
    policy: AiAppPolicy,
    /// Scan ceiling for the secret/confidential passes, taken from the
    /// classifier so all three passes bound the same byte range (a
    /// custom engine ceiling no longer diverges from a hardcoded
    /// default).
    max_scan_bytes: usize,
}

impl AiAppExfilDetector {
    /// Build a detector with the default reused-PII classifier and the
    /// supplied policy.
    ///
    /// # Errors
    /// Returns [`crate::error::DlpError::RuleCompile`] only if the
    /// builtin PII rule set fails to compile, which indicates a bug in
    /// the catalog (the unit tests guard against it).
    pub fn new(policy: AiAppPolicy) -> DlpResult<Self> {
        let classifier = ContentClassifier::compile(&default_pii_rules())?;
        Ok(Self::with_classifier(classifier, policy))
    }

    /// Build a detector with a caller-supplied classifier (e.g. one
    /// compiled with a signed ML-NER model attached) and policy. Use
    /// this to share the engine's model-backed classifier instead of
    /// the default fallback-only one.
    #[must_use]
    pub fn with_classifier(classifier: ContentClassifier, policy: AiAppPolicy) -> Self {
        let max_scan_bytes = classifier.max_scan_bytes();
        Self {
            classifier,
            secrets: SecretScanner::new(),
            confidential: ConfidentialScanner::new(),
            policy,
            max_scan_bytes,
        }
    }

    /// The active policy.
    #[must_use]
    pub const fn policy(&self) -> &AiAppPolicy {
        &self.policy
    }

    /// The egress channel AI-app uploads are observed on. The DLP
    /// engine consults the detector only for events on this channel, so
    /// the coupling between "AI upload" and the reused contextual scorer
    /// is documented in exactly one place ([`AI_UPLOAD_CHANNEL`]).
    #[must_use]
    pub const fn channel() -> DlpChannel {
        AI_UPLOAD_CHANNEL
    }

    /// Inspect a request `body` bound for `destination`, returning the
    /// coach-first [`AiAppSignal`]. `metadata` is the same out-of-band
    /// context the engine threads through classification (device
    /// posture, time of day, MIP labels, …); the destination host is
    /// also recorded into a copy of it so the reused contextual scorer
    /// and any MIP-label rules see it.
    #[must_use]
    pub fn inspect(
        &self,
        destination: &str,
        body: &[u8],
        metadata: &ContentMetadata,
    ) -> AiAppSignal {
        let dest = classify_destination(destination);

        // Master switch: a disabled detector is a pure no-op that still
        // reports the destination classification for observability.
        if !self.policy.enabled {
            return AiAppSignal {
                destination: dest,
                action: AiAppAction::Monitor,
                severity: Severity::Low,
                confidence: 0.0,
                findings: Vec::new(),
                scanned_bytes: 0,
                truncated: false,
            };
        }

        // This signal is scoped to AI-app destinations. For anything
        // else we do not scan at all — that egress path is the channel
        // DLP engine's responsibility, and skipping the scan keeps the
        // detector off the hot path for the overwhelming majority of
        // (non-AI) traffic.
        if !dest.is_ai_app() {
            return AiAppSignal {
                destination: dest,
                action: AiAppAction::Monitor,
                severity: Severity::Low,
                confidence: 0.0,
                findings: Vec::new(),
                scanned_bytes: 0,
                truncated: false,
            };
        }

        // Reuse the full content classifier for PII. The destination is
        // stamped onto the metadata source so it feeds the audit trail.
        let mut meta = metadata.clone();
        if meta.source.is_none() && !dest.domain.is_empty() {
            meta.source = Some(dest.domain.clone());
        }
        let result = self.classifier.classify(AI_UPLOAD_CHANNEL, body, &meta);

        // Secret + confidential scanners run on the same lossy-decoded
        // text the classifier inspects (bounded by the same ceiling).
        let scanned = &body[..body.len().min(self.max_scan_bytes)];
        let truncated = body.len() > scanned.len();
        let text = String::from_utf8_lossy(scanned);
        let secret_hits = self.secrets.scan(&text);
        let marker_hits = self.confidential.scan(&text);

        let findings = aggregate_findings(&result.matches, &secret_hits, &marker_hits);

        // Content-side confidence/severity from the strongest finding.
        let content_confidence = findings
            .iter()
            .map(|f| f.max_confidence)
            .fold(0.0_f64, f64::max);
        let severity = findings
            .iter()
            .map(|f| f.severity)
            .max()
            .unwrap_or(Severity::Low);
        let has_secret = findings.iter().any(|f| f.kind == FindingKind::Secret);

        // Overall confidence couples "destination is an AI app" with
        // "content is sensitive": both must hold for an exfiltration.
        let confidence = (dest.confidence * content_confidence).clamp(0.0, 1.0);

        let action = self.decide_action(&dest, &findings, severity, confidence, has_secret);

        AiAppSignal {
            destination: dest,
            action,
            severity,
            confidence,
            findings,
            scanned_bytes: scanned.len(),
            truncated,
        }
    }

    /// Apply the coach-first policy to choose an action.
    fn decide_action(
        &self,
        dest: &AiAppDestination,
        findings: &[FindingSummary],
        severity: Severity,
        confidence: f64,
        has_secret: bool,
    ) -> AiAppAction {
        // Not an AI app, nothing sensitive, or below the report bar:
        // silently monitor. This is where the long-tail heuristic's
        // false positives are absorbed without bothering the user.
        if !dest.is_ai_app()
            || findings.is_empty()
            || confidence < self.policy.min_report_confidence
        {
            return AiAppAction::Monitor;
        }

        // Operator-confirmed block: a reviewer has explicitly blocked
        // this destination app via the HITL review queue, so sensitive
        // uploads to it escalate straight to Block — independent of the
        // block_opt_in / known / critical gate below. The report-
        // confidence floor above still applies, so a sub-threshold noise
        // match to a blocked app is not blocked. A suspected (unknown)
        // destination is keyed by the SUSPECTED_AI_APP sentinel, matching
        // the wire projection in `to_wire_event`.
        let effective_app = dest.app.unwrap_or(SUSPECTED_AI_APP);
        if self.policy.blocked_apps.contains(effective_app) {
            return AiAppAction::Block;
        }

        // Escalation to block is the exception, not the rule: it
        // requires an explicit operator opt-in, a high-confidence
        // signal, a *known* (not merely suspected) destination, and a
        // genuinely severe finding (a live secret or critical PII).
        let block_eligible = self.policy.block_opt_in
            && dest.kind == AiAppKind::Known
            && confidence >= self.policy.block_confidence
            && (has_secret || severity >= Severity::Critical);
        if block_eligible {
            return AiAppAction::Block;
        }

        // Otherwise coach when the finding is notable (severe enough, or
        // any secret), and monitor the rest.
        if has_secret || severity >= self.policy.coach_severity_floor {
            AiAppAction::Coach
        } else {
            AiAppAction::Monitor
        }
    }

    /// Inspect and project straight onto the crate's [`DlpVerdict`] so
    /// the AI-app signal can flow through the same enforcement path as
    /// channel verdicts. A non-flagged result maps to
    /// [`DlpVerdict::Allow`]; otherwise the action maps
    /// `Monitor → LogOnly`, `Coach → WarnUser`, `Block → Block`, and the
    /// verdict carries the reused match provenance (metadata only).
    #[must_use]
    pub fn verdict(
        &self,
        destination: &str,
        body: &[u8],
        metadata: &ContentMetadata,
    ) -> DlpVerdict {
        self.inspect_with_verdict(destination, body, metadata).1
    }

    /// Inspect once and return both the redacted [`AiAppSignal`] and its
    /// projected [`DlpVerdict`]. The two views share a single inspection
    /// pass (no double scan): the verdict drives edge enforcement while
    /// the signal is the redacted record the control plane's review
    /// queue ingests. Callers that only need one view use [`Self::verdict`]
    /// or [`Self::inspect`]; callers wiring both enforcement *and*
    /// telemetry (the agent DLP subsystem) use this.
    #[must_use]
    pub fn inspect_with_verdict(
        &self,
        destination: &str,
        body: &[u8],
        metadata: &ContentMetadata,
    ) -> (AiAppSignal, DlpVerdict) {
        let signal = self.inspect(destination, body, metadata);
        let verdict = signal_to_verdict(
            &signal,
            body,
            metadata,
            &self.classifier,
            &self.secrets,
            &self.confidential,
        );
        (signal, verdict)
    }
}

/// Build a [`DlpVerdict`] from a finished [`AiAppSignal`], recovering
/// the raw match spans for verdict provenance. The spans are re-derived
/// here (rather than stored on the signal) so the serialisable
/// [`AiAppSignal`] stays a pure aggregate.
fn signal_to_verdict(
    signal: &AiAppSignal,
    body: &[u8],
    metadata: &ContentMetadata,
    classifier: &ContentClassifier,
    secrets: &SecretScanner,
    confidential: &ConfidentialScanner,
) -> DlpVerdict {
    // A non-flagged signal carries no enforceable verdict. `is_flagged`
    // already means "action != Monitor or there are findings", so the
    // negation covers the monitor-with-no-findings case on its own.
    if !signal.is_flagged() {
        return DlpVerdict::Allow;
    }
    let action = signal.action.as_rule_action();
    let mut meta = metadata.clone();
    if meta.source.is_none() && !signal.destination.domain.is_empty() {
        meta.source = Some(signal.destination.domain.clone());
    }
    let pii = classifier.classify(AI_UPLOAD_CHANNEL, body, &meta).matches;
    // Same ceiling the classifier used, so the recovered secret/marker
    // spans align with the PII spans rather than a hardcoded default.
    let scanned = &body[..body.len().min(classifier.max_scan_bytes())];
    let text = String::from_utf8_lossy(scanned);
    let mut matches: Vec<RuleMatch> = pii;
    for s in secrets.scan(&text) {
        matches.push(RuleMatch {
            rule_id: format!("ai_app.secret.{}", s.kind.as_str()),
            pattern_type: PatternType::Regex,
            severity: s.kind.severity(),
            action,
            confidence: SECRET_CONFIDENCE,
            offset: Some(s.offset),
            length: Some(s.length),
        });
    }
    for m in confidential.scan(&text) {
        matches.push(RuleMatch {
            rule_id: format!("ai_app.confidential.{}", m.marker),
            pattern_type: PatternType::Keyword,
            severity: m.severity,
            action,
            confidence: CONFIDENTIAL_CONFIDENCE,
            offset: Some(m.offset),
            length: Some(m.length),
        });
    }
    let details = VerdictDetails {
        channel: AI_UPLOAD_CHANNEL,
        action,
        severity: signal.severity,
        matches,
    };
    match signal.action {
        AiAppAction::Monitor => DlpVerdict::LogOnly(details),
        AiAppAction::Coach => DlpVerdict::WarnUser(details),
        AiAppAction::Block => DlpVerdict::Block(details),
    }
}

/// Aggregate raw matches into per-class [`FindingSummary`] rows. PII
/// rule ids are emitted by the default rule set as `pii.<name>`; the
/// `pii.` prefix is stripped so the label is the detector name.
fn aggregate_findings(
    pii: &[RuleMatch],
    secrets: &[SecretMatch],
    markers: &[MarkerMatch],
) -> Vec<FindingSummary> {
    let mut accs: Vec<FindingAcc> = Vec::new();

    let mut bump = |kind: FindingKind, label: &str, confidence: f64, severity: Severity| {
        if let Some(a) = accs.iter_mut().find(|a| a.kind == kind && a.label == label) {
            a.count += 1;
            a.max_confidence = a.max_confidence.max(confidence);
            a.severity = a.severity.max(severity);
        } else {
            accs.push(FindingAcc {
                kind,
                label: label.to_string(),
                count: 1,
                max_confidence: confidence,
                severity,
            });
        }
    };

    for m in pii {
        let label = m.rule_id.strip_prefix("pii.").unwrap_or(&m.rule_id);
        bump(FindingKind::Pii, label, m.confidence, m.severity);
    }
    for s in secrets {
        bump(
            FindingKind::Secret,
            s.kind.as_str(),
            SECRET_CONFIDENCE,
            s.kind.severity(),
        );
    }
    for m in markers {
        bump(
            FindingKind::Confidential,
            m.marker,
            CONFIDENTIAL_CONFIDENCE,
            m.severity,
        );
    }

    let mut out: Vec<FindingSummary> = accs
        .into_iter()
        .map(|a| FindingSummary {
            kind: a.kind,
            label: a.label,
            count: a.count,
            max_confidence: a.max_confidence,
            severity: a.severity,
        })
        .collect();
    // Stable, deterministic ordering: strongest severity first, then
    // label, so the operator-facing roll-up and tests are reproducible.
    out.sort_by(|a, b| {
        b.severity
            .cmp(&a.severity)
            .then_with(|| a.kind.cmp_key().cmp(&b.kind.cmp_key()))
            .then_with(|| a.label.cmp(&b.label))
    });
    out
}

impl FindingKind {
    /// A stable sort key for deterministic finding ordering.
    const fn cmp_key(self) -> u8 {
        match self {
            Self::Secret => 0,
            Self::Pii => 1,
            Self::Confidential => 2,
        }
    }
}

/// Severity assigned to a PII detector when it appears in the default
/// AI-app rule set. National / regional identifiers and financial /
/// medical identifiers are `High`; contactability data (email, phone)
/// is `Low`; the rest default to `Medium`.
fn pii_severity(name: &str) -> Severity {
    match name {
        "email" | "phone" => Severity::Low,
        "drivers_license" | "swift" | "routing_number" | "icd10" | "mrn" => Severity::Medium,
        _ => Severity::High,
    }
}

/// The default PII rule set: one regex rule per builtin + jurisdiction
/// detector (deduplicated by name), plus a single ML-NER rule over the
/// high-signal identifier entity classes. Rule ids are `pii.<name>` so
/// [`aggregate_findings`] can recover the detector name as the label.
///
/// This is how the AI-app signal "reuses the existing detectors": the
/// jurisdiction catalog ([`crate::detectors::registry`]) is enumerated
/// programmatically, so any detector added there is automatically
/// covered on the AI-upload path with no change here.
#[must_use]
pub fn default_pii_rules() -> Vec<DlpRule> {
    // Generic builtins (not in the jurisdiction registry).
    const GENERIC: &[&str] = &[
        "credit_card",
        "ssn_us",
        "passport_us",
        "drivers_license",
        "email",
        "phone",
        "iban",
        "swift",
        "routing_number",
        "icd10",
        "mrn",
        "china_resident_id",
        "japan_my_number",
        "korea_rrn",
        "singapore_nric",
        "malaysia_mykad",
        "thailand_id",
        "india_aadhaar",
        "india_pan",
        "uae_emirates_id",
        "saudi_id",
        "qatar_qid",
        "kuwait_civil_id",
        "bahrain_cpr",
    ];

    let mut names: Vec<&str> = Vec::new();
    let mut seen = std::collections::BTreeSet::new();
    for &n in GENERIC {
        if seen.insert(n) {
            names.push(n);
        }
    }
    for d in detectors::registry() {
        if seen.insert(d.name) {
            names.push(d.name);
        }
    }

    let mut rules: Vec<DlpRule> = names
        .into_iter()
        .map(|name| DlpRule {
            id: format!("pii.{name}"),
            name: format!("AI-app PII: {name}"),
            pattern_type: PatternType::Regex,
            pattern_data: name.to_string(),
            severity: pii_severity(name),
            // The underlying action is irrelevant to the AI-app decision
            // (which arbitrates on severity + confidence); Log keeps the
            // reused classifier's contextual scoring intact.
            action: RuleAction::Log,
            channels: Vec::new(),
        })
        .collect();

    // A single ML-NER rule over the structured-identifier entity
    // classes (names/addresses/phones are excluded — too common in chat
    // prose to be a useful exfiltration signal on their own).
    let ner_classes = [
        EntityClass::BankAccount,
        EntityClass::MedicalRecord,
        EntityClass::MedicalRecordNumber,
        EntityClass::DriverLicense,
        EntityClass::TaxId,
        EntityClass::DateOfBirth,
        EntityClass::PassportNumber,
        EntityClass::NationalId,
    ];
    let ner_data = ner_classes
        .iter()
        .map(|c| c.as_wire())
        .collect::<Vec<_>>()
        .join(",");
    rules.push(DlpRule {
        id: "pii.ml_ner".to_string(),
        name: "AI-app PII: ml_ner".to_string(),
        pattern_type: PatternType::MlNer,
        pattern_data: ner_data,
        severity: Severity::High,
        action: RuleAction::Log,
        channels: Vec::new(),
    });

    rules
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::classifier::DevicePosture;

    fn detector() -> AiAppExfilDetector {
        AiAppExfilDetector::new(AiAppPolicy::default()).expect("detector compiles")
    }

    // --- Destination classification ---------------------------------

    #[test]
    fn known_apps_classify_with_full_confidence() {
        for (url, app) in [
            ("https://chat.openai.com/c/abc", "chatgpt"),
            ("https://claude.ai/chat/123", "claude"),
            ("api.anthropic.com/v1/messages", "anthropic_api"),
            ("https://github.com/foo/bar", "github_copilot"),
            ("https://huggingface.co/models", "huggingface"),
        ] {
            let d = classify_destination(url);
            assert_eq!(d.kind, AiAppKind::Known, "{url}");
            assert_eq!(d.app, Some(app), "{url}");
            assert_eq!(d.confidence, DESTINATION_CONFIDENCE_KNOWN);
        }
    }

    #[test]
    fn long_tail_hosts_are_suspected() {
        for url in [
            "https://my-ai-assistant.example.com/upload",
            "https://chatbot.acme.io",
            "https://notes.example.com/api/chat",
            "https://gptforwork.example.org",
            "https://ai.startup.dev",
        ] {
            let d = classify_destination(url);
            assert_eq!(d.kind, AiAppKind::Suspected, "{url}");
            assert_eq!(d.confidence, DESTINATION_CONFIDENCE_SUSPECTED);
            assert!(d.is_ai_app());
        }
    }

    #[test]
    fn non_ai_hosts_do_not_false_positive() {
        for url in [
            "https://mail.example.com/inbox",
            "https://retail.shop.com",
            "https://drive.google.com/file",
            "https://email.company.com",
            "",
        ] {
            let d = classify_destination(url);
            assert_eq!(d.kind, AiAppKind::NotAiApp, "{url}");
            assert!(!d.is_ai_app(), "{url}");
        }
    }

    #[test]
    fn subdomain_boundary_is_respected() {
        // `notopenai.com` must not match `openai.com`.
        let d = classify_destination("https://notopenai.com/x");
        assert_ne!(d.kind, AiAppKind::Known);
    }

    #[test]
    fn destination_never_retains_path_or_query() {
        let d = classify_destination("https://user:pw@chat.openai.com:443/c/abc?token=sk-secret");
        assert_eq!(d.domain, "chat.openai.com");
    }

    // --- Secret scanning --------------------------------------------

    #[test]
    fn secret_scanner_finds_keyed_credentials() {
        let s = SecretScanner::new();
        let text = "aws AKIAIOSFODNN7EXAMPLE token ghp_abcdefghijklmnopqrstuvwxyz0123456789 done";
        let kinds: Vec<SecretKind> = s.scan(text).into_iter().map(|m| m.kind).collect();
        assert!(kinds.contains(&SecretKind::AwsAccessKeyId), "{kinds:?}");
        assert!(kinds.contains(&SecretKind::GitHubToken), "{kinds:?}");
    }

    #[test]
    fn secret_scanner_detects_private_key_header() {
        let s = SecretScanner::new();
        let hits = s.scan("-----BEGIN RSA PRIVATE KEY-----\nMIIE...\n");
        assert_eq!(hits.len(), 1);
        assert_eq!(hits[0].kind, SecretKind::PrivateKey);
    }

    #[test]
    fn secret_scanner_entropy_gate_rejects_low_entropy() {
        let s = SecretScanner::new();
        // Shaped like an OpenAI key but trivially low entropy: gated out.
        let hits = s.scan("sk-aaaaaaaaaaaaaaaaaaaaaaaa");
        assert!(
            hits.is_empty(),
            "low-entropy placeholder should be rejected: {hits:?}"
        );
    }

    #[test]
    fn secret_scanner_never_returns_bytes() {
        // The match type carries only offset/length, not the secret.
        let s = SecretScanner::new();
        let hits = s.scan("ghp_abcdefghijklmnopqrstuvwxyz0123456789");
        assert_eq!(hits.len(), 1);
        assert!(hits[0].length > 0);
    }

    // --- Confidential markers ---------------------------------------

    #[test]
    fn confidential_scanner_matches_banners_case_insensitively() {
        let c = ConfidentialScanner::new();
        let hits = c.scan("This document is STRICTLY CONFIDENTIAL and internal use only.");
        let labels: Vec<&str> = hits.iter().map(|m| m.marker).collect();
        assert!(labels.contains(&"confidential"), "{labels:?}");
        assert!(labels.contains(&"internal_only"), "{labels:?}");
    }

    #[test]
    fn confidential_scanner_prefers_longest_phrase() {
        let c = ConfidentialScanner::new();
        let hits = c.scan("marked company confidential here");
        // Leftmost-longest: one hit covering "company confidential".
        assert_eq!(hits.len(), 1);
        assert_eq!(hits[0].marker, "confidential");
        assert_eq!(hits[0].severity, Severity::High);
    }

    // --- End-to-end signal ------------------------------------------

    #[test]
    fn pii_to_known_app_coaches_not_blocks_by_default() {
        let det = detector();
        // A US SSN bound for ChatGPT.
        let sig = det.inspect(
            "https://chat.openai.com/c/x",
            b"my ssn is 219-09-9999 please summarise",
            &ContentMetadata::default(),
        );
        assert!(sig.is_flagged());
        assert_eq!(sig.action, AiAppAction::Coach, "{sig:?}");
        assert!(!sig.is_blocking());
        assert!(sig.findings.iter().any(|f| f.kind == FindingKind::Pii));
    }

    #[test]
    fn secret_to_known_app_coaches_by_default_never_blocks() {
        let det = detector();
        let sig = det.inspect(
            "https://claude.ai/chat",
            b"deploy with AKIAIOSFODNN7EXAMPLE and ghp_abcdefghijklmnopqrstuvwxyz0123456789",
            &ContentMetadata::default(),
        );
        assert!(sig.is_flagged());
        // Default policy is non-blocking even for secrets.
        assert_eq!(sig.action, AiAppAction::Coach, "{sig:?}");
        assert!(sig.findings.iter().any(|f| f.kind == FindingKind::Secret));
    }

    #[test]
    fn custom_scan_ceiling_bounds_the_secret_pass_consistently() {
        // A secret sitting past a small scan ceiling must be invisible to
        // the secret pass exactly as it is to the PII classifier, so the
        // engine's custom `max_scan_bytes` governs all three passes.
        let mut body = vec![b'a'; 64];
        body.extend_from_slice(b" AKIAIOSFODNN7EXAMPLE");

        // Control: the default ceiling scans the whole body and flags it.
        let wide = detector();
        let wide_sig = wide.inspect("https://claude.ai/chat", &body, &ContentMetadata::default());
        assert!(
            wide_sig
                .findings
                .iter()
                .any(|f| f.kind == FindingKind::Secret),
            "default ceiling should see the trailing secret"
        );

        // A 16-byte ceiling stops before the secret: no secret finding,
        // and the reported scan window matches the ceiling.
        let classifier = ContentClassifier::compile_with_limit(&default_pii_rules(), 16)
            .expect("classifier compiles");
        let narrow = AiAppExfilDetector::with_classifier(classifier, AiAppPolicy::default());
        let narrow_sig =
            narrow.inspect("https://claude.ai/chat", &body, &ContentMetadata::default());
        assert_eq!(narrow_sig.scanned_bytes, 16, "{narrow_sig:?}");
        assert!(narrow_sig.truncated, "{narrow_sig:?}");
        assert!(
            !narrow_sig
                .findings
                .iter()
                .any(|f| f.kind == FindingKind::Secret),
            "a secret past the ceiling must not be scanned: {narrow_sig:?}"
        );
    }

    #[test]
    fn block_requires_opt_in_and_known_high_confidence() {
        let policy = AiAppPolicy {
            block_opt_in: true,
            ..AiAppPolicy::default()
        };
        let det = AiAppExfilDetector::new(policy).expect("detector");
        let sig = det.inspect(
            "https://chat.openai.com/c/x",
            b"key AKIAIOSFODNN7EXAMPLE leaked",
            &ContentMetadata::default(),
        );
        assert_eq!(sig.action, AiAppAction::Block, "{sig:?}");
        assert!(sig.is_blocking());
    }

    #[test]
    fn operator_blocked_app_escalates_coach_to_block_without_opt_in() {
        // A secret bound for a known app coaches by default (block_opt_in
        // is false), the coach-first posture.
        let url = "https://chat.openai.com/c/x";
        let body = b"key AKIAIOSFODNN7EXAMPLE leaked";
        let coach = AiAppExfilDetector::new(AiAppPolicy::default()).expect("detector");
        let coach_sig = coach.inspect(url, body, &ContentMetadata::default());
        assert_eq!(coach_sig.action, AiAppAction::Coach, "{coach_sig:?}");

        // Once an operator has blocked that destination app via the review
        // queue, the same upload escalates straight to Block — even though
        // block_opt_in is still false. The operator already made the call.
        let policy = AiAppPolicy {
            blocked_apps: BTreeSet::from(["chatgpt".to_string()]),
            ..AiAppPolicy::default()
        };
        let det = AiAppExfilDetector::new(policy).expect("detector");
        let sig = det.inspect(url, body, &ContentMetadata::default());
        assert_eq!(sig.action, AiAppAction::Block, "{sig:?}");
        assert!(sig.is_blocking());
    }

    #[test]
    fn operator_blocked_suspected_sentinel_blocks_heuristic_destination() {
        // Operators can block the SUSPECTED_AI_APP sentinel to enforce on
        // heuristic (unknown) destinations, which otherwise can only coach.
        let url = "https://my-ai-tool.example.com/upload";
        let body = b"key AKIAIOSFODNN7EXAMPLE leaked";
        let policy = AiAppPolicy {
            blocked_apps: BTreeSet::from([SUSPECTED_AI_APP.to_string()]),
            ..AiAppPolicy::default()
        };
        let det = AiAppExfilDetector::new(policy).expect("detector");
        let sig = det.inspect(url, body, &ContentMetadata::default());
        assert_eq!(sig.action, AiAppAction::Block, "{sig:?}");
    }

    #[test]
    fn operator_block_still_respects_the_report_confidence_floor() {
        // A blocked app does not turn every upload into a block: an upload
        // with no finding clearing the report floor is still monitored, so
        // the override never blocks on noise.
        let policy = AiAppPolicy {
            blocked_apps: BTreeSet::from(["chatgpt".to_string()]),
            ..AiAppPolicy::default()
        };
        let det = AiAppExfilDetector::new(policy).expect("detector");
        let sig = det.inspect(
            "https://chat.openai.com/c/x",
            b"just an ordinary sentence with nothing sensitive in it",
            &ContentMetadata::default(),
        );
        assert_eq!(sig.action, AiAppAction::Monitor, "{sig:?}");
    }

    #[test]
    fn suspected_destination_never_blocks_even_with_secret_and_opt_in() {
        let policy = AiAppPolicy {
            block_opt_in: true,
            ..AiAppPolicy::default()
        };
        let det = AiAppExfilDetector::new(policy).expect("detector");
        let sig = det.inspect(
            "https://my-ai-tool.example.com/upload",
            b"key AKIAIOSFODNN7EXAMPLE leaked",
            &ContentMetadata::default(),
        );
        // Heuristic destinations can coach but must never block.
        assert_ne!(sig.action, AiAppAction::Block, "{sig:?}");
    }

    #[test]
    fn non_ai_destination_is_monitor_only() {
        let det = detector();
        let sig = det.inspect(
            "https://mail.example.com/compose",
            b"ssn 219-09-9999 and AKIAIOSFODNN7EXAMPLE",
            &ContentMetadata::default(),
        );
        assert_eq!(sig.action, AiAppAction::Monitor);
        assert!(!sig.is_flagged());
    }

    #[test]
    fn low_severity_pii_alone_is_monitored_not_coached() {
        let det = detector();
        // Only an email address (Low severity) to a known app: logged,
        // not coached — exactly the false-positive-averse default.
        let sig = det.inspect(
            "https://chat.openai.com/c/x",
            b"contact me at jane.doe@example.com",
            &ContentMetadata::default(),
        );
        assert!(sig.findings.iter().any(|f| f.label == "email"));
        assert_eq!(sig.action, AiAppAction::Monitor, "{sig:?}");
    }

    #[test]
    fn disabled_policy_is_noop() {
        let policy = AiAppPolicy {
            enabled: false,
            ..AiAppPolicy::default()
        };
        let det = AiAppExfilDetector::new(policy).expect("detector");
        let sig = det.inspect(
            "https://chat.openai.com/c/x",
            b"ssn 219-09-9999 AKIAIOSFODNN7EXAMPLE",
            &ContentMetadata::default(),
        );
        assert!(sig.findings.is_empty());
        assert_eq!(sig.action, AiAppAction::Monitor);
    }

    #[test]
    fn clean_body_to_ai_app_is_not_flagged() {
        let det = detector();
        let sig = det.inspect(
            "https://chat.openai.com/c/x",
            b"please write me a haiku about the sea",
            &ContentMetadata::default(),
        );
        assert!(!sig.is_flagged());
        assert_eq!(sig.action, AiAppAction::Monitor);
        assert!(sig.findings.is_empty());
    }

    #[test]
    fn signal_is_metadata_only_and_serialises() {
        let det = detector();
        let sig = det.inspect(
            "https://chat.openai.com/c/x",
            b"ssn 219-09-9999 secret AKIAIOSFODNN7EXAMPLE",
            &ContentMetadata::default(),
        );
        let json = serde_json::to_string(&sig).expect("serialises");
        // The redaction invariant: the raw SSN / key bytes never appear.
        assert!(!json.contains("219-09-9999"), "{json}");
        assert!(!json.contains("AKIAIOSFODNN7EXAMPLE"), "{json}");
        // But the aggregate findings are present.
        assert!(json.contains("findings"));
    }

    #[test]
    fn verdict_maps_coach_to_warn_user() {
        let det = detector();
        let v = det.verdict(
            "https://chat.openai.com/c/x",
            b"ssn 219-09-9999",
            &ContentMetadata::default(),
        );
        assert!(matches!(v, DlpVerdict::WarnUser(_)), "{v:?}");
        let d = v.details().expect("details");
        assert_eq!(d.channel, AI_UPLOAD_CHANNEL);
        assert!(!d.matches.is_empty());
    }

    #[test]
    fn verdict_allows_clean_upload() {
        let det = detector();
        let v = det.verdict(
            "https://chat.openai.com/c/x",
            b"nothing sensitive here",
            &ContentMetadata::default(),
        );
        assert_eq!(v, DlpVerdict::Allow);
    }

    #[test]
    fn contextual_scoring_is_reused_from_classifier() {
        // An unmanaged, after-hours device raises the reused classifier
        // confidence; the same content still coaches (not blocks) under
        // the default non-blocking policy.
        let det = detector();
        let meta = ContentMetadata {
            device_posture: DevicePosture::Unmanaged,
            local_hour: Some(2),
            ..ContentMetadata::default()
        };
        let sig = det.inspect("https://claude.ai/chat", b"ssn 219-09-9999", &meta);
        assert_eq!(sig.action, AiAppAction::Coach);
        assert!(sig.confidence > 0.0);
    }

    #[test]
    fn default_pii_rules_cover_every_jurisdiction_detector() {
        let rules = default_pii_rules();
        for d in detectors::registry() {
            assert!(
                rules.iter().any(|r| r.pattern_data == d.name),
                "missing PII rule for jurisdiction detector {}",
                d.name
            );
        }
        // And the rule set compiles into a working classifier.
        ContentClassifier::compile(&rules).expect("default PII rules compile");
    }
}
