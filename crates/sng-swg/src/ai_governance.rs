//! Inline AI-app governance on the SWG ext-authz decision path.
//!
//! Generative-AI assistants (ChatGPT, Claude, Gemini, Copilot, …) are
//! the highest-volume new-egress category on most managed networks.
//! The endpoint DLP agent already detects AI-app *uploads* carrying
//! sensitive content ([`sng_dlp::ai_app`]); this module is the
//! *inline* SWG counterpart: it sits in the per-request Envoy
//! ext-authz path and governs *access* to AI-app destinations —
//! block, monitor, allow, or redirect to RBI — based on
//! operator-configured policy.
//!
//! ## Detection
//!
//! Destination classification reuses the curated catalog +
//! long-tail heuristic pattern from [`sng_dlp::ai_app`]: a
//! registrable-domain suffix table (`KNOWN_AI_APPS`) covers the
//! high-confidence tier, and a host/path heuristic
//! (`heuristic_ai_app`) covers the long tail of niche wrappers and
//! self-hosted gateways. The catalog is intentionally a *copy*
//! rather than a dependency on `sng-dlp` — the SWG crate is
//! deployed on the edge appliance and must not pull in the
//! endpoint-agent crate's transitive dependency tree.
//!
//! ## Policy
//!
//! [`AiGovernancePolicy`] is a hot-swappable policy bundle
//! mirroring the control-plane Go `AIPolicyConfig`. It defines:
//!
//! * **Per-category rules** — govern all AI apps in a product
//!   category (e.g. block all `ModelPlatform` access, monitor all
//!   `Chatbot` usage).
//! * **Per-app rules** — override the category default for a
//!   specific app id (e.g. allow `chatgpt` but block `deepseek`).
//! * **Default action** — the fallback when no rule matches.
//!   Defaults to `Monitor` so the engine is observably useful
//!   without blocking anything on day one.
//! * **Suspected-app action** — the action for heuristic-only
//!   matches (lower confidence). Defaults to `Allow` so the
//!   long-tail heuristic never blocks on its own.
//!
//! ## Precedence
//!
//! 1. Per-app rule (exact app-id match)
//! 2. Per-category rule (product category of the matched app)
//! 3. Suspected-app action (heuristic-only match, no catalog id)
//! 4. Default action
//!
//! ## Hot-swap
//!
//! The engine wraps its compiled policy in [`ArcSwap`] so the
//! control plane can install a new policy bundle without
//! rebuilding the handler — the same pattern [`RbiPolicyEngine`]
//! and [`DlpInlineEngine`] use.

use crate::verdict::Verdict;
use arc_swap::ArcSwap;
use serde::{Deserialize, Serialize};
use std::sync::Arc;

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

/// The product category of a known AI app, recorded so an operator
/// can reason about exposure by tool type and write per-category
/// governance rules.
#[derive(Copy, Clone, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
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
    /// Model API gateway or hosting hub (OpenAI/Azure APIs, Hugging
    /// Face, Replicate) — where a body is uploaded programmatically.
    ModelPlatform,
    /// Meeting / transcription assistant (Otter, Fireflies, …).
    MeetingAssistant,
    /// Recognised as an AI app by heuristic; specific category unknown.
    Other,
}

impl AiAppCategory {
    /// Stable wire id used in policy config and telemetry.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Chatbot => "chatbot",
            Self::CodeAssistant => "code_assistant",
            Self::WritingAssistant => "writing_assistant",
            Self::ImageGenerator => "image_generator",
            Self::SearchAssistant => "search_assistant",
            Self::ModelPlatform => "model_platform",
            Self::MeetingAssistant => "meeting_assistant",
            Self::Other => "other",
        }
    }

    /// Parse a category from its wire id. Returns `None` for an
    /// unknown string so a policy bundle with a typo degrades to
    /// "no match" rather than panicking the verdict path.
    #[must_use]
    pub fn from_str(s: &str) -> Option<Self> {
        match s {
            "chatbot" => Some(Self::Chatbot),
            "code_assistant" => Some(Self::CodeAssistant),
            "writing_assistant" => Some(Self::WritingAssistant),
            "image_generator" => Some(Self::ImageGenerator),
            "search_assistant" => Some(Self::SearchAssistant),
            "model_platform" => Some(Self::ModelPlatform),
            "meeting_assistant" => Some(Self::MeetingAssistant),
            "other" => Some(Self::Other),
            _ => None,
        }
    }
}

/// One entry in the curated AI-app catalog.
struct KnownAiApp {
    /// Registrable domain (matched as an exact host or a suffix
    /// after a `.` boundary).
    domain: &'static str,
    /// Stable app id used in policy rules and telemetry.
    app: &'static str,
    /// Product category.
    category: AiAppCategory,
}

/// The curated catalog of well-known AI-app destinations. This is
/// the high-confidence tier; the long-tail heuristic covers
/// everything else. Kept in sync with `sng-dlp`'s catalog.
const KNOWN_AI_APPS: &[KnownAiApp] = &[
    // --- General-purpose chatbots ---
    KnownAiApp { domain: "openai.com", app: "chatgpt", category: AiAppCategory::Chatbot },
    KnownAiApp { domain: "chatgpt.com", app: "chatgpt", category: AiAppCategory::Chatbot },
    KnownAiApp { domain: "claude.ai", app: "claude", category: AiAppCategory::Chatbot },
    KnownAiApp { domain: "anthropic.com", app: "claude", category: AiAppCategory::Chatbot },
    KnownAiApp { domain: "gemini.google.com", app: "gemini", category: AiAppCategory::Chatbot },
    KnownAiApp { domain: "bard.google.com", app: "gemini", category: AiAppCategory::Chatbot },
    KnownAiApp { domain: "copilot.microsoft.com", app: "copilot", category: AiAppCategory::Chatbot },
    KnownAiApp { domain: "poe.com", app: "poe", category: AiAppCategory::Chatbot },
    KnownAiApp { domain: "pi.ai", app: "pi", category: AiAppCategory::Chatbot },
    KnownAiApp { domain: "chat.mistral.ai", app: "le_chat", category: AiAppCategory::Chatbot },
    KnownAiApp { domain: "mistral.ai", app: "mistral", category: AiAppCategory::Chatbot },
    KnownAiApp { domain: "chat.deepseek.com", app: "deepseek", category: AiAppCategory::Chatbot },
    KnownAiApp { domain: "deepseek.com", app: "deepseek", category: AiAppCategory::Chatbot },
    KnownAiApp { domain: "x.ai", app: "grok", category: AiAppCategory::Chatbot },
    KnownAiApp { domain: "grok.com", app: "grok", category: AiAppCategory::Chatbot },
    KnownAiApp { domain: "character.ai", app: "character_ai", category: AiAppCategory::Chatbot },
    KnownAiApp { domain: "chatglm.cn", app: "chatglm", category: AiAppCategory::Chatbot },
    KnownAiApp { domain: "moonshot.cn", app: "kimi", category: AiAppCategory::Chatbot },
    KnownAiApp { domain: "tongyi.aliyun.com", app: "tongyi", category: AiAppCategory::Chatbot },
    KnownAiApp { domain: "doubao.com", app: "doubao", category: AiAppCategory::Chatbot },
    // --- Code assistants ---
    KnownAiApp { domain: "github.com", app: "github_copilot", category: AiAppCategory::CodeAssistant },
    KnownAiApp { domain: "githubcopilot.com", app: "github_copilot", category: AiAppCategory::CodeAssistant },
    KnownAiApp { domain: "cursor.com", app: "cursor", category: AiAppCategory::CodeAssistant },
    KnownAiApp { domain: "cursor.sh", app: "cursor", category: AiAppCategory::CodeAssistant },
    KnownAiApp { domain: "codeium.com", app: "codeium", category: AiAppCategory::CodeAssistant },
    KnownAiApp { domain: "tabnine.com", app: "tabnine", category: AiAppCategory::CodeAssistant },
    KnownAiApp { domain: "phind.com", app: "phind", category: AiAppCategory::CodeAssistant },
    KnownAiApp { domain: "codium.ai", app: "qodo", category: AiAppCategory::CodeAssistant },
    KnownAiApp { domain: "sourcegraph.com", app: "cody", category: AiAppCategory::CodeAssistant },
    KnownAiApp { domain: "replit.com", app: "replit_ai", category: AiAppCategory::CodeAssistant },
    // --- Writing assistants ---
    KnownAiApp { domain: "jasper.ai", app: "jasper", category: AiAppCategory::WritingAssistant },
    KnownAiApp { domain: "writesonic.com", app: "writesonic", category: AiAppCategory::WritingAssistant },
    KnownAiApp { domain: "copy.ai", app: "copy_ai", category: AiAppCategory::WritingAssistant },
    KnownAiApp { domain: "rytr.me", app: "rytr", category: AiAppCategory::WritingAssistant },
    KnownAiApp { domain: "quillbot.com", app: "quillbot", category: AiAppCategory::WritingAssistant },
    KnownAiApp { domain: "grammarly.com", app: "grammarly", category: AiAppCategory::WritingAssistant },
    KnownAiApp { domain: "notion.so", app: "notion_ai", category: AiAppCategory::WritingAssistant },
    // --- Image / media generators ---
    KnownAiApp { domain: "midjourney.com", app: "midjourney", category: AiAppCategory::ImageGenerator },
    KnownAiApp { domain: "leonardo.ai", app: "leonardo", category: AiAppCategory::ImageGenerator },
    KnownAiApp { domain: "stability.ai", app: "stability", category: AiAppCategory::ImageGenerator },
    KnownAiApp { domain: "runwayml.com", app: "runway", category: AiAppCategory::ImageGenerator },
    KnownAiApp { domain: "elevenlabs.io", app: "elevenlabs", category: AiAppCategory::ImageGenerator },
    // --- Search / answer engines ---
    KnownAiApp { domain: "perplexity.ai", app: "perplexity", category: AiAppCategory::SearchAssistant },
    KnownAiApp { domain: "you.com", app: "you", category: AiAppCategory::SearchAssistant },
    // --- Model platforms / API gateways ---
    KnownAiApp { domain: "api.openai.com", app: "openai_api", category: AiAppCategory::ModelPlatform },
    KnownAiApp { domain: "api.anthropic.com", app: "anthropic_api", category: AiAppCategory::ModelPlatform },
    KnownAiApp { domain: "huggingface.co", app: "huggingface", category: AiAppCategory::ModelPlatform },
    KnownAiApp { domain: "replicate.com", app: "replicate", category: AiAppCategory::ModelPlatform },
    KnownAiApp { domain: "cohere.com", app: "cohere", category: AiAppCategory::ModelPlatform },
    KnownAiApp { domain: "cohere.ai", app: "cohere", category: AiAppCategory::ModelPlatform },
    KnownAiApp { domain: "together.ai", app: "together", category: AiAppCategory::ModelPlatform },
    KnownAiApp { domain: "fireworks.ai", app: "fireworks", category: AiAppCategory::ModelPlatform },
    KnownAiApp { domain: "groq.com", app: "groq", category: AiAppCategory::ModelPlatform },
    KnownAiApp { domain: "openrouter.ai", app: "openrouter", category: AiAppCategory::ModelPlatform },
    KnownAiApp { domain: "anyscale.com", app: "anyscale", category: AiAppCategory::ModelPlatform },
    KnownAiApp { domain: "azure.com", app: "azure_openai", category: AiAppCategory::ModelPlatform },
    // --- Meeting / transcription assistants ---
    KnownAiApp { domain: "otter.ai", app: "otter", category: AiAppCategory::MeetingAssistant },
    KnownAiApp { domain: "fireflies.ai", app: "fireflies", category: AiAppCategory::MeetingAssistant },
    KnownAiApp { domain: "fathom.video", app: "fathom", category: AiAppCategory::MeetingAssistant },
    KnownAiApp { domain: "tldv.io", app: "tldv", category: AiAppCategory::MeetingAssistant },
];

/// Strong AI-app tokens in host labels. A host label containing one
/// of these marks the destination as a *suspected* AI app.
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

/// Path fragments that signal a programmatic AI/LLM API call.
const AI_PATH_TOKENS: &[&str] = &[
    "/v1/chat/completions",
    "/v1/completions",
    "/v1/messages",
    "/v1/embeddings",
    "/api/generate",
    "/api/chat",
    "/chat/completions",
];

/// The classification of a request destination.
#[derive(Clone, Debug, PartialEq)]
pub struct AiAppDestination {
    /// How the destination was recognised.
    pub kind: AiAppKind,
    /// Stable app id from the catalog, or `None` for a heuristic
    /// match.
    pub app: Option<&'static str>,
    /// Product category, when known.
    pub category: Option<AiAppCategory>,
    /// The lowercased host the match was attributed to.
    pub host: String,
}

impl AiAppDestination {
    /// Whether the destination is an AI app (known or suspected).
    #[must_use]
    pub const fn is_ai_app(&self) -> bool {
        matches!(self.kind, AiAppKind::Known | AiAppKind::Suspected)
    }
}

/// True when `host` equals `domain` or is a subdomain of it
/// (matched on a `.` boundary).
fn host_matches_domain(host: &str, domain: &str) -> bool {
    host == domain || host.ends_with(&format!(".{domain}"))
}

/// Look up `host` in the curated catalog, preferring the most
/// specific (longest) matching domain.
fn known_ai_app(host: &str) -> Option<&'static KnownAiApp> {
    KNOWN_AI_APPS
        .iter()
        .filter(|a| host_matches_domain(host, a.domain))
        .max_by_key(|a| a.domain.len())
}

/// Common English words that contain "ai" as a hyphen-separated
/// token but are not AI-related. Prevents false positives like
/// `mail-app.example.com` or `trail-cam.example.com`.
const AI_FALSE_POSITIVES: &[&str] = &[
    "mail",
    "trail",
    "rail",
    "nail",
    "sail",
    "snail",
    "detail",
    "retain",
    "certain",
    "bail",
    "fail",
    "jail",
    "kail",
    "wail",
    "avail",
    "entail",
    "portrayal",
];

/// The long-tail heuristic: decide whether a non-catalog host/path
/// looks like an AI app.
fn heuristic_ai_app(host: &str, path: &str) -> bool {
    if host.is_empty() {
        return false;
    }
    for label in host.split('.') {
        // Match "ai" as a standalone DNS label (e.g. `ai.example.com`)
        // or as a hyphen-separated token (e.g. `my-ai-tool.example.com`),
        // but exclude common English words that contain "ai".
        if label == "ai" {
            return true;
        }
        for token in label.split('-') {
            if token == "ai" {
                return true;
            }
        }
        // Check curated AI host tokens as substrings of the label.
        // These are specific enough (chatgpt, claude, gemini, …) that
        // a substring match is safe.
        if AI_HOST_TOKENS.iter().any(|t| label.contains(t)) {
            return true;
        }
        // Exclude false-positive labels: if the label is a known
        // common word, do not flag it even if it contains "ai".
        let is_false_positive = AI_FALSE_POSITIVES
            .iter()
            .any(|fp| label == *fp || label.split('-').any(|t| t == *fp));
        if !is_false_positive && label.contains("ai") {
            // Only flag if "ai" appears as a distinct sub-token,
            // not buried inside a longer word like "mail" or "trail".
            // The hyphen-split check above already handles explicit
            // hyphenation; this catches labels like "aichat" or
            // "aibot" where "ai" is a prefix.
            if label.starts_with("ai") && label.len() > 2 && !label.starts_with("air") {
                return true;
            }
        }
    }
    AI_PATH_TOKENS.iter().any(|t| path.contains(t))
}

/// Classify a request destination (host + path) as an AI app.
/// Pure and allocation-light; safe to call on the hot path.
#[must_use]
pub fn classify_destination(host: &str, path: &str) -> AiAppDestination {
    let host_lc = host.to_ascii_lowercase();
    let path_lc = path.to_ascii_lowercase();
    if let Some(app) = known_ai_app(&host_lc) {
        return AiAppDestination {
            kind: AiAppKind::Known,
            app: Some(app.app),
            category: Some(app.category),
            host: host_lc,
        };
    }
    if heuristic_ai_app(&host_lc, &path_lc) {
        return AiAppDestination {
            kind: AiAppKind::Suspected,
            app: None,
            category: Some(AiAppCategory::Other),
            host: host_lc,
        };
    }
    AiAppDestination {
        kind: AiAppKind::NotAiApp,
        app: None,
        category: None,
        host: host_lc,
    }
}

// ---------------------------------------------------------------------------
// Policy
// ---------------------------------------------------------------------------

/// The governance action the engine applies to a matched AI-app
/// request.
#[derive(Copy, Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AiGovernanceAction {
    /// Allow the request (no inline enforcement, but the access is
    /// still logged as an AI-app hit for shadow-IT inventory).
    Allow,
    /// Monitor the request (allow + emit a telemetry event flagged
    /// as an AI-app access for the governance dashboard).
    Monitor,
    /// Block the request (deny with an `ai_governance.blocked`
    /// reason).
    Block,
    /// Redirect the request to the RBI proxy for isolation.
    Redirect,
}

impl Default for AiGovernanceAction {
    fn default() -> Self {
        Self::Monitor
    }
}

/// One per-app or per-category rule in the governance policy.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct AiGovernanceRule {
    /// The app id this rule targets (e.g. `"chatgpt"`). When set,
    /// this rule matches only that specific app. When `None`,
    /// `category` is used instead.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub app: Option<String>,
    /// The category this rule targets. Used when `app` is `None`.
    /// When both are `None`, the rule acts as a catch-all default.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub category: Option<String>,
    /// The governance action to apply.
    pub action: AiGovernanceAction,
}

/// The operator-configurable governance policy. Mirrors the
/// control-plane Go `AIPolicyConfig`. Hot-swapped via
/// [`AiGovernanceEngine::install`].
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct AiGovernancePolicy {
    /// Ordered per-app / per-category rules. The first matching
    /// rule wins; if none match, `default_action` is used.
    #[serde(default)]
    pub rules: Vec<AiGovernanceRule>,
    /// The fallback action when no rule matches a known AI app.
    #[serde(default)]
    pub default_action: AiGovernanceAction,
    /// The action for suspected (heuristic-only) AI apps. Defaults
    /// to `Allow` so the long-tail heuristic never blocks on its
    /// own.
    #[serde(default = "default_suspected_action")]
    pub suspected_action: AiGovernanceAction,
}

fn default_suspected_action() -> AiGovernanceAction {
    AiGovernanceAction::Allow
}

/// The reason the engine produced a particular action, surfaced on
/// the verdict's `reason` field for telemetry.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum AiGovernanceReason {
    /// A per-app rule matched.
    AppRule,
    /// A per-category rule matched.
    CategoryRule,
    /// The default action was applied (no rule matched).
    Default,
    /// The suspected-app action was applied (heuristic match).
    Suspected,
}

impl AiGovernanceReason {
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::AppRule => "ai_governance.app_rule",
            Self::CategoryRule => "ai_governance.category_rule",
            Self::Default => "ai_governance.default",
            Self::Suspected => "ai_governance.suspected",
        }
    }
}

/// The outcome of an evaluation: the action, the reason, and the
/// detected destination (for telemetry).
#[derive(Clone, Debug, PartialEq)]
pub struct AiGovernanceVerdict {
    /// The governance action.
    pub action: AiGovernanceAction,
    /// Why the action was chosen.
    pub reason: AiGovernanceReason,
    /// The detected destination.
    pub destination: AiAppDestination,
}

// ---------------------------------------------------------------------------
// Compiled policy
// ---------------------------------------------------------------------------

/// A compiled rule with the category pre-parsed from its string
/// form so the hot path does not repeat the parse.
#[derive(Clone, Debug, PartialEq, Eq)]
struct CompiledRule {
    app: Option<String>,
    category: Option<AiAppCategory>,
    action: AiGovernanceAction,
}

/// The compiled, ready-to-evaluate policy snapshot.
#[derive(Clone, Debug, PartialEq, Eq)]
struct CompiledPolicy {
    rules: Vec<CompiledRule>,
    default_action: AiGovernanceAction,
    suspected_action: AiGovernanceAction,
}

impl CompiledPolicy {
    fn compile(def: &AiGovernancePolicy) -> Self {
        let rules = def
            .rules
            .iter()
            .map(|r| CompiledRule {
                app: r.app.as_ref().map(|s| s.to_ascii_lowercase()),
                category: r.category.as_deref().and_then(AiAppCategory::from_str),
                action: r.action,
            })
            .collect();
        Self {
            rules,
            default_action: def.default_action,
            suspected_action: def.suspected_action,
        }
    }

    /// Evaluate a detected destination against the compiled rules.
    /// Returns the action + reason. Called only when the destination
    /// is an AI app.
    fn evaluate(&self, dest: &AiAppDestination) -> (AiGovernanceAction, AiGovernanceReason) {
        // 1. Per-app rule (exact app-id match).
        if let Some(app_id) = dest.app {
            let app_lc = app_id.to_ascii_lowercase();
            for rule in &self.rules {
                if let Some(ra) = &rule.app {
                    if ra == &app_lc {
                        return (rule.action, AiGovernanceReason::AppRule);
                    }
                }
            }
        }

        // 2. Per-category rule.
        if let Some(cat) = dest.category {
            for rule in &self.rules {
                if rule.app.is_none() && rule.category == Some(cat) {
                    return (rule.action, AiGovernanceReason::CategoryRule);
                }
            }
        }

        // 3. Suspected-app action (heuristic-only match).
        if dest.kind == AiAppKind::Suspected {
            return (self.suspected_action, AiGovernanceReason::Suspected);
        }

        // 4. Default action.
        (self.default_action, AiGovernanceReason::Default)
    }
}

// ---------------------------------------------------------------------------
// Engine
// ---------------------------------------------------------------------------

/// The AI-governance policy engine. Wraps a compiled policy
/// snapshot in [`ArcSwap`] for lock-free hot-swap from the control
/// plane. Cheap to clone (an `Arc` inner) so the handler can hold
/// one alongside the other engines.
#[derive(Debug)]
pub struct AiGovernanceEngine {
    inner: Arc<ArcSwap<CompiledPolicy>>,
}

impl AiGovernanceEngine {
    /// Create a new engine with an empty (default) policy. The
    /// control plane hot-swaps a real policy via [`Self::install`].
    #[must_use]
    pub fn new() -> Self {
        let compiled = CompiledPolicy::compile(&AiGovernancePolicy::default());
        Self {
            inner: Arc::new(ArcSwap::from_pointee(compiled)),
        }
    }

    /// Hot-swap the policy. Returns `(rules_count, 0)` so the
    /// caller can log the install. The swap is atomic and
    /// lock-free: in-flight verdicts continue using the old
    /// snapshot; the next request picks up the new one.
    pub fn install(&self, def: &AiGovernancePolicy) -> (usize, usize) {
        let compiled = CompiledPolicy::compile(def);
        let count = compiled.rules.len();
        self.inner.store(Arc::new(compiled));
        (count, 0)
    }

    /// Evaluate a request against the governance policy. Returns
    /// `None` when the destination is not an AI app (the pipeline
    /// continues unchanged). Returns `Some(verdict)` when the
    /// destination is an AI app, carrying the action + reason.
    #[must_use]
    pub fn evaluate(&self, host: &str, path: &str) -> Option<AiGovernanceVerdict> {
        let dest = classify_destination(host, path);
        if !dest.is_ai_app() {
            return None;
        }
        let snap = self.inner.load();
        let (action, reason) = snap.evaluate(&dest);
        Some(AiGovernanceVerdict {
            action,
            reason,
            destination: dest,
        })
    }
}

impl Default for AiGovernanceEngine {
    fn default() -> Self {
        Self::new()
    }
}

/// Convert a governance verdict into an SWG [`Verdict`]. `Allow`
/// and `Monitor` map to `Verdict::allow` (the monitor case is
/// distinguished by the reason string on telemetry). `Block` maps
/// to `Verdict::deny`. `Redirect` maps to `Verdict::redirect` —
/// the caller supplies the RBI proxy URL.
#[must_use]
pub fn governance_to_verdict(
    gv: &AiGovernanceVerdict,
    rbi_proxy_url: Option<&str>,
) -> Verdict {
    match gv.action {
        AiGovernanceAction::Allow | AiGovernanceAction::Monitor => {
            Verdict::allow(gv.reason.as_str())
        }
        AiGovernanceAction::Block => {
            Verdict::deny(format!("{}.blocked.{}", gv.reason.as_str(), gv.destination.app.unwrap_or("suspected")))
        }
        AiGovernanceAction::Redirect => {
            let url = rbi_proxy_url.map(|base| {
                let host = &gv.destination.host;
                let session = format!("pending:{host}");
                let escaped = url_escape(&session);
                format!("{base}/rbi/session/{escaped}")
            });
            Verdict::redirect(
                format!("{}.redirect.{}", gv.reason.as_str(), gv.destination.app.unwrap_or("suspected")),
                url.unwrap_or_default(),
            )
        }
    }
}

/// Percent-encode characters that are unsafe in a URL path segment.
/// Matches the RBI engine's escaping so a redirect from either
/// engine produces the same session-id format.
fn url_escape(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for b in s.bytes() {
        match b {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'_' | b'.' | b'~' => {
                out.push(b as char);
            }
            _ => {
                out.push('%');
                out.push_str(&format!("{b:02X}"));
            }
        }
    }
    out
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use crate::verdict::Action;

    fn engine() -> AiGovernanceEngine {
        AiGovernanceEngine::new()
    }

    #[test]
    fn known_app_chatgpt() {
        let dest = classify_destination("chat.openai.com", "/");
        assert_eq!(dest.kind, AiAppKind::Known);
        assert_eq!(dest.app, Some("chatgpt"));
        assert_eq!(dest.category, Some(AiAppCategory::Chatbot));
        assert!(dest.is_ai_app());
    }

    #[test]
    fn known_app_claude() {
        let dest = classify_destination("claude.ai", "/chat");
        assert_eq!(dest.kind, AiAppKind::Known);
        assert_eq!(dest.app, Some("claude"));
    }

    #[test]
    fn known_app_api_subdomain_wins() {
        // api.anthropic.com should match the ModelPlatform entry,
        // not the Chatbot entry for anthropic.com.
        let dest = classify_destination("api.anthropic.com", "/v1/messages");
        assert_eq!(dest.kind, AiAppKind::Known);
        assert_eq!(dest.app, Some("anthropic_api"));
        assert_eq!(dest.category, Some(AiAppCategory::ModelPlatform));
    }

    #[test]
    fn suspected_app_heuristic_host() {
        let dest = classify_destination("my-ai-tool.example.com", "/");
        assert_eq!(dest.kind, AiAppKind::Suspected);
        assert_eq!(dest.category, Some(AiAppCategory::Other));
        assert!(dest.is_ai_app());
    }

    #[test]
    fn suspected_app_ai_standalone_label() {
        let dest = classify_destination("ai.example.com", "/");
        assert_eq!(dest.kind, AiAppKind::Suspected);
        assert!(dest.is_ai_app());
    }

    #[test]
    fn suspected_app_ai_prefix_label() {
        let dest = classify_destination("aichat.example.com", "/");
        assert_eq!(dest.kind, AiAppKind::Suspected);
        assert!(dest.is_ai_app());
    }

    #[test]
    fn not_ai_app_mail_subdomain() {
        // "mail" contains "ai" but is a common English word — must
        // not be flagged as a suspected AI app.
        let dest = classify_destination("mail-app.example.com", "/");
        assert_eq!(dest.kind, AiAppKind::NotAiApp);
    }

    #[test]
    fn not_ai_app_trail_subdomain() {
        let dest = classify_destination("trail-cam.example.com", "/");
        assert_eq!(dest.kind, AiAppKind::NotAiApp);
    }

    #[test]
    fn not_ai_app_air_prefix_excluded() {
        // "air" starts with "ai" but is excluded to avoid false
        // positives on airline / air-conditioning domains.
        let dest = classify_destination("airtools.example.com", "/");
        assert_eq!(dest.kind, AiAppKind::NotAiApp);
    }

    #[test]
    fn suspected_app_heuristic_path() {
        let dest = classify_destination("gateway.example.com", "/v1/chat/completions");
        assert_eq!(dest.kind, AiAppKind::Suspected);
        assert!(dest.is_ai_app());
    }

    #[test]
    fn not_ai_app() {
        let dest = classify_destination("example.com", "/page");
        assert_eq!(dest.kind, AiAppKind::NotAiApp);
        assert!(!dest.is_ai_app());
    }

    #[test]
    fn no_rules_default_monitor() {
        let e = engine();
        let v = e.evaluate("chatgpt.com", "/").unwrap();
        assert_eq!(v.action, AiGovernanceAction::Monitor);
        assert_eq!(v.reason, AiGovernanceReason::Default);
    }

    #[test]
    fn per_app_rule_wins_over_category() {
        let e = engine();
        e.install(&AiGovernancePolicy {
            rules: vec![
                AiGovernanceRule {
                    app: Some("chatgpt".into()),
                    category: None,
                    action: AiGovernanceAction::Block,
                },
                AiGovernanceRule {
                    app: None,
                    category: Some("chatbot".into()),
                    action: AiGovernanceAction::Allow,
                },
            ],
            default_action: AiGovernanceAction::Monitor,
            suspected_action: AiGovernanceAction::Allow,
        });
        let v = e.evaluate("chatgpt.com", "/").unwrap();
        assert_eq!(v.action, AiGovernanceAction::Block);
        assert_eq!(v.reason, AiGovernanceReason::AppRule);
    }

    #[test]
    fn per_category_rule_matches() {
        let e = engine();
        e.install(&AiGovernancePolicy {
            rules: vec![AiGovernanceRule {
                app: None,
                category: Some("model_platform".into()),
                action: AiGovernanceAction::Block,
            }],
            default_action: AiGovernanceAction::Monitor,
            suspected_action: AiGovernanceAction::Allow,
        });
        let v = e.evaluate("api.openai.com", "/v1/chat/completions").unwrap();
        assert_eq!(v.action, AiGovernanceAction::Block);
        assert_eq!(v.reason, AiGovernanceReason::CategoryRule);
    }

    #[test]
    fn suspected_uses_suspected_action() {
        let e = engine();
        e.install(&AiGovernancePolicy {
            rules: vec![],
            default_action: AiGovernanceAction::Block,
            suspected_action: AiGovernanceAction::Monitor,
        });
        let v = e.evaluate("my-ai-tool.example.com", "/").unwrap();
        assert_eq!(v.action, AiGovernanceAction::Monitor);
        assert_eq!(v.reason, AiGovernanceReason::Suspected);
    }

    #[test]
    fn not_ai_app_returns_none() {
        let e = engine();
        assert!(e.evaluate("example.com", "/page").is_none());
    }

    #[test]
    fn hot_swap_replaces_rules() {
        let e = engine();
        e.install(&AiGovernancePolicy {
            rules: vec![AiGovernanceRule {
                app: Some("chatgpt".into()),
                category: None,
                action: AiGovernanceAction::Block,
            }],
            ..Default::default()
        });
        let v = e.evaluate("chatgpt.com", "/").unwrap();
        assert_eq!(v.action, AiGovernanceAction::Block);

        // Hot-swap to empty policy → default action (Monitor).
        e.install(&AiGovernancePolicy::default());
        let v2 = e.evaluate("chatgpt.com", "/").unwrap();
        assert_eq!(v2.action, AiGovernanceAction::Monitor);
    }

    #[test]
    fn governance_to_verdict_block_produces_deny() {
        let v = governance_to_verdict(
            &AiGovernanceVerdict {
                action: AiGovernanceAction::Block,
                reason: AiGovernanceReason::AppRule,
                destination: classify_destination("chatgpt.com", "/"),
            },
            None,
        );
        assert_eq!(v.action, Action::Deny);
        assert!(v.reason.contains("ai_governance.app_rule.blocked.chatgpt"));
    }

    #[test]
    fn governance_to_verdict_allow_produces_allow() {
        let v = governance_to_verdict(
            &AiGovernanceVerdict {
                action: AiGovernanceAction::Allow,
                reason: AiGovernanceReason::Default,
                destination: classify_destination("chatgpt.com", "/"),
            },
            None,
        );
        assert_eq!(v.action, Action::Allow);
    }

    #[test]
    fn governance_to_verdict_redirect_produces_redirect() {
        let v = governance_to_verdict(
            &AiGovernanceVerdict {
                action: AiGovernanceAction::Redirect,
                reason: AiGovernanceReason::CategoryRule,
                destination: classify_destination("chatgpt.com", "/"),
            },
            Some("https://rbi.test"),
        );
        assert_eq!(v.action, Action::Redirect);
        assert!(v.redirect_url.is_some());
        assert!(
            v.redirect_url
                .as_ref()
                .unwrap()
                .starts_with("https://rbi.test/rbi/session/")
        );
    }

    #[test]
    fn url_escape_encodes_colon() {
        assert_eq!(url_escape("pending:evil.com"), "pending%3Aevil.com");
    }

    #[test]
    fn category_from_str_roundtrip() {
        for cat in [
            AiAppCategory::Chatbot,
            AiAppCategory::CodeAssistant,
            AiAppCategory::WritingAssistant,
            AiAppCategory::ImageGenerator,
            AiAppCategory::SearchAssistant,
            AiAppCategory::ModelPlatform,
            AiAppCategory::MeetingAssistant,
            AiAppCategory::Other,
        ] {
            assert_eq!(AiAppCategory::from_str(cat.as_str()), Some(cat));
        }
        assert_eq!(AiAppCategory::from_str("unknown"), None);
    }
}
