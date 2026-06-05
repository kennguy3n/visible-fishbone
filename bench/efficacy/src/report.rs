//! Efficacy report schema + scoring.
//!
//! Every security function under test is scored the same way: a corpus
//! of *known-bad* and *known-good* cases is run through the real
//! decision code, and each case is classified into a confusion matrix.
//!
//! * **bad** cases SHOULD be stopped (denied / detected).
//! * **good** cases SHOULD be permitted (allowed / not alerted).
//!
//! From the matrix we derive the two numbers a security buyer asks for:
//! the **catch rate** (block-rate for enforcement, detection-rate for
//! IPS) and the **false-positive rate**.

use serde::{Deserialize, Serialize};

/// Whether a function blocks inline (FW/SWG/ZTNA) or detects
/// out-of-band (IPS). Only changes the KPI label, not the math.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Kind {
    Enforcement,
    Detection,
}

/// One corpus case outcome.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Case {
    /// Human description of the scenario.
    pub description: String,
    /// `true` if this is a known-bad case (should be stopped).
    pub bad: bool,
    /// What the function was expected to do ("deny" / "detect" /
    /// "allow" / "pass").
    pub expected: String,
    /// What the function actually did.
    pub actual: String,
    /// `true` when `actual` matched `expected`.
    pub correct: bool,
}

/// PASS / WARN / FAIL grade.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum Grade {
    #[serde(rename = "PASS")]
    Pass,
    #[serde(rename = "WARN")]
    Warn,
    #[serde(rename = "FAIL")]
    Fail,
    #[serde(rename = "UNTESTED")]
    Untested,
}

impl Grade {
    pub fn as_str(self) -> &'static str {
        match self {
            Grade::Pass => "PASS",
            Grade::Warn => "WARN",
            Grade::Fail => "FAIL",
            Grade::Untested => "UNTESTED",
        }
    }

    /// Worst (most severe) of two grades. Untested is treated as
    /// worse than Warn but better than Fail so a partially-run
    /// suite never masquerades as green.
    pub fn worst(self, other: Grade) -> Grade {
        fn rank(g: Grade) -> u8 {
            match g {
                Grade::Pass => 0,
                Grade::Warn => 1,
                Grade::Untested => 2,
                Grade::Fail => 3,
            }
        }
        if rank(self) >= rank(other) {
            self
        } else {
            other
        }
    }
}

/// Catch-rate / false-positive-rate targets a function is graded
/// against. PASS needs catch ≥ `catch_pass` AND fp ≤ `fp_pass`.
#[derive(Debug, Clone, Copy, Serialize, Deserialize)]
pub struct Targets {
    pub catch_pass: f64,
    pub catch_warn: f64,
    pub fp_pass: f64,
    pub fp_warn: f64,
}

impl Default for Targets {
    fn default() -> Self {
        // A security buyer expects near-perfect catch on a curated
        // corpus and very few false positives.
        Self {
            catch_pass: 0.99,
            catch_warn: 0.90,
            fp_pass: 0.02,
            fp_warn: 0.05,
        }
    }
}

/// Per-function efficacy result.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FunctionReport {
    pub function: String,
    #[serde(rename = "crate")]
    pub crate_name: String,
    pub kind: Kind,
    pub tested: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub untested_reason: Option<String>,

    pub total_cases: usize,
    pub bad_cases: usize,
    pub good_cases: usize,

    /// Confusion matrix. tp = bad correctly stopped; fn_ = bad
    /// missed; tn = good correctly permitted; fp = good wrongly
    /// stopped.
    pub tp: usize,
    #[serde(rename = "fn")]
    pub fn_: usize,
    pub tn: usize,
    pub fp: usize,

    /// Catch rate = tp / (tp + fn). Block-rate (enforcement) or
    /// detection-rate (IPS).
    pub catch_rate: f64,
    pub false_positive_rate: f64,
    pub accuracy: f64,

    pub targets: Targets,
    pub verdict: Grade,

    #[serde(skip_serializing_if = "Option::is_none")]
    pub notes: Option<String>,
    pub cases: Vec<Case>,
}

impl FunctionReport {
    /// Build a tested function report from its cases and grade it.
    pub fn from_cases(
        function: &str,
        crate_name: &str,
        kind: Kind,
        targets: Targets,
        cases: Vec<Case>,
        notes: Option<String>,
    ) -> Self {
        let (mut tp, mut fn_, mut tn, mut fp) = (0usize, 0usize, 0usize, 0usize);
        for c in &cases {
            match (c.bad, c.correct) {
                (true, true) => tp += 1,
                (true, false) => fn_ += 1,
                (false, true) => tn += 1,
                (false, false) => fp += 1,
            }
        }
        let bad_cases = tp + fn_;
        let good_cases = tn + fp;
        let total = bad_cases + good_cases;
        let catch_rate = if bad_cases == 0 {
            1.0
        } else {
            tp as f64 / bad_cases as f64
        };
        let false_positive_rate = if good_cases == 0 {
            0.0
        } else {
            fp as f64 / good_cases as f64
        };
        let accuracy = if total == 0 {
            1.0
        } else {
            (tp + tn) as f64 / total as f64
        };
        let verdict = grade(catch_rate, false_positive_rate, targets);
        Self {
            function: function.into(),
            crate_name: crate_name.into(),
            kind,
            tested: true,
            untested_reason: None,
            total_cases: total,
            bad_cases,
            good_cases,
            tp,
            fn_,
            tn,
            fp,
            catch_rate,
            false_positive_rate,
            accuracy,
            targets,
            verdict,
            notes,
            cases,
        }
    }

    /// Build an untested placeholder (e.g. Suricata not installed).
    pub fn untested(function: &str, crate_name: &str, kind: Kind, reason: &str) -> Self {
        Self {
            function: function.into(),
            crate_name: crate_name.into(),
            kind,
            tested: false,
            untested_reason: Some(reason.into()),
            total_cases: 0,
            bad_cases: 0,
            good_cases: 0,
            tp: 0,
            fn_: 0,
            tn: 0,
            fp: 0,
            catch_rate: 0.0,
            false_positive_rate: 0.0,
            accuracy: 0.0,
            targets: Targets::default(),
            verdict: Grade::Untested,
            notes: None,
            cases: Vec::new(),
        }
    }
}

/// Grade a function: PASS needs catch ≥ pass-target AND fp ≤ pass-target;
/// WARN is the looser band; otherwise FAIL.
pub fn grade(catch: f64, fp: f64, t: Targets) -> Grade {
    if catch >= t.catch_pass && fp <= t.fp_pass {
        Grade::Pass
    } else if catch >= t.catch_warn && fp <= t.fp_warn {
        Grade::Warn
    } else {
        Grade::Fail
    }
}

/// Top-level report serialized to `efficacy-report.json`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EfficacyReport {
    pub suite: String,
    pub git_sha: String,
    pub generated_at: String,
    pub host: String,
    pub overall_verdict: Grade,
    pub functions: Vec<FunctionReport>,
}

impl EfficacyReport {
    pub fn new(git_sha: String, host: String, functions: Vec<FunctionReport>) -> Self {
        // An empty report is not a pass: fold the per-function verdicts but
        // treat "nothing was tested" as UNTESTED so an accidentally-empty run
        // can never read as green.
        let overall_verdict = if functions.is_empty() {
            Grade::Untested
        } else {
            functions
                .iter()
                .map(|f| f.verdict)
                .fold(Grade::Pass, Grade::worst)
        };
        Self {
            suite: "security-efficacy".into(),
            git_sha,
            generated_at: chrono::Utc::now().to_rfc3339(),
            host,
            overall_verdict,
            functions,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn case(bad: bool, correct: bool) -> Case {
        Case {
            description: "c".into(),
            bad,
            expected: if bad { "deny" } else { "allow" }.into(),
            actual: "x".into(),
            correct,
        }
    }

    #[test]
    fn perfect_corpus_is_pass_with_full_matrix() {
        // 3 bad all stopped, 2 good all permitted.
        let cases = vec![
            case(true, true),
            case(true, true),
            case(true, true),
            case(false, true),
            case(false, true),
        ];
        let r = FunctionReport::from_cases(
            "fw",
            "sng-fw",
            Kind::Enforcement,
            Targets::default(),
            cases,
            None,
        );
        assert_eq!((r.tp, r.fn_, r.tn, r.fp), (3, 0, 2, 0));
        assert_eq!(r.bad_cases, 3);
        assert_eq!(r.good_cases, 2);
        assert!((r.catch_rate - 1.0).abs() < f64::EPSILON);
        assert!(r.false_positive_rate.abs() < f64::EPSILON);
        assert!((r.accuracy - 1.0).abs() < f64::EPSILON);
        assert_eq!(r.verdict, Grade::Pass);
    }

    #[test]
    fn one_missed_bad_drops_catch_rate() {
        // 1 of 4 bad missed (false negative) => catch 0.75.
        let cases = vec![
            case(true, true),
            case(true, true),
            case(true, true),
            case(true, false),
            case(false, true),
        ];
        let r = FunctionReport::from_cases(
            "fw",
            "sng-fw",
            Kind::Enforcement,
            Targets::default(),
            cases,
            None,
        );
        assert_eq!((r.tp, r.fn_), (3, 1));
        assert!((r.catch_rate - 0.75).abs() < 1e-9);
        // 0.75 catch is below the 0.90 warn floor => FAIL.
        assert_eq!(r.verdict, Grade::Fail);
    }

    #[test]
    fn grade_boundaries() {
        let t = Targets::default();
        // exactly on the pass targets => PASS.
        assert_eq!(grade(0.99, 0.02, t), Grade::Pass);
        // catch in warn band, fp clean => WARN.
        assert_eq!(grade(0.95, 0.0, t), Grade::Warn);
        // fp above warn ceiling => FAIL even with perfect catch.
        assert_eq!(grade(1.0, 0.10, t), Grade::Fail);
    }

    #[test]
    fn untested_is_worse_than_warn_but_better_than_fail() {
        assert_eq!(Grade::Pass.worst(Grade::Untested), Grade::Untested);
        assert_eq!(Grade::Warn.worst(Grade::Untested), Grade::Untested);
        assert_eq!(Grade::Untested.worst(Grade::Fail), Grade::Fail);
    }

    #[test]
    fn overall_verdict_is_worst_of_functions() {
        let pass = FunctionReport::from_cases(
            "a",
            "c",
            Kind::Enforcement,
            Targets::default(),
            vec![case(true, true), case(false, true)],
            None,
        );
        let untested = FunctionReport::untested("b", "c", Kind::Detection, "tool missing");
        let rep = EfficacyReport::new("sha".into(), "host".into(), vec![pass, untested]);
        assert_eq!(rep.overall_verdict, Grade::Untested);
    }
}
