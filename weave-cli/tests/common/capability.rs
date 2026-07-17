//! Compat-status taxonomy emitted by per-app validation tests.
//!
//! Defined by TASK-META-06. Documented in `docs/VALIDATION-TIERS.md`
//! § "Capability Class Taxonomy".
//!
//! ## Why this exists
//!
//! Weave's existing tier model (Tier A/B/C in `VALIDATION-TIERS.md`) tells us
//! whether a milestone gate held. It does NOT tell us, per app, *which user-
//! observable capability classes the app was actually exercised against*.
//! Without that, any future user-facing compatibility statement collapses to
//! "works / doesn't work" — which throws away the discipline that
//! `KNOWN-BUG-CLASSES.md` and the tier model were built to preserve.
//!
//! This module gives every per-app test a way to declare:
//!
//!   * which capability classes it intends to exercise, and
//!   * for each declared class, the observed pass/fail/untested state.
//!
//! Output is emitted to stderr in a stable, grep-able format
//! (`weave-capability:` lines). It is NOT consumed by any UI or public DB —
//! per the task, the taxonomy must live in test output for at least 3 months
//! before anything user-facing is built on top of it.
//!
//! ## "Untested" is first-class
//!
//! If a test does not exercise `printing`, the report records
//! `tested=false, passed=false`. This is intentionally distinct from
//! `tested=true, passed=false`. A future compat-DB conversation needs the
//! untested signal preserved, not collapsed into a fail.

use std::collections::BTreeMap;
use std::fmt;

/// User-observable capability classes a per-app test may declare.
///
/// Add new variants only when an existing test in the corpus actually
/// exercises something none of the current variants describe. Do NOT pre-add
/// variants for hypothetical future apps — the taxonomy is supposed to track
/// real test coverage.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum CapabilityClass {
    /// Process starts and reaches a steady state (event loop, exit, or
    /// declared "ready" point) without crashing.
    Launches,
    /// App reads a file given to it (CLI arg, drag-drop, or File→Open) and
    /// the contents reach the app's data model.
    OpensFile,
    /// App writes a file the user can later read back — produces persistent
    /// output observable outside the process.
    SavesFile,
    /// App makes outbound network calls successfully (DNS + TCP + first
    /// payload, at minimum).
    Network,
    /// App produces audio output through the configured backend (real or
    /// dummy backend that confirms the audio path was driven, not silently
    /// skipped).
    Audio,
    /// App can drive a print pipeline — including print-to-PDF — to a
    /// recognisable output document.
    Printing,
    /// App's required sandbox permissions are correctly granted and
    /// respected: the app can do what it needs and is blocked from what it
    /// does not need.
    SandboxPermissions,
}

impl CapabilityClass {
    /// Stable string token used in stderr emission. Do not rename without
    /// updating downstream consumers (currently: human readers; eventually:
    /// the post-3-month compat-DB conversation).
    pub fn as_token(self) -> &'static str {
        match self {
            CapabilityClass::Launches => "launches",
            CapabilityClass::OpensFile => "opens_file",
            CapabilityClass::SavesFile => "saves_file",
            CapabilityClass::Network => "network",
            CapabilityClass::Audio => "audio",
            CapabilityClass::Printing => "printing",
            CapabilityClass::SandboxPermissions => "sandbox_permissions",
        }
    }
}

/// One row of the per-app capability report.
#[derive(Debug, Clone)]
pub struct CapabilityOutcome {
    /// Did this test attempt to exercise the class at all?
    /// `false` => `passed` is meaningless; treat as "untested".
    pub tested: bool,
    /// If `tested`, did the exercise succeed?
    /// If `!tested`, must be `false`.
    pub passed: bool,
    /// Short free-text evidence — gate name, observed marker, exit reason.
    /// Kept short on purpose; deeper detail belongs in stderr above.
    pub evidence: String,
}

impl CapabilityOutcome {
    /// Class was exercised and the exercise passed.
    pub fn pass(evidence: impl Into<String>) -> Self {
        CapabilityOutcome {
            tested: true,
            passed: true,
            evidence: evidence.into(),
        }
    }
    /// Class was exercised and the exercise failed.
    pub fn fail(evidence: impl Into<String>) -> Self {
        CapabilityOutcome {
            tested: true,
            passed: false,
            evidence: evidence.into(),
        }
    }
    /// Class was NOT exercised by this test. First-class state — must not
    /// be conflated with `fail`.
    pub fn untested(reason: impl Into<String>) -> Self {
        CapabilityOutcome {
            tested: false,
            passed: false,
            evidence: reason.into(),
        }
    }
}

/// Per-app, per-run capability report.
///
/// Construct with `CapabilityReport::for_app("nx.exe")`, declare which
/// classes the test intends to exercise via `declare`, record outcomes as
/// the test runs, and call `emit()` at the end. `emit()` writes one
/// `weave-capability:` line per declared class plus one summary line.
///
/// Undeclared classes are NOT emitted — the act of declaring is itself the
/// truth-claim ("this test intends to exercise X"). Declaring without
/// recording an outcome counts as untested.
pub struct CapabilityReport {
    app: String,
    rows: BTreeMap<CapabilityClass, CapabilityOutcome>,
}

impl CapabilityReport {
    /// Start a new report for an app fixture (e.g. `"nx.exe"`).
    pub fn for_app(app: impl Into<String>) -> Self {
        CapabilityReport {
            app: app.into(),
            rows: BTreeMap::new(),
        }
    }

    /// Declare that this test intends to exercise `class`. Initial state is
    /// `untested("not yet exercised")`; replace with `record` once the
    /// exercise runs.
    pub fn declare(&mut self, class: CapabilityClass) -> &mut Self {
        self.rows
            .entry(class)
            .or_insert_with(|| CapabilityOutcome::untested("not yet exercised"));
        self
    }

    /// Record the outcome of a class exercise. Auto-declares if the class
    /// was not pre-declared.
    pub fn record(&mut self, class: CapabilityClass, outcome: CapabilityOutcome) -> &mut Self {
        self.rows.insert(class, outcome);
        self
    }

    /// Emit the report to stderr. One line per declared class, plus a
    /// trailing summary line. Format is stable.
    ///
    /// Example output:
    /// ```text
    /// weave-capability: app=nx.exe class=launches tested=true passed=true evidence="PE loaded; CreateWindow seen"
    /// weave-capability: app=nx.exe class=audio tested=true passed=true evidence="waveOut→PipeWire exercised via SDL2 audio driver"
    /// weave-capability-summary: app=nx.exe declared=2 tested=2 passed=2
    /// ```
    pub fn emit(&self) {
        for (class, outcome) in &self.rows {
            eprintln!(
                "weave-capability: app={app} class={class} tested={tested} passed={passed} evidence={evidence:?}",
                app = self.app,
                class = class.as_token(),
                tested = outcome.tested,
                passed = outcome.passed,
                evidence = outcome.evidence,
            );
        }
        let declared = self.rows.len();
        let tested = self.rows.values().filter(|o| o.tested).count();
        let passed = self.rows.values().filter(|o| o.tested && o.passed).count();
        eprintln!(
            "weave-capability-summary: app={app} declared={declared} tested={tested} passed={passed}",
            app = self.app,
        );
    }
}

impl fmt::Debug for CapabilityReport {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("CapabilityReport")
            .field("app", &self.app)
            .field("rows", &self.rows)
            .finish()
    }
}

#[cfg(test)]
mod self_tests {
    use super::*;

    #[test]
    fn untested_is_distinct_from_fail() {
        let u = CapabilityOutcome::untested("printer not driven");
        let f = CapabilityOutcome::fail("printer crashed");
        assert!(!u.tested);
        assert!(!u.passed);
        assert!(f.tested);
        assert!(!f.passed);
    }

    #[test]
    fn declare_then_record_replaces_untested() {
        let mut r = CapabilityReport::for_app("demo.exe");
        r.declare(CapabilityClass::Launches);
        r.record(
            CapabilityClass::Launches,
            CapabilityOutcome::pass("entry point reached"),
        );
        let outcome = r.rows.get(&CapabilityClass::Launches).unwrap();
        assert!(outcome.tested);
        assert!(outcome.passed);
    }

    #[test]
    fn declared_but_unrecorded_is_untested() {
        let mut r = CapabilityReport::for_app("demo.exe");
        r.declare(CapabilityClass::Printing);
        let outcome = r.rows.get(&CapabilityClass::Printing).unwrap();
        assert!(!outcome.tested);
        assert!(!outcome.passed);
    }

    #[test]
    fn token_strings_are_stable() {
        assert_eq!(CapabilityClass::Launches.as_token(), "launches");
        assert_eq!(CapabilityClass::OpensFile.as_token(), "opens_file");
        assert_eq!(CapabilityClass::SavesFile.as_token(), "saves_file");
        assert_eq!(CapabilityClass::Network.as_token(), "network");
        assert_eq!(CapabilityClass::Audio.as_token(), "audio");
        assert_eq!(CapabilityClass::Printing.as_token(), "printing");
        assert_eq!(
            CapabilityClass::SandboxPermissions.as_token(),
            "sandbox_permissions"
        );
    }
}
