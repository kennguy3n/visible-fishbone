#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::cast_precision_loss,
    clippy::cast_possible_truncation,
    clippy::cast_sign_loss,
    clippy::cast_possible_wrap,
    clippy::cast_lossless,
    clippy::float_cmp,
    // The labelled corpus is a flat data table; rustfmt expands each
    // entry across several lines, so the builder legitimately exceeds
    // the default line budget. Splitting a data fixture for the sake of
    // the lint would hurt, not help, readability.
    clippy::too_many_lines
)]

//! ML NER efficacy: drive the *real* on-device ONNX inference path over
//! a labelled PII corpus and assert the DLP spec's precision/recall
//! targets (precision > 0.90, recall > 0.85). The model is the exact
//! shipped `ner_v2.onnx` asset, so this is a measurement of the product
//! detector, not a re-trained or stubbed one.

use sng_dlp::ml_classifier::{EntityClass, NerModel};

const MODEL_BYTES: &[u8] = include_bytes!("../assets/ner_v2.onnx");

/// A labelled example: text plus the single entity class it contains,
/// or `None` for a benign control that must produce no detection.
type Example = (&'static str, Option<EntityClass>);

/// One labelled PII example (helper keeps the corpus table one line per
/// entry, which also keeps each builder well under the line budget).
fn pii(text: &'static str, class: EntityClass) -> Example {
    (text, Some(class))
}

/// One benign control: no PII, so any detection is a false positive.
fn benign(text: &'static str) -> Example {
    (text, None)
}

/// Labelled PII examples across all twelve entity classes. The first
/// block uses surface forms close to the training templates; the
/// held-out block uses names/codes deliberately absent from the
/// templates, so a pass there demonstrates generalisation (gazetteer +
/// shape features) rather than memorisation.
fn pii_examples() -> Vec<Example> {
    use EntityClass::{
        Address, BankAccount, DateOfBirth, DriverLicense, LegalDocument, MedicalRecord,
        MedicalRecordNumber, NationalId, PassportNumber, PersonName, PhoneNumber, TaxId,
    };
    vec![
        pii(
            "Please contact Mr John Smith regarding the open file",
            PersonName,
        ),
        pii(
            "Dr Emily Carter signed the discharge summary today",
            PersonName,
        ),
        pii("Ms Sarah Johnson will join the onboarding call", PersonName),
        pii(
            "The account belongs to Robert Williams of the east office",
            PersonName,
        ),
        pii(
            "Maria Garcia approved the quarterly travel budget",
            PersonName,
        ),
        pii("He lives at 742 Evergreen Terrace in Springfield", Address),
        pii(
            "Ship the parcel to 1600 Pennsylvania Avenue Washington",
            Address,
        ),
        pii("Her home address is 221B Baker Street London", Address),
        pii("The office moved to 350 Fifth Avenue last spring", Address),
        pii(
            "Deliver the documents to 10 Downing Street tomorrow",
            Address,
        ),
        pii(
            "Call the office at +1-202-555-0173 tomorrow morning",
            PhoneNumber,
        ),
        pii(
            "You can reach me on +44-20-7946-0958 after lunch",
            PhoneNumber,
        ),
        pii(
            "Dial the support line +1-800-555-0199 for help",
            PhoneNumber,
        ),
        pii(
            "My mobile is +1-415-555-2671 if you need anything",
            PhoneNumber,
        ),
        pii(
            "Reach the desk at +61-2-5550-1234 during the day",
            PhoneNumber,
        ),
        pii(
            "Wire the funds to IBAN GB29NWBK60161331926819 today",
            BankAccount,
        ),
        pii(
            "Transfer to account DE89370400440532013000 by Friday",
            BankAccount,
        ),
        pii(
            "The vendor IBAN is FR1420041010050500013M02606 on file",
            BankAccount,
        ),
        pii("Remit payment to NL91ABNA0417164300 next week", BankAccount),
        pii(
            "Settle the invoice via ES9121000418450200051332 promptly",
            BankAccount,
        ),
        // medical_record: clinical-context record codes that are NOT
        // the bare `MRN#######` shape (that is the distinct
        // medical_record_number class below).
        pii("Lab results A12-3456 pending review", MedicalRecord),
        pii("The patient chart 78451236 on record", MedicalRecord),
        pii("Lab chart C45-9981 needs review", MedicalRecord),
        pii("The clinic record D88-2210 was filed", MedicalRecord),
        // medical_record_number: the canonical `MRN#######` identifier.
        pii(
            "The patient record MRN8472910 shows the diagnosis",
            MedicalRecordNumber,
        ),
        pii(
            "Chart MRN5523017 was updated by the attending nurse",
            MedicalRecordNumber,
        ),
        pii(
            "Lab results for MRN3391045 are now available",
            MedicalRecordNumber,
        ),
        pii(
            "Admission note references MRN7782134 from intake",
            MedicalRecordNumber,
        ),
        pii(
            "The medical record number MRN1209887 needs a follow up",
            MedicalRecordNumber,
        ),
        // driver_license
        pii("Driver license D1234567 expires soon", DriverLicense),
        pii("DL S99887766 issued by DMV", DriverLicense),
        pii("His driving licence X4471230 is on record", DriverLicense),
        // tax_id
        pii("Tax id 12-3456789 for filing", TaxId),
        pii("Taxpayer tin 078051120 verified", TaxId),
        pii("The ein is 123456789 on file", TaxId),
        // date_of_birth
        pii("Date of birth 1990-05-21 recorded", DateOfBirth),
        pii("Born on 05/21/1990 in London", DateOfBirth),
        pii("DOB 1985-12-03 per passport", DateOfBirth),
        // passport_number
        pii("Passport number AB1234567 expires 2030", PassportNumber),
        pii("Travel passport X12345678 issued", PassportNumber),
        // national_id
        pii("National identity card S1234567A verified", NationalId),
        pii("Citizen nric T7712345B on file", NationalId),
        pii(
            "The court filed case 1:21-cv-04567 last week",
            LegalDocument,
        ),
        pii(
            "Review docket 3:19-cr-00321 before the hearing",
            LegalDocument,
        ),
        pii(
            "The motion in case 2:20-cv-09981 was granted",
            LegalDocument,
        ),
        pii(
            "Counsel cited case 4:18-cv-00245 in the brief",
            LegalDocument,
        ),
        pii(
            "The appeal docket 5:22-cv-01177 is pending review",
            LegalDocument,
        ),
        // Held-out entities: NOT present in the training templates.
        pii("Thomas Anderson chaired the review committee", PersonName),
        pii("Forward the file to Karen Lopez before noon", PersonName),
        pii(
            "Send the deposit to IBAN BE68539007547034 promptly",
            BankAccount,
        ),
        pii(
            "The wire went to account IT60X0542811101000000123456 today",
            BankAccount,
        ),
        pii(
            "Pull the chart for MRN9981002 from the ward",
            MedicalRecordNumber,
        ),
        pii(
            "The hearing for case 6:23-cv-07788 is set for May",
            LegalDocument,
        ),
        pii(
            "Ring the front desk at +49-30-1234-5678 if delayed",
            PhoneNumber,
        ),
        // Held-out WS5 breadth entities (absent from training templates).
        pii(
            "Driver license P7782134A on record at the dmv",
            DriverLicense,
        ),
        pii("Taxpayer fiscal id GB123456789 confirmed", TaxId),
        pii("Date of birth 03/14/1978 on the form", DateOfBirth),
        pii("Passport 98765432A for travel", PassportNumber),
        pii(
            "Identification number 990101135792 recorded for the citizen",
            NationalId,
        ),
    ]
}

/// Benign controls: realistic prose with no PII, plus hard negatives
/// (capitalised place/product pairs and bare reference numbers) that a
/// shape-only detector might over-trigger on. None may yield an entity.
fn benign_examples() -> Vec<Example> {
    vec![
        benign("The quarterly report is ready and revenue grew this year"),
        benign("Our team shipped the new dashboard feature on schedule"),
        benign("The weather was pleasant during the offsite last month"),
        benign("Please review the agenda before the staff meeting"),
        benign("The cafeteria menu changes every week in the summer"),
        benign("We refactored the build pipeline to cut compile time"),
        benign("The library closes early on public holidays"),
        benign("Sales trends improved after the product relaunch"),
        benign("New York and Hong Kong remain our largest markets"),
        benign("Project Apollo ships in the third quarter"),
        benign("Order 48210 was shipped to the warehouse yesterday"),
        benign("Version 12345 of the firmware is now available"),
    ]
}

/// The full labelled corpus: PII examples followed by benign controls.
fn corpus() -> Vec<Example> {
    let mut all = pii_examples();
    all.extend(benign_examples());
    all
}

/// Measure ML NER precision and recall over the labelled corpus using
/// the real ONNX inference path. This is the harness contract: ML NER
/// precision > 0.90 and recall > 0.85.
#[test]
fn ml_ner_meets_precision_recall_targets() {
    let model = NerModel::load_from_bytes(MODEL_BYTES).expect("model loads");

    let (mut tp, mut fp, mut fn_) = (0usize, 0usize, 0usize);
    for (text, expected) in corpus() {
        let ents = model.detect(text).expect("inference");
        let detected_classes: Vec<EntityClass> = ents.iter().map(|e| e.class).collect();
        match expected {
            Some(want) => {
                if detected_classes.contains(&want) {
                    tp += 1;
                } else {
                    fn_ += 1;
                }
                // Any detection of a class other than the labelled one
                // in a single-entity sentence is a spurious positive.
                fp += detected_classes.iter().filter(|&&c| c != want).count();
            }
            None => {
                // Benign control: every detection is a false positive.
                fp += detected_classes.len();
            }
        }
    }

    let precision = tp as f64 / (tp + fp).max(1) as f64;
    let recall = tp as f64 / (tp + fn_).max(1) as f64;
    eprintln!(
        "ML NER efficacy: tp={tp} fp={fp} fn={fn_} precision={precision:.3} recall={recall:.3}"
    );

    assert!(
        precision > 0.90,
        "ML NER precision {precision:.3} must exceed 0.90 (tp={tp}, fp={fp})"
    );
    assert!(
        recall > 0.85,
        "ML NER recall {recall:.3} must exceed 0.85 (tp={tp}, fn={fn_})"
    );
}
