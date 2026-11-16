@testable import DNIeCore
import Foundation
import XCTest

final class EvidenceCapabilityTests: XCTestCase {
    private let documented = #"{"evidence_id":"E-SOURCE-001","claim":"Public declaration","state":"DOCUMENTED","primary_source":"SDK declaration","decision_impact":"Discovery","review_date":"2026-09-27"}"#
    private let verified = #"{"evidence_id":"E-TEST-001","claim":"Bounded observation","state":"EXPERIMENTALLY VERIFIED","experiment_id":"U-04","decision_impact":"Authentication","review_date":"2026-09-27"}"#
    private let inferred = #"{"evidence_id":"E-INFERRED-001","claim":"Reasoned interpretation","state":"INFERRED","supporting_evidence":["U-04 record"],"decision_impact":"Blocks signing","review_date":"2026-09-27"}"#
    private let unknown = #"{"evidence_id":"E-UNKNOWN-001","claim":"Open question","state":"UNKNOWN","decision_impact":"Blocks signing","review_date":"2026-09-27"}"#

    private func load(_ records: [String], mapping: [ProfileCapability: [String]] = [:], version: String = "1") throws -> EvidenceManifest {
        try EvidenceManifest.load(
            version: version,
            evidenceRecords: Data("[\(records.joined(separator: ","))]".utf8),
            capabilityEvidenceIDs: mapping
        )
    }

    func testUnknownRequirementDisablesDiscoveryAuthenticationAndSigningIndependently() {
        for capability in [ProfileCapability.discover, .authenticate, .sign] {
            let gate = CapabilityGate(requirements: [
                capability: [
                    EvidenceRequirement(evidenceID: "EV-ESTABLISHED", state: .documented),
                    EvidenceRequirement(evidenceID: "EV-OPEN", state: .unknown),
                ],
            ])

            XCTAssertFalse(gate.isEnabled(capability), "UNKNOWN enabled \(capability)")
        }
    }

    func testInferredAndMissingRequirementsFailClosed() {
        let gate = CapabilityGate(requirements: [
            .discover: [EvidenceRequirement(evidenceID: "EV-INFERRED", state: .inferred)],
            .authenticate: [],
        ])

        XCTAssertFalse(gate.isEnabled(.discover))
        XCTAssertFalse(gate.isEnabled(.authenticate))
        XCTAssertFalse(gate.isEnabled(.sign))
    }

    func testOnlyDocumentedOrExperimentallyVerifiedRequirementsEnableTheirOwnCapability() {
        let gate = CapabilityGate(requirements: [
            .discover: [EvidenceRequirement(evidenceID: "EV-SOURCE", state: .documented)],
            .authenticate: [EvidenceRequirement(
                evidenceID: "EV-EXPERIMENT",
                state: .experimentallyVerified
            )],
            .sign: [EvidenceRequirement(evidenceID: "EV-OPEN", state: .unknown)],
        ])

        XCTAssertTrue(gate.isEnabled(.discover))
        XCTAssertTrue(gate.isEnabled(.authenticate))
        XCTAssertFalse(gate.isEnabled(.sign))
    }

    func testVersionedManifestCannotPromoteUnknownEvidenceToCapabilities() throws {
        // T079 must supply this production loader. Keeping the call here makes the
        // missing evidence-to-capability boundary an intentional compile-time RED.
        // Records use Validation/evidence-schema.json's root-array shape. The
        // capability mapping and version are separate loader inputs.
        let records = Data(#"""
        [
          {
            "evidence_id": "E-VERIFIED-001",
            "claim": "A bounded offline observation passed",
            "state": "EXPERIMENTALLY VERIFIED",
            "experiment_id": "U-04",
            "decision_impact": "Permits only the mapped capability when all its requirements pass",
            "review_date": "2026-09-27"
          },
          {
            "evidence_id": "E-UNKNOWN-001",
            "claim": "A required card behavior remains untested",
            "state": "UNKNOWN",
            "decision_impact": "Blocks mapped capabilities pending a bounded experiment",
            "review_date": "2026-09-27"
          }
        ]
        """#.utf8)
        let mapping: [ProfileCapability: [String]] = [
            .discover: ["E-VERIFIED-001", "E-UNKNOWN-001"],
            .authenticate: ["E-VERIFIED-001", "E-UNKNOWN-001"],
            .sign: ["E-VERIFIED-001", "E-UNKNOWN-001"],
        ]

        let manifest = try EvidenceManifest.load(
            version: "1",
            evidenceRecords: records,
            capabilityEvidenceIDs: mapping
        )

        XCTAssertFalse(manifest.capabilityGate.isEnabled(.discover))
        XCTAssertFalse(manifest.capabilityGate.isEnabled(.authenticate))
        XCTAssertFalse(manifest.capabilityGate.isEnabled(.sign))
    }

    func testCanonicalProvenanceEnablesOnlyMappedProvenCapabilities() throws {
        let manifest = try load([documented, verified, inferred, unknown], mapping: [
            .discover: ["E-SOURCE-001"],
            .authenticate: ["E-TEST-001"],
            .sign: ["E-TEST-001", "E-INFERRED-001"],
            .recognize: ["E-UNKNOWN-001"],
        ])
        XCTAssertTrue(manifest.capabilityGate.isEnabled(.discover))
        XCTAssertTrue(manifest.capabilityGate.isEnabled(.authenticate))
        XCTAssertFalse(manifest.capabilityGate.isEnabled(.sign))
        XCTAssertFalse(manifest.capabilityGate.isEnabled(.recognize))
        XCTAssertFalse(manifest.capabilityGate.isEnabled(.instance))
    }

    func testMissingOrDuplicateIDsAndInvalidMappingsFailClosed() throws {
        XCTAssertThrowsError(try load([documented, documented]))
        XCTAssertThrowsError(try load([documented], mapping: [.discover: ["E-MISSING-001"]]))
        XCTAssertThrowsError(try load([documented], mapping: [.discover: ["E-SOURCE-001", "E-SOURCE-001"]]))
        XCTAssertThrowsError(try load([documented], mapping: [.discover: []]))
        XCTAssertThrowsError(try load([documented], version: "2"))
    }

    func testMissingOrInvalidProvenanceFailsEvenIfAnotherRecordCouldEnable() throws {
        let noSource = documented.replacingOccurrences(of: #""primary_source":"SDK declaration","#, with: "")
        let noExperiment = verified.replacingOccurrences(of: #""experiment_id":"U-04","#, with: "")
        let noSupport = inferred.replacingOccurrences(of: #""supporting_evidence":["U-04 record"],"#, with: "")
        for bad in [noSource, noExperiment, noSupport,
                    documented.replacingOccurrences(of: "SDK declaration", with: "raw APDU"),
                    verified.replacingOccurrences(of: "2026-09-27", with: "2026-02-30"),
                    documented.replacingOccurrences(of: "E-SOURCE-001", with: "BAD-ID"),
                    documented.replacingOccurrences(of: #""claim":"Public declaration""#, with: #""claim":123"#),
                    documented.replacingOccurrences(of: #""review_date""#, with: #""extra":true,"review_date""#)] {
            XCTAssertThrowsError(try load([documented, bad], mapping: [.discover: ["E-SOURCE-001"]]), "Accepted invalid record: \(bad)")
        }
    }

    func testBoundedRootAndRecordCount() throws {
        XCTAssertThrowsError(try EvidenceManifest.load(
            version: "1", evidenceRecords: Data(#"{"evidence_id":"E-SOURCE-001"}"#.utf8), capabilityEvidenceIDs: [:]
        ))
        XCTAssertThrowsError(try load([]))
        XCTAssertThrowsError(try load(Array(repeating: unknown, count: 257)))
        XCTAssertThrowsError(try EvidenceManifest.load(
            version: "1", evidenceRecords: Data(repeating: 0x20, count: 262_145), capabilityEvidenceIDs: [:]
        ))
    }

    func testDuplicateJSONMembersAndTerminalNewlinesAreMalformed() throws {
        let duplicateState = documented.replacingOccurrences(
            of: #""state":"DOCUMENTED""#,
            with: #""state":"UNKNOWN","state":"DOCUMENTED""#
        )
        let escapedDuplicate = documented.replacingOccurrences(
            of: #""state":"DOCUMENTED""#,
            with: #""st\u0061te":"UNKNOWN","state":"DOCUMENTED""#
        )
        let newlineID = documented.replacingOccurrences(
            of: "E-SOURCE-001", with: #"E-SOURCE-001\n"#
        )
        let newlineExperiment = verified.replacingOccurrences(
            of: "U-04", with: #"U-04\n"#
        )
        for bad in [duplicateState, escapedDuplicate, newlineID, newlineExperiment] {
            XCTAssertThrowsError(try load([bad]))
        }
    }
}
