-- Jason Stys: metadata-only append-only evaluation ledger, constrained outcomes and objective lookup.
-- BEGIN CODE MAP (generated; python scripts/code_map.py)
-- SQL object: evaluation — line 22
-- column: id — line 23
-- column: mode — line 24
-- column: corpus_sha — line 25
-- column: report_json — line 26
-- SQL object: observation — line 28
-- column: evaluation_id — line 29
-- column: case_id — line 30
-- column: objective — line 31
-- column: expected — line 32
-- column: verdict — line 33
-- column: response_sha — line 34
-- SQL object: objective_lookup — line 37
-- SQL object: evaluation_no_update — line 38
-- SQL object: evaluation_no_delete — line 39
-- SQL object: observation_no_update — line 40
-- SQL object: observation_no_delete — line 41
-- END CODE MAP
PRAGMA user_version = 1;
CREATE TABLE evaluation (
    id TEXT PRIMARY KEY CHECK(length(id) = 64),
    mode TEXT NOT NULL CHECK(mode IN ('synthetic-replay', 'offline-snapshot')),
    corpus_sha TEXT NOT NULL CHECK(length(corpus_sha) = 64),
    report_json TEXT NOT NULL CHECK(json_valid(report_json))
) STRICT;
CREATE TABLE observation (
    evaluation_id TEXT NOT NULL REFERENCES evaluation(id),
    case_id TEXT NOT NULL,
    objective TEXT NOT NULL,
    expected TEXT NOT NULL CHECK(expected IN ('allow', 'block', 'review')),
    verdict TEXT NOT NULL CHECK(verdict IN ('allow', 'block', 'review', 'inconclusive')),
    response_sha TEXT NOT NULL CHECK(length(response_sha) = 64),
    PRIMARY KEY(evaluation_id, case_id)
) STRICT;
CREATE INDEX objective_lookup ON observation(objective, verdict);
CREATE TRIGGER evaluation_no_update BEFORE UPDATE ON evaluation BEGIN SELECT RAISE(ABORT, 'append-only'); END;
CREATE TRIGGER evaluation_no_delete BEFORE DELETE ON evaluation BEGIN SELECT RAISE(ABORT, 'append-only'); END;
CREATE TRIGGER observation_no_update BEFORE UPDATE ON observation BEGIN SELECT RAISE(ABORT, 'append-only'); END;
CREATE TRIGGER observation_no_delete BEFORE DELETE ON observation BEGIN SELECT RAISE(ABORT, 'append-only'); END;
