from copy import deepcopy

import pytest

from tools.review_record import verify


def evidence():
    authors = [{"model_id": "synthetic-author", "session_id": "author-session", "model_family": "family-a"}]
    summary = {"base_sha": "a" * 40, "head_sha": "b" * 40, "diff_sha256": "c" * 64}
    record = {**summary, "authors": deepcopy(authors), "verdict": "approve",
              "reviewer": {"model_id": "synthetic-reviewer", "session_id": "review-session", "model_family": "family-b"}}
    return record, summary, authors


def test_bound_independent_record_passes():
    verify(*evidence(), [])


@pytest.mark.parametrize("plant", ["stale_head", "stale_base", "stale_diff", "wrong_author",
                                   "same_model", "same_session", "same_family", "blocked", "empty_authors"])
def test_planted_review_violations_fail(plant):
    record, summary, authors = evidence()
    if plant.startswith("stale_"):
        key = {"stale_head": "head_sha", "stale_base": "base_sha", "stale_diff": "diff_sha256"}[plant]
        record[key] = "d" * len(record[key])
    elif plant == "wrong_author":
        record["authors"][0]["session_id"] = "different-session"
    elif plant == "same_model":
        record["reviewer"]["model_id"] = authors[0]["model_id"]
    elif plant == "same_session":
        record["reviewer"]["session_id"] = authors[0]["session_id"]
    elif plant == "same_family":
        record["reviewer"]["model_family"] = authors[0]["model_family"]
    elif plant == "blocked":
        record["verdict"] = "block"
    else:
        record["authors"] = []
    with pytest.raises(ValueError, match="AD-06"):
        verify(record, summary, authors, [])


def test_same_family_requires_exact_approved_model_pair():
    record, summary, authors = evidence()
    record["reviewer"]["model_family"] = "family-a"
    verify(record, summary, authors, [["synthetic-author", "synthetic-reviewer"]])
    with pytest.raises(ValueError, match="AD-06"):
        verify(record, summary, authors, [["other-author", "synthetic-reviewer"]])


def test_missing_author_family_evidence_fails():
    record, summary, authors = evidence()
    del authors[0]["model_family"]
    with pytest.raises(ValueError, match="AD-06"):
        verify(record, summary, authors, [])
