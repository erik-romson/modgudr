"""The output contract (§6.1): tsv, csv, json, ndjson and table."""

import io
import json

import pytest

from modgudr.client.protocol import Column
from modgudr.client.render import FORMATS, make_renderer, unique_names

COLUMNS = [Column("id", "integer"), Column("note", "string"), Column("ok", "boolean")]
NASTY = "a\tb\nc\rd\\e"


def render(
    fmt: str,
    rows: list[list[object]],
    *,
    header: bool = True,
    truncated: bool = False,
    columns: list[Column] | None = None,
) -> str:
    out = io.StringIO()
    renderer = make_renderer(fmt, out, header=header)
    renderer.begin(COLUMNS if columns is None else columns)
    for row in rows:
        renderer.row(row)
    renderer.end(truncated=truncated)
    return out.getvalue()


def test_tsv_escapes_tab_newline_cr_backslash_and_the_text_backslash_n() -> None:
    text = render("tsv", [["1", NASTY, True], ["2", "\\N", False], ["3", None, None]])
    assert text == ("id\tnote\tok\n1\ta\\tb\\nc\\rd\\\\e\ttrue\n2\t\\\\N\tfalse\n3\t\\N\t\\N\n")


def test_tsv_escapes_the_header_too() -> None:
    assert render("tsv", [], columns=[Column("a\tb", "string")]) == "a\\tb\n"


def test_csv_is_rfc_4180() -> None:
    text = render("csv", [["1", 'say "hi", ok', True], ["2", "two\nlines", None]])
    assert text == 'id,note,ok\r\n1,"say ""hi"", ok",true\r\n2,"two\nlines",\r\n'


def test_json_is_one_document() -> None:
    text = render("json", [["1", NASTY, True], ["2", None, False]])
    doc = json.loads(text)
    assert doc == {
        "columns": [
            {"name": "id", "type": "integer"},
            {"name": "note", "type": "string"},
            {"name": "ok", "type": "boolean"},
        ],
        "rows": [
            {"id": "1", "note": NASTY, "ok": True},
            {"id": "2", "note": None, "ok": False},
        ],
    }


def test_json_marks_truncation_and_stays_valid() -> None:
    doc = json.loads(render("json", [["1", "x", True]], truncated=True))
    assert doc["truncated"] is True and len(doc["rows"]) == 1


def test_ndjson_is_one_object_per_row() -> None:
    lines = render("ndjson", [["1", "x", True], ["2", None, False]]).splitlines()
    assert [json.loads(line) for line in lines] == [
        {"id": "1", "note": "x", "ok": True},
        {"id": "2", "note": None, "ok": False},
    ]


def test_duplicate_column_names_get_suffixes_in_json_and_ndjson() -> None:
    columns = [Column("A", "string"), Column("A", "string"), Column("A_2", "string")]
    assert unique_names(["A", "A", "A_2", "A"]) == ["A", "A_3", "A_2", "A_4"]
    assert json.loads(render("ndjson", [["1", "2", "3"]], columns=columns)) == {
        "A": "1",
        "A_3": "2",
        "A_2": "3",
    }
    doc = json.loads(render("json", [["1", "2", "3"]], columns=columns))
    assert [c["name"] for c in doc["columns"]] == ["A", "A_3", "A_2"]


def test_duplicate_names_stay_as_they_are_in_tsv_and_csv() -> None:
    columns = [Column("A", "string"), Column("A", "string")]
    assert render("tsv", [], columns=columns) == "A\tA\n"
    assert render("csv", [], columns=columns) == "A,A\r\n"


def test_table_aligns_and_shows_null() -> None:
    text = render("table", [["1", "alpha", True], ["22", None, False]])
    assert text.splitlines() == [
        "id | note  | ok",
        "---+-------+------",
        "1  | alpha | true",
        "22 | NULL  | false",
    ]


@pytest.mark.parametrize(
    ("fmt", "expected"),
    [
        ("tsv", "id\tnote\tok\n"),
        ("csv", "id,note,ok\r\n"),
        (
            "json",
            '{"columns":[{"name":"id","type":"integer"},'
            '{"name":"note","type":"string"},{"name":"ok","type":"boolean"}],"rows":[]}\n',
        ),
        ("ndjson", ""),
    ],
)
def test_an_empty_result_still_has_its_header(fmt: str, expected: str) -> None:
    assert render(fmt, []) == expected


@pytest.mark.parametrize("fmt", ["tsv", "csv", "table"])
def test_no_header_prints_nothing_for_an_empty_result(fmt: str) -> None:
    assert render(fmt, [], header=False).strip("-+ \n") == ""


def test_no_header_drops_only_the_header_line() -> None:
    assert render("tsv", [["1", "x", True]], header=False) == "1\tx\ttrue\n"


def test_an_unknown_format_names_the_valid_ones() -> None:
    with pytest.raises(ValueError, match="tsv, csv, json, ndjson, table"):
        make_renderer("xml", io.StringIO())
    assert FORMATS == ("tsv", "csv", "json", "ndjson", "table")
