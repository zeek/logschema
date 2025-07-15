# Log Schema Support for Zeek

[![Zeek matrix tests](https://github.com/zeek/logschema/actions/workflows/zeek-matrix.yml/badge.svg)](https://github.com/zeek/logschema/actions/workflows/zeek-matrix.yml)
[![Zeek nightly build](https://github.com/zeek/logschema/actions/workflows/zeek-nightly.yml/badge.svg)](https://github.com/zeek/logschema/actions/workflows/zeek-nightly.yml)


This [Zeek](https://zeek.org) package generates schemas for Zeek's logs.  For
every log your Zeek installation produces (such as conn.log or tls.log) the
schema describes each log field including name, type, docstring, and more. The
package supports popular schema formats and understands Zeek's log customization
in detail. The schema export code is extensible, allowing you to produce your
own schemas.

## Quickstart

Install this package via `zkg install logschema`. The package has no dependencies and
currently works with Zeek 5.2 and newer.

To get a [JSON Schema](https://json-schema.org/) of each Zeek log in your
installation, run:

```console
$ zeek logschema/export/jsonschema
```

Your local directory now contains a JSON Schema file for each of Zeek's
logs. For example, for your conn.log:

```console
$ cat zeek-conn-log.schema.json | jq
{
  "$schema": "https://json-schema.org/draft/2020-12/schema",
  "title": "Schema for Zeek conn.log",
  "description": "JSON Schema for Zeek conn.log",
  "type": "object",
  "properties": {
    "ts": {
      "type": "number",
      "description": "This is the time of the first packet.",
      ...
    },
...
}
```

To instead get a schema in CSV format, run this:

```console
$ zeek logschema/export/csv
```

This combines all schema information in one file:

```console
$ cat zeek-logschema.csv
log,field,type,record_type,script,is_optional,default,docstring,package
analyzer,ts,time,Analyzer::Logging::Info,base/frameworks/analyzer/logging.zeek,false,-,"Timestamp of confirmation or violation.",-
analyzer,cause,string,Analyzer::Logging::Info,base/frameworks/analyzer/logging.zeek,false,-,"What caused this log entry to be produced. This can\ncurrently be ""violation"" or ""confirmation"".",-
analyzer,analyzer_kind,string,Analyzer::Logging::Info,base/frameworks/analyzer/logging.zeek,false,-,"The kind of analyzer involved. Currently ""packet"", ""file""\nor ""protocol"".",-
...
```

## Background

Zeek features a powerful [logging
framework](https://docs.zeek.org/en/master/frameworks/logging.html) that manages
Zeek's log streams, log writes, and their eventual output format. The format of
Zeek's log entries is highly site-dependent and depends on the configuration of
log filters, enrichments that add additional fields to existing logs, new logs
produced by add-on protocol parsers, etc.

Zeek does not automatically provide a description of what the resulting log
data, after all of this customization, look like. This package closes this gap,
allowing users to verify that their logs still look the same after an upgrade,
that they're compatible with a given log ingester, etc.

The package does this by using reflection APIs at runtime. It scans registered
log streams to retrieve each log's underlying Zeek `record` type and study its
fields, and inspects a configurable log filter on each of those streams to
understand included/excluded fields, separator naming, field name mappings,
etc. For each schema format a registered _exporter_ then translates the gathered
information into suitable output.

## Using the package

The package does nothing when loaded via `@load packages` or `@load logschema`.
Instead, you load the desired exporters, each of which resides in its own script
in `logschema/export/<format>`. Exports run at startup: in standalone Zeek this
means right after `zeek_init()` handlers have executed, and when running in a
cluster, it means once the cluster is up and running.

Many aspects of the export are customizable, and you can roll your own logic for
when to run (and perhaps re-run) schema generation at runtime if desired.

## Schema information

For each log stream known to Zeek, the package determines for each of the
log's fields:

- the name (such as `uid` or `service`),
- its type in the Zeek scripting language (such as `string` or `count`),
- the record type containing the field (such as `Conn::Info` or `conn_id`),
- whether the field is optional [(*)](#old-zeek-footnote),
- the default value of the field, if any,
- the field's docstring,
- the Zeek script that defined the field [(*)](#old-zeek-footnote),
- the package that added the field, if applicable [(*)](#old-zeek-footnote).

<a name="old-zeek-footnote">(*)</a> Only available when using Zeek 6 or newer.

The package then filters this information based on modifications applied by the
[log filter](https://docs.zeek.org/en/master/frameworks/logging.html#filters) in
effect, which can include/exclude fields, transform field names, add extension
fields, etc.

At this point, each schema exporter decides how to use the resulting field
metadata. Not all schema formats support all of this information -- for example,
a schema language may have no concept of the Zeek package providing a log field.

## Supported schema formats

### JSON Schema

```zeek
@load logschema/export/jsonschema
```

This exporter provides [JSON Schema](https://json-schema.org/) files. By default
the exporter writes one schema file per log, named
`zeek-{logname}-log.schema.json`. Each log field becomes a property in the
schema. The schemas feature the type of each field when rendered in JSON, a
description (from Zeek's docstrings), default values, and whether a field is
required. They currently do not annotate or enforce formats (e.g. to convey that
an address string is formatted as an IP address), and they don't yet apply all
conceivable constraints (such as the integer range of a port number). The
schemas also don't currently prohibit `additionalProperties`.

Zeek knows more about its log schema than what JSON Schema's expressiveness can
capture naturally. For example, there's no immediate "vocabulary" in JSON Schema
to express that a log field has a certain Zeek type, or that a particular Zeek
package added it. To convey these properties, the package adds an `x-zeek`
[annotation](https://json-schema.org/blog/posts/custom-annotations-will-continue)
to each field's property. Schema validators and other JSON Schema-centric
applications safely ignore such annotations. The annotation is
[an object](https://github.com/zeek/logschema/blob/main/scripts/export/jsonschema.zeek#L6-L25)
including the Zeek type, the record type containing the field, whether the field
is optional, the script that defined the field, and the package that added the
field, if applicable. (See [Schema information](#schema-information) above for
details.)

Each log's schema is self-contained.

Note that Zeek logs written in JSON format are technically
[JSONL](https://jsonlines.org/) documents, i.e., every line in a log is a JSON
document. Keep this in mind when validating logs, since the validator might need
nudging to accept this format.

#### Customization

Redef `Log::Schema::JSONSchema::filename` to control the file output, see below
for details.

You can omit the `x-zeek` annotation by redef'ing
`Log::Schema::JSONSchema::add_zeek_annotations` to `F`.

#### Example

```console
$ cat zeek-conn-log.schema.json | jq
{
  "$schema": "https://json-schema.org/draft/2020-12/schema",
  "title": "Schema for Zeek conn.log",
  "description": "JSON Schema for Zeek conn.log",
  "type": "object",
  "properties": {
    "ts": {
      "type": "number",
      "description": "This is the time of the first packet.",
      "x-zeek": {
        "type": "time",
        "record_type": "Conn::Info",
        "is_optional": false,
        "script": "base/protocols/conn/main.zeek"
      }
    },
...
}
```

#### Validation

Using the [Sourcemeta jsonschema CLI](https://github.com/sourcemeta/jsonschema):

```console
$ npm install --global @sourcemeta/jsonschema
$ zeek -r test.pcap LogAscii::use_json=T
$ zeek logschema/export/jsonschema
```
Now:
```console
$ jsonschema validate zeek-conn-log.schema.json conn.log
$
$ # Pass! Now mismatch schema and log:
$ jsonschema validate zeek-conn-log.schema.json ssl.log
fail: /home/christian/t4/logs/ssl.log
error: Schema validation failure
  The value was expected to be an object that defines properties "id.orig_h", "id.orig_p", "id.resp_h", "id.resp_p", "proto", "ts", and "uid"
    at instance location ""
    at evaluate path "/required"
```

### CSV

```zeek
@load logschema/export/csv
```

The CSV exporter renders the schema into comma-separated rows, with one row per
log field. By default it produces a file called `zeek-logschema.csv`. A header
line explaining each column is optional and included by default. The
line-oriented nature makes this format great for diffing.

For "complex" columns, such as default values or the docstrings, the formatter
uses JSON representation of the resulting strings. It escapes `\"` to `""`, but
leaves escaped newline in place.

#### Customization

Redef `Log::Schema::CSV::filename` to control the file output, see below
for details.

To disable the header line, use the following:

```zeek
redef Log::Schema::CSV::add_header = F;
```

To change the separator from commas to another string:

```zeek
redef Log::Schema::CSV::separater = ":";
```

To change the string used for unset `&optional` fields from the default of "-":

```zeek
redef Log::Schema::CSV::separater = "";
```

#### Example

```console
$ cat zeek-logschema.csv
log,field,type,record_type,script,is_optional,default,docstring,package
analyzer,ts,time,Analyzer::Logging::Info,base/frameworks/analyzer/logging.zeek,false,-,"Timestamp of confirmation or violation.",-
analyzer,cause,string,Analyzer::Logging::Info,base/frameworks/analyzer/logging.zeek,false,-,"What caused this log entry to be produced. This can\ncurrently be ""violation"" or ""confirmation"".",-
analyzer,analyzer_kind,string,Analyzer::Logging::Info,base/frameworks/analyzer/logging.zeek,false,-,"The kind of analyzer involved. Currently ""packet"", ""file""\nor ""protocol"".",-
...
```

### Zeek Log

```zeek
@load logschema/export/log
```

This export looks a lot like the CSV format, but produces a regular Zeek log
named `logschema` with the schema information (and yes, the log itself gets
reflected in the schema :-). This is a handy way to record and archive schema
information as part of your regular Zeek setup.

#### Example

```console
$ cat logschema.log
#separator \x09
#set_separator  ,
#empty_field    (empty)
#unset_field    -
#path   logschema
#open   2025-05-20-18-00-08
#fields log     field   _type   record_type     script  is_optional     _default        docstring       package
#types  string  string  string  string  string  bool    string  string  string
analyzer        ts      time    Analyzer::Logging::Info base/frameworks/analyzer/logging.zeek   F       -       Timestamp of confirmation or violation. -
analyzer        cause   string  Analyzer::Logging::Info base/frameworks/analyzer/logging.zeek   F       -       What caused this log entry to be produced. This can\x0acurrently be "violation" or "confirmation".-
analyzer        analyzer_kind   string  Analyzer::Logging::Info base/frameworks/analyzer/logging.zeek   F       -       The kind of analyzer involved. Currently "packet", "file"\x0aor "protocol".     -
...
```

### Zeek-y JSON

```zeek
@load logschema/export/json
```

This exporter essentially runs the package's internal log analysis state through
`to_json()` to produce the schema, and is just a handful of lines of code. While
simple, this naturally features all log information the schema analysis is aware
of.

By default, this writes a single output file called `zeek-logschema.json`. The
result is a JSON array of objects, each representing a log. Each object has three members:

- "name", the name of the log (such as "conn" for conn.log),
- "id", the Log::ID enum identifying the log stream in Zeek,
- "fields", an array of fields that each contain the JSON rendering of a Log::Schema::Log record.

The sequence of logs is sorted alphabetically by name, and the sequence of
fields is in the order they're defined in the corresponding Zeek records.

When writing individual schema files per log, each file contains the JSON object
for the respective log.

#### Customization

Redef `Log::Schema::JSON::filename` to control the file output, see below
for details.

#### Example

```console
$ cat zeek-logschema.json | jq
[
  {
    "name": "analyzer",
    "id": "Analyzer::Logging::LOG",
    "fields": [
      {
        "name": "ts",
        "type": "time",
        "record_type": "Analyzer::Logging::Info",
        "is_optional": false,
        "docstring": "Timestamp of the violation.",
        "script": "base/frameworks/analyzer/logging.zeek"
      },
      ...
```

## Choosing a log filter

By default, the package studies the `default` filter on each log stream. You can
adjust this by redef'ing `Log::Schema::logfilter`.

## Configuring filenames

All exporters except the Zeek log one write their schemas to files. You can
configure how they do this by adjusting a per-exporter filename pattern. This
pattern supports keyword substitutions, as follows:

- `{log}`: the name of the log, such as "`conn`". This keyword also controls
  whether the exporter writes one file per log, or all schemas in a single log:
  when the filename pattern features this keyword, it's one-file-per-log,
  otherwise a single file.

- `{filter}`: the log filter used for the export, such as "`default`".

- `{pid}`: the PID of the Zeek process, handy for disambiguating multiple runs.

- `{version}`: the Zeek version string, as produced by `zeek_version()`.

- `strftime()` conversion characters, such as `%Y-%m-%d`, based on
  `current_time()`.

Using "-" as filename will cause the schemas to be written to stdout.

## Customizing log metadata

The package provides a hook to make arbitrary changes to the log metadata before
the exporters produce schemas from it. Let's say you want to patch up the
docstring of the conn.log's service field. With this in test.zeek ...

```zeek
hook Log::Schema::adapt(logs: Log::Schema::LogsTable) {
    logs[Conn::LOG]$fields["service"]$docstring = "My much better docstring";
}
```
... creating a JSON Schema yields:
```console
$ zeek logschema/export/jsonschema ./test.zeek
$ cat zeek-conn-log.schema.json | jq '.properties["service"]'
{
  "type": "string",
  "description": "My much better docstring"
}
```
Consult the logschema package's [`Field` record](https://github.com/zeek/logschema/blob/main/scripts/main.zeek#L6-L32)
for details on the available log field metadata.

## Writing your own exporter

Writing an exporter involves three steps:

- Create a record of type `Log::Schema::Exporter` with a name for your exporter
  and needed function callbacks. The record features callbacks for every log the
  reflection processes (`$process_log()`), a finalization over all state prior
  to output (`$finalize_schema()`), a callback to write all information to a
  single file (`$write_all_schemas()`), a callback to write a single log's
  schema to a file (`$write_single_schema()`), and a custom output routine when
  filenames don't apply (`$custom_export()`).

- Register this exporter with a call to `Log::Schema::add_exporter()`. This
  usually happens in a `zeek_init()` handler.

- Run the export. You can use the default logic, in which case you need to do
  nothing. To roll your own logic, redef `Log::Schema::run_at_startup` to `F` to
  disable built-in schema production, and call `Log::Schema::run_export()`
  where- and whenever you see fit.

Take a look at the exporters in this package to get you started.

## Common pitfalls

### Completeness

Log streams nearly always get defined in `zeek_init()` event handlers. That's
why the package looks for registered log streams after those handlers have
run. However, script authors are free to create Zeek logs at any time and under
arbitrary conditions, so the package will not automatically see such logs. We
suggest the use of custom `Log::Schema::run_export()` invocations in that case.

### Ever-changing default field values

A few Zeek logs use `&default` attributes for which this package produces
different output from run to run in schema formats that capture default values,
such as CSV. Specifically, the SMB logs have timestamps defaulting to current
network time, producing different timestamps every time you generate the schema.
You can adjust this and other troublesome output via the `Log::Schema::adapt()`
hook mentioned above:

```zeek
hook Log::Schema::adapt(logs: Log::Schema::LogsTable) {
    logs[SMB::FILES_LOG]$fields["ts"]$_default = 0.0;
    logs[SMB::MAPPING_LOG]$fields["ts"]$_default = 0.0;
}
```

(You can also suppress this particular churn by redef'ing
`allow_network_time_forward=F`, which will keep these timestamps at 0.0 when
producing the schema at startup. You will probably not want to use this approach
if you're running Zeek in production while producing schemas, since it affects
Zeek's internal handling of time.)
